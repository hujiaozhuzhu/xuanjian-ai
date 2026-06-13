"""
L3: 历史基线过滤器

基于指纹匹配的基线比对，支持：
- 同项目、同规则、同路径的指纹匹配
- 历史误报指纹库
- 基线管理（增/删/查）
"""

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import List, Optional, Dict, Any, Set, Tuple
from ..models import ScanResult, FilterResult, FilterReason, Verdict


logger = logging.getLogger(__name__)


class BaselineFilter:
    """L3 历史基线过滤器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.baseline_path = self.config.get("baseline_path", ".fp_sentinel/baseline.json")
        self.similarity_threshold = self.config.get("similarity_threshold", 0.85)
        self.confidence_threshold = self.config.get("confidence_threshold", 0.7)

        # 加载基线数据
        self._fingerprints: Dict[str, Dict[str, Any]] = {}
        self._load_baseline()

    def _load_baseline(self):
        """加载基线指纹库"""
        path = Path(self.baseline_path)
        if not path.exists():
            logger.info(f"基线文件不存在: {self.baseline_path}, 使用空基线")
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("fingerprints", []):
                fp = entry.get("fingerprint", "")
                if fp:
                    self._fingerprints[fp] = entry
            logger.info(f"已加载 {len(self._fingerprints)} 条基线指纹")
        except Exception as e:
            logger.warning(f"加载基线文件失败: {e}")

    def _save_baseline(self):
        """保存基线指纹库"""
        path = Path(self.baseline_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = {
                "version": "1.0",
                "fingerprints": list(self._fingerprints.values()),
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"保存基线文件失败: {e}")

    async def filter(self, scan_result: ScanResult) -> FilterResult:
        """过滤单条扫描结果"""
        if not self.enabled:
            return self._pass_through(scan_result)

        # 计算精确指纹
        fingerprint = self._compute_fingerprint(scan_result)

        # 精确匹配
        if fingerprint in self._fingerprints:
            entry = self._fingerprints[fingerprint]
            is_fp = entry.get("verdict") == "false_positive"
            confidence = entry.get("confidence", 0.85)

            if is_fp and confidence >= self.confidence_threshold:
                return FilterResult(
                    id=scan_result.id,
                    original=scan_result,
                    verdict=Verdict.FALSE_POSITIVE,
                    confidence=confidence,
                    filter_reasons=[FilterReason(
                        filter_level="L3",
                        rule_name="baseline_exact_match",
                        description=f"精确匹配基线指纹: {fingerprint[:16]}...",
                        confidence=confidence,
                    )],
                    risk_score=self._calc_risk(scan_result, True, confidence),
                    recommendation="匹配历史基线误报指纹，建议忽略",
                )

        # 模糊匹配
        fuzzy_match, fuzzy_conf = self._fuzzy_match(scan_result)
        if fuzzy_match and fuzzy_conf >= self.confidence_threshold:
            return FilterResult(
                id=scan_result.id,
                original=scan_result,
                verdict=Verdict.LIKELY_FALSE_POSITIVE,
                confidence=fuzzy_conf,
                filter_reasons=[FilterReason(
                    filter_level="L3",
                    rule_name="baseline_fuzzy_match",
                    description=f"模糊匹配基线指纹 (相似度: {fuzzy_conf:.2f})",
                    confidence=fuzzy_conf,
                )],
                risk_score=self._calc_risk(scan_result, True, fuzzy_conf),
                recommendation="模糊匹配历史基线，建议人工确认",
            )

        return self._pass_through(scan_result)

    def _compute_fingerprint(self, scan_result: ScanResult) -> str:
        """计算精确指纹（同项目 + 同规则 + 同路径 + 同行号）"""
        normalized_code = re.sub(r"\s+", " ", scan_result.code.strip())[:100]
        raw = f"{scan_result.rule_id}:{scan_result.file}:{scan_result.line}:{normalized_code}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _compute_path_fingerprint(self, scan_result: ScanResult) -> str:
        """计算路径级指纹（同规则 + 同路径，忽略行号）"""
        raw = f"{scan_result.rule_id}:{scan_result.file}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _fuzzy_match(self, scan_result: ScanResult) -> Tuple[bool, float]:
        """模糊匹配：同规则 + 同路径 + 代码相似度"""
        path_fp = self._compute_path_fingerprint(scan_result)
        best_conf = 0.0

        for fp_key, entry in self._fingerprints.items():
            if entry.get("verdict") != "false_positive":
                continue
            if entry.get("rule_id") != scan_result.rule_id:
                continue
            if entry.get("file") != scan_result.file:
                continue

            # 代码相似度
            stored_code = entry.get("code_normalized", "")
            current_code = re.sub(r"\s+", " ", scan_result.code.strip())[:100]
            similarity = self._text_similarity(stored_code, current_code)

            if similarity >= self.similarity_threshold:
                conf = entry.get("confidence", 0.8) * similarity
                best_conf = max(best_conf, conf)

        return best_conf >= self.confidence_threshold, best_conf

    def _text_similarity(self, a: str, b: str) -> float:
        """计算两段文本的相似度（基于字符集的Jaccard系数）"""
        if not a or not b:
            return 0.0
        set_a = set(a.split())
        set_b = set(b.split())
        if not set_a or not set_b:
            return 0.0
        intersection = set_a & set_b
        union = set_a | set_b
        return len(intersection) / len(union) if union else 0.0

    def add_to_baseline(
        self,
        scan_result: ScanResult,
        verdict: str = "false_positive",
        confidence: float = 0.9,
        reason: str = "",
    ) -> str:
        """添加到基线"""
        fingerprint = self._compute_fingerprint(scan_result)
        normalized_code = re.sub(r"\s+", " ", scan_result.code.strip())[:100]

        self._fingerprints[fingerprint] = {
            "fingerprint": fingerprint,
            "tool": scan_result.tool.value,
            "rule_id": scan_result.rule_id,
            "file": scan_result.file,
            "line": scan_result.line,
            "code_normalized": normalized_code,
            "verdict": verdict,
            "confidence": confidence,
            "reason": reason,
        }

        self._save_baseline()
        return fingerprint

    def remove_from_baseline(self, fingerprint: str) -> bool:
        """从基线移除"""
        if fingerprint in self._fingerprints:
            del self._fingerprints[fingerprint]
            self._save_baseline()
            return True
        return False

    def get_baseline_count(self) -> int:
        """获取基线条目数"""
        return len(self._fingerprints)

    def clear_baseline(self):
        """清空基线"""
        self._fingerprints.clear()
        self._save_baseline()

    def _pass_through(self, scan_result: ScanResult) -> FilterResult:
        """传递到后续处理"""
        return FilterResult(
            id=scan_result.id,
            original=scan_result,
            verdict=Verdict.NEEDS_REVIEW,
            confidence=0.5,
            filter_reasons=[],
            risk_score=self._calc_risk(scan_result, False, 0.5),
            recommendation="L3基线未命中，需要进一步审查",
        )

    def _calc_risk(self, scan_result: ScanResult, is_fp: bool, confidence: float) -> float:
        """计算风险评分"""
        base = {
            "CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 1.0,
        }.get(scan_result.severity.value, 5.0)
        if is_fp:
            return round(base * (1 - confidence * 0.8), 2)
        return round(base * confidence, 2)
