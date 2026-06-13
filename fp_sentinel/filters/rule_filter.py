"""
L1: 规则过滤器

基于白名单/黑名单的快速过滤，支持：
- 路径模式匹配 (测试文件、示例代码)
- 代码模式匹配 (nosec、pragma)
- 规则ID匹配
- Java/Python 特定规则
"""

import hashlib
import re
from typing import List, Optional, Dict, Any
from ..models import ScanResult, FilterResult, FilterReason, Verdict, ScanTool
from ..rules.java.rules import JAVA_FALSE_POSITIVE_RULES
from ..utils.fingerprint import compute_fingerprint


class RuleFilter:
    """L1 规则过滤器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)

        # 路径白名单（测试、示例、文档）
        self.path_whitelist = self.config.get("path_whitelist", [
            r".*/test/.*",
            r".*/tests/.*",
            r".*/test_.*\.py$",
            r".*/.*_test\.py$",
            r".*/.*Test\.java$",
            r".*/.*Tests\.java$",
            r".*/examples?/.*",
            r".*/docs?/.*",
            r".*/migrations?/.*",
            r".*/generated?/.*",
            r".*/vendor/.*",
            r".*/node_modules/.*",
            r".*/\.git/.*",
            r".*/target/.*",
            r".*/build/.*",
            r".*/__pycache__/.*",
        ])

        # 代码忽略模式
        self.code_ignore_patterns = self.config.get("code_ignore_patterns", [
            r"#\s*nosec",
            r"#\s*noqa",
            r"#\s*auditshield-ignore",
            r"#\s*fp-sentinel-ignore",
            r"#\s*pragma:\s*allowlist\s+secret",
            r"//\s*NOSONAR",
            r"//\s*nosec",
            r"@SuppressWarnings",
            r"//\s*spotbugs:\s*ignore",
            r"//\s*findbugs:\s*ignore",
        ])

        # 编译正则
        self._path_patterns = [re.compile(p) for p in self.path_whitelist]
        self._code_patterns = [re.compile(p, re.IGNORECASE) for p in self.code_ignore_patterns]

        # 自定义规则（用户配置 + Java 内置误报规则）
        self.custom_rules = self.config.get("custom_rules", [])
        self.custom_rules = self.custom_rules + list(JAVA_FALSE_POSITIVE_RULES)

        # 历史误报指纹库
        self.false_positive_fingerprints = set(
            self.config.get("false_positive_fingerprints", [])
        )

    async def filter(self, scan_result: ScanResult) -> FilterResult:
        """过滤单条扫描结果"""
        if not self.enabled:
            return self._pass_through(scan_result)

        # 检查路径白名单
        path_reason = self._check_path_whitelist(scan_result)
        if path_reason:
            return self._mark_false_positive(scan_result, path_reason, 0.9)

        # 检查代码忽略标记
        code_reason = self._check_code_ignore(scan_result)
        if code_reason:
            return self._mark_false_positive(scan_result, code_reason, 0.95)

        # 检查历史误报指纹
        fingerprint = self._compute_fingerprint(scan_result)
        if fingerprint in self.false_positive_fingerprints:
            return self._mark_false_positive(
                scan_result,
                FilterReason(
                    filter_level="L1",
                    rule_name="historical_false_positive",
                    description="匹配历史误报指纹",
                    confidence=0.85,
                ),
                0.85,
            )

        # 检查自定义规则（包含 Java 内置规则）
        custom_reason = self._check_custom_rules(scan_result)
        if custom_reason:
            return self._mark_false_positive(scan_result, custom_reason, 0.8)

        return self._pass_through(scan_result)

    def _check_path_whitelist(self, scan_result: ScanResult) -> Optional[FilterReason]:
        """检查路径白名单"""
        for pattern in self._path_patterns:
            if pattern.match(scan_result.file):
                return FilterReason(
                    filter_level="L1",
                    rule_name="path_whitelist",
                    description=f"文件路径匹配白名单模式: {pattern.pattern}",
                    confidence=0.9,
                )
        return None

    def _check_code_ignore(self, scan_result: ScanResult) -> Optional[FilterReason]:
        """检查代码忽略标记"""
        for pattern in self._code_patterns:
            if pattern.search(scan_result.code):
                return FilterReason(
                    filter_level="L1",
                    rule_name="code_ignore_marker",
                    description=f"代码中存在忽略标记: {pattern.pattern}",
                    confidence=0.95,
                )
        return None

    def _check_custom_rules(self, scan_result: ScanResult) -> Optional[FilterReason]:
        """检查自定义规则（含 Java 内置规则）"""
        for rule in self.custom_rules:
            if self._match_custom_rule(scan_result, rule):
                return FilterReason(
                    filter_level="L1",
                    rule_name=rule.get("name", "custom_rule"),
                    description=rule.get("reason", "匹配自定义规则"),
                    confidence=rule.get("confidence", 0.8),
                )
        return None

    def _match_custom_rule(self, scan_result: ScanResult, rule: Dict[str, Any]) -> bool:
        """匹配自定义规则"""
        # 匹配规则ID（精确匹配）
        if "rule_id" in rule:
            if isinstance(rule["rule_id"], list):
                if scan_result.rule_id not in rule["rule_id"]:
                    return False
            elif scan_result.rule_id != rule["rule_id"]:
                return False

        # 匹配规则ID模式（正则匹配）
        if "rule_id_pattern" in rule:
            if not re.search(rule["rule_id_pattern"], scan_result.rule_id, re.IGNORECASE):
                return False

        # 匹配文件模式
        if "file_pattern" in rule:
            pattern = re.compile(rule["file_pattern"])
            if not pattern.match(scan_result.file):
                return False

        # 匹配代码模式
        if "code_pattern" in rule:
            if not re.search(rule["code_pattern"], scan_result.code):
                return False

        # 匹配严重程度
        if "severity" in rule:
            if isinstance(rule["severity"], list):
                if scan_result.severity.value not in rule["severity"]:
                    return False
            elif scan_result.severity.value != rule["severity"]:
                return False

        # 匹配工具
        if "tool" in rule:
            if isinstance(rule["tool"], list):
                if scan_result.tool.value not in rule["tool"]:
                    return False
            elif scan_result.tool.value != rule["tool"]:
                return False

        return True

    def _compute_fingerprint(self, scan_result: ScanResult) -> str:
        """计算结果指纹（使用统一指纹工具）"""
        return compute_fingerprint(
            tool=scan_result.tool.value,
            rule_id=scan_result.rule_id,
            file=scan_result.file,
            code=scan_result.code,
        )

    def _mark_false_positive(
        self, scan_result: ScanResult, reason: FilterReason, confidence: float
    ) -> FilterResult:
        """标记为误报"""
        return FilterResult(
            id=scan_result.id,
            original=scan_result,
            verdict=Verdict.FALSE_POSITIVE,
            confidence=confidence,
            filter_reasons=[reason],
            risk_score=self._calc_risk(scan_result, True, confidence),
            recommendation=self._gen_recommendation(Verdict.FALSE_POSITIVE, confidence),
        )

    def _pass_through(self, scan_result: ScanResult) -> FilterResult:
        """传递到下一层"""
        return FilterResult(
            id=scan_result.id,
            original=scan_result,
            verdict=Verdict.NEEDS_REVIEW,
            confidence=0.5,
            filter_reasons=[],
            risk_score=self._calc_risk(scan_result, False, 0.5),
            recommendation="L1规则未命中，传递到L2上下文分析",
        )

    def _calc_risk(self, scan_result: ScanResult, is_fp: bool, confidence: float) -> float:
        """计算风险评分"""
        base = {
            "CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 1.0
        }.get(scan_result.severity.value, 5.0)
        if is_fp:
            return round(base * (1 - confidence * 0.8), 2)
        return round(base * confidence, 2)

    def _gen_recommendation(self, verdict: Verdict, confidence: float) -> str:
        """生成建议"""
        if verdict == Verdict.FALSE_POSITIVE:
            if confidence > 0.9:
                return "高置信度误报，建议忽略"
            elif confidence > 0.7:
                return "中置信度误报，建议快速确认"
            else:
                return "低置信度误报，建议人工复核"
        return "待复核"
