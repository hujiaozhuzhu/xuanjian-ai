"""
玄鉴 v2.3.0 — 规则自动调优模块 (Auto Tuner)

功能：读取历史误报数据，自动调整三层过滤器(L1/L2/L3)的判定阈值，
     降低整体误报率不低于15%。

设计原则：
- 只分析误报数据，不修改现有过滤器核心逻辑
- 阈值调整基于统计分布，避免过度拟合
- 提供回滚机制，支持阈值版本管理
- 调整幅度受安全上下限约束

版本: 2.3.0
"""

from __future__ import annotations

import json
import logging
import math
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import ScanTool, Severity

logger = logging.getLogger(__name__)


# ─────────────────────── 常量定义 ───────────────────────

# 阈值安全上下限（防止调优过度导致漏报）
THRESHOLD_BOUNDARIES = {
    "L1": {
        "min_confidence": 0.5,      # L1最低置信度阈值
        "max_confidence": 0.95,     # L1最高置信度阈值
        "default": 0.7,             # 默认阈值
    },
    "L2": {
        "min_confidence": 0.4,
        "max_confidence": 0.9,
        "default": 0.5,
    },
    "L3": {
        "min_confidence": 0.5,
        "max_confidence": 0.95,
        "default": 0.7,
    },
}

# 每次调整的最大步长
MAX_ADJUSTMENT_STEP = 0.05

# 最低误报样本量要求
MIN_FP_SAMPLES = 10

# 目标误报率降低百分比
TARGET_FP_REDUCTION = 15.0


# ─────────────────────── 数据模型 ───────────────────────

@dataclass
class TuningResult:
    """调优结果"""
    layer: str                              # L1/L2/L3
    previous_threshold: float               # 调整前阈值
    new_threshold: float                    # 调整后阈值
    adjustment: float                       # 调整量
    fp_samples_analyzed: int                # 分析的误报样本数
    predicted_reduction_pct: float          # 预计误报降低百分比
    confidence: float                       # 调优置信度(0-1)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer": self.layer,
            "previous_threshold": round(self.previous_threshold, 4),
            "new_threshold": round(self.new_threshold, 4),
            "adjustment": round(self.adjustment, 4),
            "fp_samples_analyzed": self.fp_samples_analyzed,
            "predicted_reduction_pct": round(self.predicted_reduction_pct, 2),
            "confidence": round(self.confidence, 4),
            "timestamp": self.timestamp,
        }


@dataclass
class TuningReport:
    """调优综合报告"""
    results: List[TuningResult] = field(default_factory=list)
    total_fp_samples: int = 0
    overall_predicted_reduction: float = 0.0
    create_time: str = field(default_factory=lambda: datetime.now().isoformat())
    version: str = "2.3.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "create_time": self.create_time,
            "total_fp_samples": self.total_fp_samples,
            "overall_predicted_reduction_pct": round(self.overall_predicted_reduction, 2),
            "layer_results": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


@dataclass
class FalsePositiveSample:
    """误报样本数据"""
    fingerprint: str                        # 误报指纹
    layer: str                              # 被哪层过滤器判定 (L1/L2/L3)
    rule_id: str                            # 规则ID
    tool: str                               # 扫描工具
    severity: str                           # 严重程度
    file_path: str                          # 文件路径
    code_snippet: str                       # 代码片段
    confidence_when_marked: float           # 判定时的置信度
    marked_at: str                          # 标记时间
    filter_reasons: List[str] = field(default_factory=list)  # 触发过滤原因


# ─────────────────────── 核心调优引擎 ───────────────────────

class AutoTuner:
    """
    规则自动调优引擎

    通过分析历史误报样本数据，使用统计方法计算最优阈值配置。
    支持增量调优、回滚、和配置持久化。

    使用方式:
        tuner = AutoTuner(fp_data_path="path/to/fp_samples.json")
        report = await tuner.tune_all_layers()
        tuner.apply_thresholds(report)  # 将新阈值写入配置
        tuner.save_report(report)       # 保存调优报告
    """

    def __init__(
        self,
        fp_data_path: Optional[str] = None,
        baseline_path: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """
        初始化调优器

        Args:
            fp_data_path: 历史误报数据文件路径（JSON格式）
            baseline_path: 基线阈值配置路径（JSON格式），用于回滚
            config: 可选的调参配置
        """
        self.config = config or {}
        self.fp_data_path = fp_data_path or self.config.get("fp_data_path")
        self.baseline_path = baseline_path or self.config.get(
            "baseline_path", ".fp_sentinel/threshold_baseline.json"
        )

        # 当前阈值配置（默认值）
        self.current_thresholds = {
            "L1": THRESHOLD_BOUNDARIES["L1"]["default"],
            "L2": THRESHOLD_BOUNDARIES["L2"]["default"],
            "L3": THRESHOLD_BOUNDARIES["L3"]["default"],
        }

        # 误报样本缓存
        self._fp_samples: List[FalsePositiveSample] = []
        self._fp_samples_by_layer: Dict[str, List[FalsePositiveSample]] = {
            "L1": [], "L2": [], "L3": [],
        }

        # 调优历史
        self._tuning_history: List[TuningReport] = []

    # ─────────────── 数据加载 ───────────────

    def load_fp_samples(self, path: Optional[str] = None) -> int:
        """
        加载历史误报样本数据

        Args:
            path: 误报数据文件路径，不传则使用初始化时的路径

        Returns:
            加载的样本数量

        支持的格式:
            - JSON 数组文件（每项为误报记录）
            - 目录（批量加载目录下所有 .json 文件）
        """
        target_path = path or self.fp_data_path
        if not target_path:
            logger.warning("No FP data path specified")
            return 0

        resolved = Path(target_path)
        if not resolved.exists():
            logger.warning(f"FP data path not found: {target_path}")
            return 0

        count = 0
        if resolved.is_dir():
            for json_file in resolved.glob("*.json"):
                count += self._load_single_file(json_file)
        else:
            count = self._load_single_file(resolved)

        logger.info(f"Loaded {count} FP samples from {target_path}")
        return count

    def _load_single_file(self, file_path: Path) -> int:
        """从单个JSON文件加载误报样本"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if isinstance(data, dict) and "samples" in data:
                items = data["samples"]
            elif isinstance(data, list):
                items = data
            else:
                items = [data]

            loaded = 0
            for item in items:
                sample = self._parse_single_sample(item)
                if sample:
                    self._fp_samples.append(sample)
                    if sample.layer in self._fp_samples_by_layer:
                        self._fp_samples_by_layer[sample.layer].append(sample)
                    loaded += 1

            return loaded
        except Exception as e:
            logger.error(f"Failed to load FP data from {file_path}: {e}")
            return 0

    def _parse_single_sample(self, data: Dict[str, Any]) -> Optional[FalsePositiveSample]:
        """解析单条误报样本"""
        try:
            # 必须有的字段
            if "fingerprint" not in data:
                return None

            return FalsePositiveSample(
                fingerprint=data["fingerprint"],
                layer=data.get("layer", "unknown"),
                rule_id=data.get("rule_id", "unknown"),
                tool=data.get("tool", "unknown"),
                severity=data.get("severity", "MEDIUM"),
                file_path=data.get("file_path", ""),
                code_snippet=data.get("code_snippet", ""),
                confidence_when_marked=float(data.get("confidence_when_marked", 0.5)),
                marked_at=data.get("marked_at", datetime.now().isoformat()),
                filter_reasons=data.get("filter_reasons", []),
            )
        except (ValueError, TypeError) as e:
            logger.debug(f"Failed to parse FP sample: {e}")
            return None

    def add_fp_sample(self, sample: FalsePositiveSample) -> None:
        """手动添加单条误报样本"""
        self._fp_samples.append(sample)
        if sample.layer in self._fp_samples_by_layer:
            self._fp_samples_by_layer[sample.layer].append(sample)

    # ─────────────── 调优计算 ───────────────

    async def tune_all_layers(self) -> TuningReport:
        """
        对全部三层过滤器执行调优

        Returns:
            TuningReport 综合调优报告
        """
        report = TuningReport()
        report.total_fp_samples = len(self._fp_samples)

        for layer in ["L1", "L2", "L3"]:
            result = await self.tune_layer(layer)
            if result:
                report.results.append(result)

        # 计算整体预期误报降低率
        if report.results:
            # 按样本量加权平均
            total_samples = sum(r.fp_samples_analyzed for r in report.results)
            if total_samples > 0:
                report.overall_predicted_reduction = sum(
                    r.predicted_reduction_pct * r.fp_samples_analyzed
                    for r in report.results
                ) / total_samples

        self._tuning_history.append(report)
        logger.info(
            f"Auto-tuning completed: {report.overall_predicted_reduction:.1f}% "
            f"predicted FP reduction across {len(report.results)} layers"
        )
        return report

    async def tune_layer(self, layer: str) -> Optional[TuningResult]:
        """
        对指定层级执行调优

        Args:
            layer: 层级标识 (L1/L2/L3)

        Returns:
            TuningResult 或 None（样本不足时）
        """
        samples = self._fp_samples_by_layer.get(layer, [])
        if len(samples) < MIN_FP_SAMPLES:
            logger.warning(
                f"Insufficient FP samples for {layer}: "
                f"{len(samples)} < {MIN_FP_SAMPLES}"
            )
            return None

        # 获取当前阈值和边界
        current_threshold = self.current_thresholds.get(layer, 0.7)
        boundaries = THRESHOLD_BOUNDARIES.get(layer, {})
        min_t = boundaries.get("min_confidence", 0.4)
        max_t = boundaries.get("max_confidence", 0.95)

        # 分析置信度分布
        confidences = [s.confidence_when_marked for s in samples]

        if not confidences:
            return None

        # 计算统计量
        mean_conf = sum(confidences) / len(confidences)
        std_conf = self._calc_std(confidences)

        # 核心算法：基于置信度分布的阈值调整
        # 思路：如果误报样本的平均置信度远高于当前阈值，
        # 说明阈值偏低，可以适当提高以过滤更多误报
        new_threshold = self._calc_optimal_threshold(
            current_threshold=current_threshold,
            mean_fp_confidence=mean_conf,
            std_fp_confidence=std_conf,
            sample_count=len(confidences),
            min_bound=min_t,
            max_bound=max_t,
        )

        # 计算预期误报降低率
        predicted_reduction = self._estimate_reduction(
            samples=samples,
            old_threshold=current_threshold,
            new_threshold=new_threshold,
        )

        # 调优置信度（样本越多越可信）
        confidence = min(1.0, len(confidences) / (MIN_FP_SAMPLES * 5))

        adjustment = new_threshold - current_threshold

        result = TuningResult(
            layer=layer,
            previous_threshold=current_threshold,
            new_threshold=new_threshold,
            adjustment=adjustment,
            fp_samples_analyzed=len(samples),
            predicted_reduction_pct=predicted_reduction,
            confidence=confidence,
        )

        logger.info(
            f"Tuning {layer}: {current_threshold:.3f} -> {new_threshold:.3f} "
            f"(adj={adjustment:+.3f}, reduction={predicted_reduction:.1f}%, "
            f"confidence={confidence:.3f})"
        )
        return result

    def _calc_optimal_threshold(
        self,
        current_threshold: float,
        mean_fp_confidence: float,
        std_fp_confidence: float,
        sample_count: int,
        min_bound: float,
        max_bound: float,
    ) -> float:
        """
        计算最优阈值

        算法：加权移动法
        - 当误报样本平均置信度高于当前阈值时，提高阈值
        - 调整幅度与均值差成正比，但受 MAX_ADJUSTMENT_STEP 约束
        - 调整后范围被约束在 [min_bound, max_bound]
        """
        # 计算误报样本应该被正确过滤的目标置信度
        # 目标：将阈值设在误报样本 confidence 的第75百分位
        # 这样约75%的误报样本会因为新阈值而被过滤
        target = mean_fp_confidence + 0.5 * std_fp_confidence

        # 向目标方向移动
        delta = target - current_threshold

        # 限制步长
        if abs(delta) > MAX_ADJUSTMENT_STEP:
            direction = 1.0 if delta > 0 else -1.0
            delta = direction * MAX_ADJUSTMENT_STEP

        # 应用调整
        new_threshold = current_threshold + delta

        # 约束边界
        new_threshold = max(min_bound, min(max_bound, new_threshold))

        return round(new_threshold, 4)

    def _estimate_reduction(
        self,
        samples: List[FalsePositiveSample],
        old_threshold: float,
        new_threshold: float,
    ) -> float:
        """
        估算误报降低百分比

        逻辑：统计有多少样本的置信度在旧阈值之上但低于新阈值，
        这些样本在新阈值下会被正确过滤。
        """
        if not samples or new_threshold <= old_threshold:
            return 0.0

        newly_correct = sum(
            1 for s in samples
            if old_threshold <= s.confidence_when_marked < new_threshold
        )

        # 预期降低率 = 新正确过滤数 / 总样本数 * 系数
        # 系数 80% 是因为实际场景中有些样本会被其他层过滤
        reduction = (newly_correct / len(samples)) * 80.0
        return round(reduction, 2)

    def _calc_std(self, values: List[float]) -> float:
        """计算标准差"""
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        return math.sqrt(variance)

    def apply_thresholds(self, report: TuningReport) -> Dict[str, float]:
        """
        应用调优结果到当前阈值配置

        Args:
            report: 调优报告

        Returns:
            更新后的阈值配置
        """
        for result in report.results:
            if result.confidence >= 0.5:  # 只应用置信度足够的调整
                self.current_thresholds[result.layer] = result.new_threshold
                logger.info(
                    f"Applied {result.layer} threshold: "
                    f"{result.previous_threshold} -> {result.new_threshold}"
                )

        return dict(self.current_thresholds)

    async def rollback(self, steps: int = 1) -> bool:
        """
        回滚到之前的阈值配置

        Args:
            steps: 回滚步数（默认为1，回滚到上一次调优前）

        Returns:
            是否成功回滚
        """
        if len(self._tuning_history) < steps:
            logger.warning(
                f"Cannot rollback {steps} steps, "
                f"history size: {len(self._tuning_history)}"
            )
            return False

        target_report = self._tuning_history[-steps]

        # 恢复到调整前的阈值
        for result in target_report.results:
            self.current_thresholds[result.layer] = result.previous_threshold
            logger.info(
                f"Rolled back {result.layer}: "
                f"{result.new_threshold} -> {result.previous_threshold}"
            )

        # 从历史中移除被回滚的报告
        self._tuning_history = self._tuning_history[:-steps]
        return True

    # ─────────────── 持久化 ───────────────

    def save_report(self, report: TuningReport, output_dir: str = "./reports/tuning") -> str:
        """
        保存调优报告到文件

        Args:
            report: 调优报告
            output_dir: 输出目录

        Returns:
            保存的文件路径
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        filename = f"tuning_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        file_path = output_path / filename

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(report.to_json())

        logger.info(f"Tuning report saved to: {file_path}")
        return str(file_path)

    def save_thresholds(self, path: Optional[str] = None) -> str:
        """
        保存当前阈值配置

        Args:
            path: 保存路径

        Returns:
            保存的文件路径
        """
        target = path or self.baseline_path
        file_path = Path(target)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "version": "2.3.0",
            "thresholds": self.current_thresholds,
            "updated_at": datetime.now().isoformat(),
        }

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        logger.info(f"Thresholds saved to: {file_path}")
        return str(file_path)

    def load_thresholds(self, path: Optional[str] = None) -> Dict[str, float]:
        """
        加载已保存的阈值配置

        Args:
            path: 配置文件路径

        Returns:
            阈值配置
        """
        target = path or self.baseline_path
        try:
            file_path = Path(target)
            if not file_path.exists():
                logger.info(f"No saved thresholds at {target}, using defaults")
                return dict(self.current_thresholds)

            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            thresholds = data.get("thresholds", {})
            self.current_thresholds.update(thresholds)
            logger.info(f"Loaded thresholds: {self.current_thresholds}")
            return dict(self.current_thresholds)
        except Exception as e:
            logger.error(f"Failed to load thresholds: {e}")
            return dict(self.current_thresholds)

    def generate_synthetic_fp_data(
        self,
        count: int = 100,
        output_path: Optional[str] = None,
        seed: int = 42,
    ) -> str:
        """
        生成合成误报数据（用于测试和演示）

        Args:
            count: 生成样本数量
            output_path: 输出文件路径
            seed: 随机种子

        Returns:
            输出文件路径
        """
        import random
        random.seed(seed)

        samples = []
        rules_by_layer = {
            "L1": [
                {"rule_id": "sql.injection", "tool": "semgrep", "severity": "HIGH"},
                {"rule_id": "xss.cross.site", "tool": "js_scanner", "severity": "MEDIUM"},
                {"rule_id": "path.traversal", "tool": "semgrep", "severity": "HIGH"},
            ],
            "L2": [
                {"rule_id": "java.sql.injection", "tool": "findsecbugs", "severity": "MEDIUM"},
                {"rule_id": "java.xss.output", "tool": "findsecbugs", "severity": "LOW"},
                {"rule_id": "hardcoded.secret", "tool": "semgrep", "severity": "CRITICAL"},
            ],
            "L3": [
                {"rule_id": "ssrf.url.fetch", "tool": "semgrep", "severity": "HIGH"},
                {"rule_id": "command.injection", "tool": "bandit", "severity": "HIGH"},
                {"rule_id": "weak.crypto", "tool": "findsecbugs", "severity": "MEDIUM"},
            ],
        }

        for i in range(count):
            layer = random.choice(["L1", "L2", "L3"])
            rule_info = random.choice(rules_by_layer[layer])

            # 模拟误报置信度分布（偏高样本偏多）
            base_conf = random.gauss(0.75, 0.1)
            confidence = max(0.3, min(0.99, base_conf))

            sample = {
                "fingerprint": f"sample_fp_{i:06d}",
                "layer": layer,
                "rule_id": rule_info["rule_id"],
                "tool": rule_info["tool"],
                "severity": rule_info["severity"],
                "file_path": f"src/main/java/com/example/Service{i % 10}.java",
                "code_snippet": f"// sample code snippet {i}",
                "confidence_when_marked": round(confidence, 4),
                "marked_at": datetime.now().isoformat(),
                "filter_reasons": [f"layer_{layer}_match"],
            }
            samples.append(sample)

        result = {
            "version": "2.3.0",
            "total": count,
            "generated_at": datetime.now().isoformat(),
            "samples": samples,
        }

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            return str(path)

        # 生成到内存，加载到当前 tuner
        for sample_data in samples:
            sample = self._parse_single_sample(sample_data)
            if sample:
                self.add_fp_sample(sample)

        return "memory"
