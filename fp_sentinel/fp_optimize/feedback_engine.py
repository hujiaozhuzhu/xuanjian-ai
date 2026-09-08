"""
玄鉴 v3.0 — 反馈学习引擎 (Feedback Learning Engine)

基于用户反馈数据自动调整过滤阈值、更新误报规则
版本: 3.0.0
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .feedback_store import FeedbackStore
from .models import (
    FeedbackStatistics,
    FeedbackType,
    FpRateTrendPoint,
    OptimizationEffect,
    OptimizationRecord,
    OptimizationStatus,
    UserFeedback,
)

logger = logging.getLogger(__name__)


# ─────────────────────── 常量定义 ───────────────────────

# 目标误报率 (1%)
TARGET_FP_RATE = 0.01

# 每次优化最大阈值调整步长
MAX_THRESHOLD_STEP = 0.03

# 触发优化所需的最少反馈样本数
MIN_FEEDBACK_FOR_OPTIMIZATION = 5

# 规则误报概率阈值（超过此值触发规则权重调整）
RULE_FP_PROBABILITY_THRESHOLD = 0.7

# 置信度衰减因子（越新的反馈权重越高）
CONFIDENCE_DECAY_FACTOR = 0.95


# ─────────────────────── 反馈学习引擎 ───────────────────────

class FeedbackLearningEngine:
    """
    反馈学习引擎

    核心功能：
    1. 分析用户反馈数据，识别系统性误报模式
    2. 自动调整三层过滤器阈值
    3. 更新规则权重和误报概率
    4. 提供优化建议

    使用方式:
        engine = FeedbackLearningEngine(store)
        result = await engine.analyze_and_optimize(project_id="xxx")
        suggestions = await engine.get_optimization_suggestions()
    """

    def __init__(self, store: FeedbackStore):
        """
        Args:
            store: FeedbackStore 实例
        """
        self.store = store

    # ─────────────── 核心分析流程 ───────────────

    async def analyze_and_optimize(
        self,
        project_id: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        执行完整的分析+优化流程

        Args:
            project_id: 项目ID (None 表示全局)
            dry_run: 如果为 True，只分析不实际应用优化

        Returns:
            优化结果报告
        """
        # 1. 统计反馈分布
        stats = await self.get_feedback_statistics(project_id)
        total_feedbacks = stats.total_feedbacks

        if total_feedbacks < MIN_FEEDBACK_FOR_OPTIMIZATION:
            return {
                "status": "insufficient_data",
                "message": f"反馈样本不足: {total_feedbacks}/{MIN_FEEDBACK_FOR_OPTIMIZATION}",
                "stats": stats.model_dump(),
            }

        # 2. 获取误报倾向规则
        fp_prone_rules = await self.store.get_fp_prone_rules(
            project_id=project_id, min_samples=3
        )

        # 3. 计算阈值调整建议
        threshold_adjustments = self._calculate_threshold_adjustments(
            current_fp_rate=stats.fp_rate,
            fp_prone_rules=fp_prone_rules,
        )

        # 4. 获取高频误报规则优化建议
        rule_suggestions = await self._generate_rule_suggestions(project_id)

        # 5. 应用优化（非 dry_run 模式下）
        optimization_ids = []
        if not dry_run and threshold_adjustments:
            for adj in threshold_adjustments:
                opt_id = await self.store.add_optimization_record(
                    feedback_count=total_feedbacks,
                    status=OptimizationStatus.APPLIED.value,
                    layer=adj.get("layer"),
                    rule_id=adj.get("rule_id"),
                    adjustment_type=adj.get("adjustment_type"),
                    old_value=adj.get("old_value"),
                    new_value=adj.get("new_value"),
                    fp_rate_before=stats.fp_rate,
                    description=adj.get("description"),
                )
                optimization_ids.append(opt_id)

        return {
            "status": "optimized" if not dry_run else "analyzed",
            "dry_run": dry_run,
            "stats": stats.model_dump(),
            "fp_prone_rules": fp_prone_rules,
            "threshold_adjustments": threshold_adjustments,
            "rule_suggestions": rule_suggestions,
            "optimization_ids": optimization_ids,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ─────────────── 统计分析 ───────────────

    async def get_feedback_statistics(
        self,
        project_id: Optional[str] = None,
    ) -> FeedbackStatistics:
        """
        获取反馈统计数据

        Args:
            project_id: 项目ID

        Returns:
            FeedbackStatistics 统计结果
        """
        dist = await self.store.get_feedback_type_distribution(project_id)
        total = sum(dist.values())
        fp_count = dist.get("false_positive", 0)
        tp_count = dist.get("true_positive", 0)
        unsure_count = dist.get("unsure", 0)

        # 计算误报率
        fp_rate = fp_count / total if total > 0 else 0.0

        # 计算趋势 (比较最近一半和前面一半的反馈)
        fp_rate_trend = await self._calculate_fp_rate_trend(project_id)

        # 获取高频误报规则和文件
        top_rules = await self.store.get_top_fp_rules(project_id, limit=10)
        top_files = await self.store.get_top_fp_files(project_id, limit=10)

        # 获取优化次数
        optimizations = await self.store.list_optimizations(
            status=OptimizationStatus.APPLIED.value, limit=1000
        )

        last_opt_at = None
        if optimizations:
            last_opt = optimizations[0]
            if last_opt.get("applied_at"):
                try:
                    last_opt_at = datetime.fromisoformat(last_opt["applied_at"])
                except ValueError:
                    pass

        return FeedbackStatistics(
            total_feedbacks=total,
            fp_feedbacks=fp_count,
            tp_feedbacks=tp_count,
            unsure_feedbacks=unsure_count,
            fp_rate=round(fp_rate, 4),
            target_fp_rate=TARGET_FP_RATE,
            fp_rate_trend=fp_rate_trend,
            optimization_count=len(optimizations),
            last_optimization_at=last_opt_at,
            top_fp_rules=top_rules,
            top_fp_files=top_files,
        )

    async def get_fp_rate_trend(
        self,
        project_id: Optional[str] = None,
        days: int = 30,
    ) -> List[FpRateTrendPoint]:
        """
        获取误报率趋势数据

        Args:
            project_id: 项目ID
            days: 天数范围

        Returns:
            趋势数据点列表
        """
        daily_data = await self.store.get_daily_fp_rate(project_id, days)
        points = []
        for d in daily_data:
            total = d.get("total", 0)
            fp_count = d.get("fp_count", 0)
            tp_count = d.get("tp_count", 0)
            fp_rate = round(fp_count / total, 4) if total > 0 else 0.0

            try:
                ts = datetime.fromisoformat(d["day"]) if isinstance(d["day"], str) else datetime.now(timezone.utc)
            except (ValueError, TypeError):
                ts = datetime.now(timezone.utc)

            points.append(FpRateTrendPoint(
                timestamp=ts,
                fp_rate=fp_rate,
                total_findings=total,
                fp_count=fp_count,
                tp_count=tp_count,
            ))

        return points

    # ─────────────── 阈值优化 ───────────────

    def _calculate_threshold_adjustments(
        self,
        current_fp_rate: float,
        fp_prone_rules: Dict[str, float],
    ) -> List[Dict[str, Any]]:
        """
        计算阈值调整建议

        算法：基于当前误报率与目标误报率的差距，计算需要的阈值调整
        - 如果当前误报率远高于目标，则提高阈值
        - 调整幅度受 MAX_THRESHOLD_STEP 约束
        """
        adjustments = []
        gap = current_fp_rate - TARGET_FP_RATE

        if gap <= 0:
            # 已经达到目标
            return adjustments

        # 全局阈值调整
        # 调整量与差距成正比，但不超过 MAX_THRESHOLD_STEP
        adjustment_factor = min(gap * 0.5, MAX_THRESHOLD_STEP)

        # 针对各层的调整建议
        layers = [
            {"layer": "L1", "current": 0.7, "min": 0.5, "max": 0.95},
            {"layer": "L2", "current": 0.5, "min": 0.4, "max": 0.9},
            {"layer": "L3", "current": 0.7, "min": 0.5, "max": 0.95},
        ]

        for layer_cfg in layers:
            new_value = layer_cfg["current"] + adjustment_factor
            new_value = min(layer_cfg["max"], new_value)
            new_value = round(new_value, 4)

            if new_value > layer_cfg["current"]:
                adjustments.append({
                    "layer": layer_cfg["layer"],
                    "rule_id": None,
                    "adjustment_type": "threshold_increase",
                    "old_value": layer_cfg["current"],
                    "new_value": new_value,
                    "description": (
                        f"{layer_cfg['layer']}阈值 {layer_cfg['current']} -> {new_value} "
                        f"(误报率从 {current_fp_rate:.1%} 优化向目标 {TARGET_FP_RATE:.1%})"
                    ),
                })

        # 针对高误报规则的特定调整
        for rule_id, fp_prob in fp_prone_rules.items():
            if fp_prob >= RULE_FP_PROBABILITY_THRESHOLD:
                # 针对此规则特别降低其权重/提高判定阈值
                rule_adjustment = round(
                    min(fp_prob * MAX_THRESHOLD_STEP, MAX_THRESHOLD_STEP), 4
                )
                adjustments.append({
                    "layer": None,
                    "rule_id": rule_id,
                    "adjustment_type": "rule_threshold_increase",
                    "old_value": 0.5,
                    "new_value": round(0.5 + rule_adjustment, 4),
                    "description": (
                        f"规则 {rule_id} 误报概率 {fp_prob:.1%}，"
                        f"建议提高阈值 +{rule_adjustment:.3f}"
                    ),
                })

        return adjustments

    # ─────────────── 规则优化建议 ───────────────

    async def _generate_rule_suggestions(
        self,
        project_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """生成规则优化建议"""
        top_rules = await self.store.get_top_fp_rules(project_id, limit=10)
        suggestions = []

        for rule in top_rules:
            rule_id = rule.get("rule_id")
            total = rule.get("total", 0)
            fp_count = rule.get("fp_count", 0)
            fp_pct = rule.get("fp_pct", 0.0)

            if fp_pct >= 80 and total >= 3:
                suggestions.append({
                    "action": "increase_threshold",
                    "rule_id": rule_id,
                    "severity": "high",
                    "reason": f"规则 {rule_id} 的误报率为 {fp_pct}% ({fp_count}/{total})",
                    "suggestion": "建议将该规则的判定阈值提高 0.1-0.2，或加入白名单逻辑",
                })
            elif fp_pct >= 60 and total >= 5:
                suggestions.append({
                    "action": "add_context_filter",
                    "rule_id": rule_id,
                    "severity": "medium",
                    "reason": f"规则 {rule_id} 的误报率为 {fp_pct}% ({fp_count}/{total})",
                    "suggestion": "建议增加上下文分析逻辑，过滤测试代码和框架安全模式",
                })

        return suggestions

    # ─────────────── 趋势分析 ───────────────

    async def _calculate_fp_rate_trend(
        self,
        project_id: Optional[str] = None,
    ) -> str:
        """
        计算误报率变化趋势

        Returns:
            "decreasing" / "stable" / "increasing"
        """
        points = await self.get_fp_rate_trend(project_id, days=30)
        if len(points) < 3:
            return "stable"

        # 比较前1/3和后1/3的平均误报率
        n = len(points)
        third = max(1, n // 3)
        early_avg = sum(p.fp_rate for p in points[:third]) / third
        late_avg = sum(p.fp_rate for p in points[-third:]) / third

        # 如果变化小于1个百分点，视为稳定
        if abs(late_avg - early_avg) < 0.01:
            return "stable"
        elif late_avg < early_avg:
            return "decreasing"
        else:
            return "increasing"

    # ─────────────── 优化效果评估 ───────────────

    async def evaluate_optimizations(
        self,
        project_id: Optional[str] = None,
    ) -> List[OptimizationEffect]:
        """
        评估已应用优化的效果

        Returns:
            优化效果列表
        """
        optimizations = await self.store.list_optimizations(
            status=OptimizationStatus.APPLIED.value, limit=100
        )
        effects = []

        for opt in optimizations:
            fp_before = opt.get("fp_rate_before", 0.0) or 0.0
            fp_after = opt.get("fp_rate_after", 0.0) or 0.0

            absolute_improvement = fp_before - fp_after
            relative_pct = 0.0
            if fp_before > 0:
                relative_pct = round(
                    (absolute_improvement / fp_before) * 100, 2
                )

            effects.append(OptimizationEffect(
                optimization_id=opt.get("id", ""),
                fp_rate_before=fp_before,
                fp_rate_after=fp_after,
                absolute_improvement=round(absolute_improvement, 4),
                relative_improvement_pct=relative_pct,
                sample_size=opt.get("feedback_count", 0),
                is_effective=absolute_improvement > 0,
            ))

        return effects

    # ─────────────── 误报模式识别 ───────────────

    async def identify_fp_patterns(
        self,
        project_id: Optional[str] = None,
        min_confidence: float = 0.6,
    ) -> List[Dict[str, Any]]:
        """
        识别系统性误报模式

        Args:
            project_id: 项目ID
            min_confidence: 最低置信度

        Returns:
            误报模式列表
        """
        fp_prone_rules = await self.store.get_fp_prone_rules(
            project_id=project_id, min_samples=3
        )

        patterns = []
        for rule_id, fp_prob in fp_prone_rules.items():
            if fp_prob >= min_confidence:
                patterns.append({
                    "type": "rule_fp_pattern",
                    "rule_id": rule_id,
                    "fp_probability": fp_prob,
                    "confidence": fp_prob,
                    "description": f"规则 {rule_id} 有 {fp_prob:.1%} 的概率为误报",
                    "suggestion": "建议提高阈值或增加更多过滤条件",
                })

        # 按概率降序排列
        patterns.sort(key=lambda x: x["fp_probability"], reverse=True)
        return patterns
