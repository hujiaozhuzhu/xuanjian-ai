"""
玄鉴 v3.0 — 反馈统计分析引擎 (Feedback Statistics Engine)

提供误报率变化趋势、优化效果统计等数据计算
版本: 3.0.0
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .feedback_engine import FeedbackLearningEngine
from .feedback_store import FeedbackStore
from .models import (
    DashboardData,
    FeedbackStatistics,
    FpRateTrendPoint,
    OptimizationEffect,
)

logger = logging.getLogger(__name__)


# ─────────────────────── 统计分析引擎 ───────────────────────

class StatsEngine:
    """
    反馈统计分析引擎

    提供：
    1. 仪表板综合数据
    2. 误报率时间序列分析
    3. 优化效果归因
    4. 预测和建议

    使用方式:
        engine = StatsEngine(store)
        dashboard = await engine.get_dashboard_data(project_id="xxx")
        trend = await engine.get_trend_report(project_id="xxx", days=30)
    """

    def __init__(self, store: FeedbackStore):
        """
        Args:
            store: FeedbackStore 实例
        """
        self.store = store
        self.feedback_engine = FeedbackLearningEngine(store)

    # ─────────────── 仪表板数据 ───────────────

    async def get_dashboard_data(
        self,
        project_id: Optional[str] = None,
    ) -> DashboardData:
        """
        获取仪表板综合数据

        Args:
            project_id: 项目ID (None 表示全局)

        Returns:
            DashboardData 综合仪表板数据
        """
        # 1. 反馈统计
        feedback_stats = await self.feedback_engine.get_feedback_statistics(project_id)

        # 2. 趋势数据 (最近30天)
        trend_points = await self.feedback_engine.get_fp_rate_trend(
            project_id, days=30
        )

        # 3. 最近优化效果
        recent_effects = await self.feedback_engine.evaluate_optimizations(project_id)

        # 4. 代码风格画像
        style_profile = None
        if project_id:
            style_data = await self.store.get_code_style(project_id)
            if style_data:
                from .models import CodeStyleProfile
                style_profile = CodeStyleProfile(**style_data)

        return DashboardData(
            feedback_stats=feedback_stats,
            trend_points=trend_points,
            recent_optimizations=recent_effects,
            style_profile=style_profile,
        )

    # ─────────────── 趋势报告 ───────────────

    async def get_trend_report(
        self,
        project_id: Optional[str] = None,
        days: int = 30,
    ) -> Dict[str, Any]:
        """
        获取误报率趋势报告

        Args:
            project_id: 项目ID
            days: 天数范围

        Returns:
            趋势报告
        """
        trend_points = await self.feedback_engine.get_fp_rate_trend(
            project_id, days=days
        )

        if not trend_points:
            return {
                "status": "no_data",
                "message": "暂无趋势数据",
                "trend": "stable",
                "trend_points": [],
            }

        # 计算统计指标
        fp_rates = [p.fp_rate for p in trend_points]
        avg_fp_rate = sum(fp_rates) / len(fp_rates) if fp_rates else 0.0
        min_fp_rate = min(fp_rates) if fp_rates else 0.0
        max_fp_rate = max(fp_rates) if fp_rates else 0.0

        # 计算趋势方向
        trend_direction = self._determine_trend(fp_rates)

        # 计算改善率
        if len(fp_rates) >= 2:
            improvement = fp_rates[0] - fp_rates[-1]
            improvement_pct = (
                (improvement / fp_rates[0] * 100) if fp_rates[0] > 0 else 0.0
            )
        else:
            improvement = 0.0
            improvement_pct = 0.0

        # 计算标准差 (波动性)
        if len(fp_rates) >= 2:
            variance = sum((r - avg_fp_rate) ** 2 for r in fp_rates) / len(fp_rates)
            std_dev = variance ** 0.5
        else:
            std_dev = 0.0

        return {
            "status": "ok",
            "period_days": days,
            "trend": trend_direction,
            "avg_fp_rate": round(avg_fp_rate, 4),
            "min_fp_rate": round(min_fp_rate, 4),
            "max_fp_rate": round(max_fp_rate, 4),
            "current_fp_rate": round(fp_rates[-1], 4) if fp_rates else 0.0,
            "improvement": round(improvement, 4),
            "improvement_pct": round(improvement_pct, 2),
            "volatility": round(std_dev, 4),
            "total_data_points": len(trend_points),
            "trend_points": [
                {
                    "date": p.timestamp.isoformat() if isinstance(p.timestamp, datetime) else str(p.timestamp),
                    "fp_rate": p.fp_rate,
                    "total_findings": p.total_findings,
                    "fp_count": p.fp_count,
                    "tp_count": p.tp_count,
                }
                for p in trend_points
            ],
        }

    # ─────────────── 优化效果报告 ───────────────

    async def get_optimization_report(
        self,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        获取优化效果报告

        Args:
            project_id: 项目ID

        Returns:
            优化效果综合报告
        """
        effects = await self.feedback_engine.evaluate_optimizations(project_id)

        if not effects:
            return {
                "status": "no_optimizations",
                "message": "暂无优化记录",
                "total_optimizations": 0,
                "effective_count": 0,
                "avg_improvement_pct": 0.0,
            }

        effective = [e for e in effects if e.is_effective]
        total = len(effects)
        effective_count = len(effective)

        avg_improvement = (
            sum(e.relative_improvement_pct for e in effective) / effective_count
            if effective_count > 0 else 0.0
        )

        total_absolute_improvement = sum(e.absolute_improvement for e in effective)

        return {
            "status": "ok",
            "total_optimizations": total,
            "effective_count": effective_count,
            "ineffective_count": total - effective_count,
            "effectiveness_rate": round(effective_count / total * 100, 1) if total > 0 else 0.0,
            "avg_improvement_pct": round(avg_improvement, 2),
            "total_absolute_improvement": round(total_absolute_improvement, 4),
            "best_optimization": self._find_best_optimization(effects),
            "worst_optimization": self._find_worst_optimization(effects),
            "recent_effects": [e.model_dump() for e in effects[:5]],
        }

    # ─────────────── 预测和建议 ───────────────

    async def get_predictions(
        self,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        获取误报率预测

        基于历史趋势，预测未来几次扫描后的误报率

        Args:
            project_id: 项目ID

        Returns:
            预测结果
        """
        trend_points = await self.feedback_engine.get_fp_rate_trend(
            project_id, days=30
        )

        if len(trend_points) < 3:
            return {
                "status": "insufficient_data",
                "message": "需要至少3天的历史数据才能预测",
                "current_fp_rate": 0.0,
                "predicted_fp_rates": [],
            }

        fp_rates = [p.fp_rate for p in trend_points]
        current = fp_rates[-1]
        avg = sum(fp_rates) / len(fp_rates)

        # 计算平均衰减率
        decay_rates = []
        for i in range(1, len(fp_rates)):
            if fp_rates[i - 1] > 0:
                rate = fp_rates[i] / fp_rates[i - 1]
                decay_rates.append(rate)

        avg_decay = sum(decay_rates) / len(decay_rates) if decay_rates else 0.95

        # 预测未来10个周期的误报率
        predicted = []
        forecast = current
        for i in range(10):
            forecast *= avg_decay
            predicted.append(round(max(0.001, forecast), 4))

        return {
            "status": "ok",
            "current_fp_rate": round(current, 4),
            "avg_decay_rate": round(avg_decay, 4),
            "predicted_fp_rates": predicted,
            "target_reachable": any(r <= 0.01 for r in predicted),
            "estimated_periods_to_target": self._estimate_periods_to_target(
                current, avg_decay, target=0.01
            ),
        }

    async def get_recommendations(
        self,
        project_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        生成优化建议

        Args:
            project_id: 项目ID

        Returns:
            建议列表
        """
        recommendations = []

        # 1. 获取当前统计
        stats = await self.feedback_engine.get_feedback_statistics(project_id)

        if stats.total_feedbacks < 5:
            recommendations.append({
                "priority": "info",
                "category": "data_collection",
                "message": f"目前仅有 {stats.total_feedbacks} 条反馈，建议继续标记误报/真实漏洞以积累数据",
                "action": "继续标记反馈",
            })
            return recommendations

        # 2. 检查误报率是否达标
        if stats.fp_rate > 0.05:
            recommendations.append({
                "priority": "high",
                "category": "fp_reduction",
                "message": f"当前误报率 {stats.fp_rate:.1%} 远高于目标 1%，需要积极优化",
                "action": "运行 analyze_and_optimize 自动优化",
            })
        elif stats.fp_rate > 0.01:
            recommendations.append({
                "priority": "medium",
                "category": "fp_reduction",
                "message": f"当前误报率 {stats.fp_rate:.1%}，正在接近 1%目标",
                "action": "继续标记反馈以进一步优化",
            })
        else:
            recommendations.append({
                "priority": "success",
                "category": "fp_reduction",
                "message": f"已达到 {stats.fp_rate:.1%} 的目标误报率！",
                "action": "保持当前策略",
            })

        # 3. 趋势分析
        if stats.fp_rate_trend == "increasing":
            recommendations.append({
                "priority": "high",
                "category": "trend",
                "message": "误报率呈上升趋势，需要检查近期代码变更或规则更新",
                "action": "分析新增的高频误报规则",
            })
        elif stats.fp_rate_trend == "decreasing":
            recommendations.append({
                "priority": "info",
                "category": "trend",
                "message": "误报率正持续下降，优化策略生效中",
                "action": "继续当前标记和优化节奏",
            })

        # 4. 高频误报规则
        if stats.top_fp_rules:
            top_rule = stats.top_fp_rules[0]
            if top_rule.get("fp_pct", 0) >= 80:
                recommendations.append({
                    "priority": "medium",
                    "category": "rule_tuning",
                    "message": f"规则 {top_rule.get('rule_id')} 误报率高达 {top_rule.get('fp_pct')}%, 建议重点优化",
                    "action": "针对此规则增加上下文过滤条件",
                })

        # 5. 检查是否需要更多反馈类型多样性
        if stats.tp_feedbacks == 0 and stats.fp_feedbacks > 10:
            recommendations.append({
                "priority": "low",
                "category": "feedback_quality",
                "message": "只有误报反馈，缺少真实漏洞确认。标记真实漏洞有助于优化引擎区分精准度",
                "action": "标记已确认的真实漏洞",
            })

        return recommendations

    # ─────────────── 辅助方法 ───────────────

    @staticmethod
    def _determine_trend(values: List[float]) -> str:
        """确定趋势方向"""
        if len(values) < 3:
            return "stable"

        n = len(values)
        third = max(1, n // 3)
        early = sum(values[:third]) / third
        late = sum(values[-third:]) / third

        diff = late - early
        threshold = 0.005  # 0.5个百分点

        if diff < -threshold:
            return "decreasing"
        elif diff > threshold:
            return "increasing"
        else:
            return "stable"

    @staticmethod
    def _find_best_optimization(
        effects: List[OptimizationEffect],
    ) -> Optional[Dict[str, Any]]:
        """找到最有效的优化"""
        effective = [e for e in effects if e.is_effective]
        if not effective:
            return None
        best = max(effective, key=lambda e: e.relative_improvement_pct)
        return best.model_dump()

    @staticmethod
    def _find_worst_optimization(
        effects: List[OptimizationEffect],
    ) -> Optional[Dict[str, Any]]:
        """找到效果最差的优化"""
        if not effects:
            return None
        worst = min(effects, key=lambda e: e.relative_improvement_pct)
        return worst.model_dump()

    @staticmethod
    def _estimate_periods_to_target(
        current: float,
        decay_rate: float,
        target: float = 0.01,
    ) -> Optional[int]:
        """估算达到目标需要的周期数"""
        if current <= target:
            return 0
        if decay_rate <= 0 or decay_rate >= 1:
            return None

        import math
        try:
            periods = math.ceil(math.log(target / current) / math.log(decay_rate))
            return max(1, periods)
        except (ValueError, ZeroDivisionError):
            return None
