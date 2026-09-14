"""优先级排序与过滤 —— severity > confidence > 类别 稳定排序。"""

from __future__ import annotations

from typing import List, Optional

from ..models.insight import InsightCategory, Severity, TechnicalInsight

__all__ = ["sort_insights", "filter_insights", "severity_rank"]

# 类别权重: 加密/网络/存储/组件类风险优先于反分析与隐私提示
_CATEGORY_ORDER = {
    InsightCategory.CRYPTO: 0,
    InsightCategory.NETWORK: 1,
    InsightCategory.STORAGE: 2,
    InsightCategory.COMPONENT: 3,
    InsightCategory.ANTI_ANALYSIS: 4,
    InsightCategory.PRIVACY: 5,
}


def severity_rank(insight: TechnicalInsight) -> int:
    """严重度数值(供外部排序)。"""
    return insight.severity.value


def sort_insights(insights: List[TechnicalInsight]) -> List[TechnicalInsight]:
    """稳定排序: 严重度降序 → 置信度降序 → 类别权重 → 规则 ID。"""
    return sorted(
        insights,
        key=lambda i: (
            -i.severity.value,
            -i.confidence,
            _CATEGORY_ORDER.get(i.category, 99),
            i.rule_id,
        ),
    )


def filter_insights(
    insights: List[TechnicalInsight],
    category: Optional[InsightCategory] = None,
    min_severity: Optional[Severity] = None,
) -> List[TechnicalInsight]:
    """按类别/最低严重度过滤。"""
    out = insights
    if category is not None:
        cat = InsightCategory.parse(category) if isinstance(category, str) else category
        out = [i for i in out if i.category == cat]
    if min_severity is not None:
        sev = Severity.parse(min_severity)
        out = [i for i in out if i.severity.value >= sev.value]
    return out
