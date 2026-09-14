"""mobile_insight.core —— 提示引擎核心。"""

from .context import AnalysisContext
from .engine import InsightEngine, Rule
from .priority import filter_insights, sort_insights

__all__ = ["AnalysisContext", "InsightEngine", "Rule", "filter_insights", "sort_insights"]
