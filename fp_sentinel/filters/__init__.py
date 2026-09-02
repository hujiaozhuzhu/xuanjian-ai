"""
过滤器模块

三层过滤架构：
- L1: 规则过滤 (rule_filter)
- L2: 上下文分析 (context_filter)
- L3: 历史基线 (baseline)
"""

from .rule_filter import RuleFilter
from .context_filter import ContextFilter
from .baseline import BaselineFilter

# JS 上下文过滤器（可选）
try:
    from .js_context_filter import JSContextFilter
except ImportError:
    JSContextFilter = None

# 保持向后兼容：MLFilter = BaselineFilter
MLFilter = BaselineFilter

__all__ = ["RuleFilter", "ContextFilter", "BaselineFilter", "MLFilter", "JSContextFilter"]
