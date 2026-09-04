"""
过滤器模块

三层过滤架构：
- L1: 规则过滤 (rule_filter)
- L2: 上下文分析 (context_filter)
- L3: 历史基线 (baseline)

四级降噪引擎 (v2.0):
- L1: 语法降噪 (白名单注释/安全函数/常量/测试文件)
- L2: 语义降噪 (框架安全/MVC分层/安全装饰器)
- L3: 统计降噪 (误报指纹/置信度/聚类去重)
- L4: 智能降噪 (LLM边界判断)
"""

from .rule_filter import RuleFilter
from .context_filter import ContextFilter
from .baseline import BaselineFilter

# JS 上下文过滤器（可选）
try:
    from .js_context_filter import JSContextFilter
except ImportError:
    JSContextFilter = None

# 降噪引擎（v2.0）
try:
    from .noise_reducer import (
        NoiseReducerL1,
        NoiseReducerL2,
        NoiseReducerL3,
        NoiseReducerL4,
        NoisePipeline,
    )
except ImportError:
    NoiseReducerL1 = None
    NoiseReducerL2 = None
    NoiseReducerL3 = None
    NoiseReducerL4 = None
    NoisePipeline = None

# 保持向后兼容：MLFilter = BaselineFilter
MLFilter = BaselineFilter

__all__ = [
    "RuleFilter", "ContextFilter", "BaselineFilter", "MLFilter", "JSContextFilter",
    "NoiseReducerL1", "NoiseReducerL2", "NoiseReducerL3", "NoiseReducerL4", "NoisePipeline",
]
