"""
玄鉴 v2.3.0 — 规则优化模块 (Rule Optimization Module)

包含三个子功能：
1. 自动调优 (auto_tuner): 读取历史误报数据，自动调整三层过滤器阈值
2. 用户自定义规则加载器 (custom_rule_loader): YAML文件导入自定义扫描规则
3. Java规则库优化器 (java_rule_optimizer): 合并重复规则，修复已知漏洞

版本: 2.3.0
"""

__version__ = "2.3.0"

from .auto_tuner import AutoTuner, TuningResult
from .custom_rule_loader import CustomRuleLoader, CustomRule
from .java_rule_optimizer import JavaRuleOptimizer, OptimizationResult

__all__ = [
    "AutoTuner",
    "TuningResult",
    "CustomRuleLoader",
    "CustomRule",
    "JavaRuleOptimizer",
    "OptimizationResult",
]
