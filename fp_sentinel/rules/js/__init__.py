"""
JavaScript/TypeScript 安全规则库

包含 JS 特有的误报规则和安全模式定义
"""

from .rules import JS_SECURITY_RULES, JS_FALSE_POSITIVE_RULES, JS_SECURITY_GUARD_PATTERNS, JS_RULES_INDEX

__all__ = [
    "JS_SECURITY_RULES",
    "JS_FALSE_POSITIVE_RULES",
    "JS_SECURITY_GUARD_PATTERNS",
    "JS_RULES_INDEX",
]
