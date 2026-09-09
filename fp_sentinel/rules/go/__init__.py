"""
Go 语言安全规则库 v2.3.0

覆盖 OWASP Top 10 中 Go 常见高危漏洞场景：
- 命令注入 (Command Injection)
- SQL 注入 (SQL Injection)
- 路径遍历 (Path Traversal)
- 硬编码密钥 (Hardcoded Secrets)
- SSRF (Server-Side Request Forgery)
- 弱加密 (Weak Cryptography)
- 不安全的 HTTP 配置
- Template 注入
- 竞态条件（信息级别）

遵循玄鉴规则规范：
- 每条规则编译安全（正则预编译缓存）
- 支持 false_positive_indicators 行内误报抑制
- 支持安全守卫上下文窗口（GoScanner 内实现）
- 规则 ID 统一前缀 go.
"""

from .rules import (
    GO_SECURITY_RULES,
    GO_RULES_INDEX,
    GO_SECURITY_GUARD_PATTERNS,
    GO_FALSE_POSITIVE_RULES,
    GoRule,
)

__all__ = [
    "GO_SECURITY_RULES",
    "GO_RULES_INDEX",
    "GO_SECURITY_GUARD_PATTERNS",
    "GO_FALSE_POSITIVE_RULES",
    "GoRule",
]
