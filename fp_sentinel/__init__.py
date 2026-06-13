"""
玄鉴 fp_sentinel - 代码审计误报排查 MCP Skill

面向安全研究团队的开源代码审计误报排查工具
优先支持 Java 代码审计

三层过滤架构：
- L1: 规则过滤 (RuleFilter)
- L2: 上下文分析 (ContextFilter)
- L3: 历史基线 (BaselineFilter)
"""

__version__ = "0.1.0"
__author__ = "XuanJian AI"

from .server import create_server, FPServer, create_app
from .mcp_server import create_mcp_server, MCPAuditServer
from .filters import RuleFilter, ContextFilter, BaselineFilter, MLFilter
from .models import (
    ScanResult, FilterResult, FilterStatistics, FilterResponse,
    Verdict, Severity, ScanTool, Finding, Project,
)

__all__ = [
    # 服务器
    "create_server",
    "create_mcp_server",
    "create_app",
    "FPServer",
    "MCPAuditServer",
    # 过滤器
    "RuleFilter",
    "ContextFilter",
    "BaselineFilter",
    "MLFilter",
    # 模型
    "ScanResult",
    "FilterResult",
    "FilterStatistics",
    "FilterResponse",
    "Verdict",
    "Severity",
    "ScanTool",
    "Finding",
    "Project",
]
