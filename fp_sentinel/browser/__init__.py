"""
浏览器引擎模块

提供 Playwright 集成、脚本注入、JSRPC 通信等功能
用于 JavaScript 逆向工程和自动化安全测试
"""

from .manager import BrowserManager
from .script_injector import ScriptInjector
from .hook_manager import HookManager

# BrowserEngine 和 RPCServer 需要额外依赖，延迟导入
try:
    from .engine import BrowserEngine
except ImportError:
    BrowserEngine = None

try:
    from ..rpc_server import RPCServer
except ImportError:
    RPCServer = None

__all__ = [
    "BrowserEngine",
    "BrowserManager",
    "ScriptInjector",
    "RPCServer",
    "HookManager",
]
