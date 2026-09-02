"""
浏览器引擎模块

提供 Playwright 集成、脚本注入、JSRPC 通信等功能
用于 JavaScript 逆向工程和自动化安全测试
"""

from .engine import BrowserEngine
from .manager import BrowserManager
from .script_injector import ScriptInjector
from .rpc_server import RPCServer
from .hook_manager import HookManager

__all__ = [
    "BrowserEngine",
    "BrowserManager",
    "ScriptInjector",
    "RPCServer",
    "HookManager",
]
