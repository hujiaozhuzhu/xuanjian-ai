"""
JSRPC 核心引擎

整合浏览器管理、脚本注入、RPC 通信，提供统一的 API
"""

import asyncio
import logging
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime

from ..models import (
    BrowserConfig, RPCConfig, HookConfig, HookType,
    BrowserSession, JSRPCResult,
)
from .manager import BrowserManager
from .script_injector import ScriptInjector
from .hook_manager import HookManager
from ..rpc_server import RPCServer

logger = logging.getLogger(__name__)


class BrowserEngine:
    """JSRPC 核心引擎"""

    def __init__(
        self,
        browser_config: Optional[BrowserConfig] = None,
        rpc_config: Optional[RPCConfig] = None,
    ):
        self._browser_config = browser_config or BrowserConfig()
        self._rpc_config = rpc_config or RPCConfig()

        self._browser_manager = BrowserManager(self._browser_config.model_dump())
        self._script_injector = ScriptInjector()
        self._hook_manager = HookManager()
        self._rpc_server = RPCServer(
            host=self._rpc_config.host,
            port=self._rpc_config.port,
            auth_token=self._rpc_config.auth_token,
        )

        self._sessions: Dict[str, BrowserSession] = {}
        self._pages: Dict[str, Any] = {}  # session_id -> page object

        # 关联 RPC 服务器和引擎
        self._rpc_server.set_engine(self)

    async def start(self, enable_rpc: bool = True) -> BrowserSession:
        """启动引擎，创建默认会话"""
        await self._browser_manager.launch()

        if enable_rpc and self._rpc_config.enabled:
            try:
                await self._rpc_server.start()
            except Exception as e:
                logger.warning(f"Failed to start RPC server: {e}")

        # 创建默认会话
        session = await self.create_session()
        logger.info(f"Browser engine started. Session: {session.session_id}")
        return session

    async def create_session(self) -> BrowserSession:
        """创建新的浏览器会话"""
        session_id = str(uuid.uuid4())[:8]
        page = await self._browser_manager.new_page()

        session = BrowserSession(
            session_id=session_id,
            status="created",
            created_at=datetime.now(),
        )

        self._sessions[session_id] = session
        self._pages[session_id] = page

        # 注入事件监听器（用于接收 Hook 回调）
        await page.evaluate("""
        window.addEventListener('xuanjian_hook', function(e) {
            // 存储到全局变量，供后续读取
            if (!window.__xuanjian_events__) window.__xuanjian_events__ = [];
            window.__xuanjian_events__.push(e.detail);
        });
        """)

        logger.info(f"Created session: {session_id}")
        return session

    async def navigate(self, session_id: str, url: str) -> Dict[str, Any]:
        """导航到目标页面"""
        session, page = self._get_session(session_id)

        try:
            response = await page.goto(url, wait_until="domcontentloaded")
            session.url = url
            session.title = await page.title()
            session.status = "navigating"

            # 自动注入 RPC 桥接
            if self._rpc_config.enabled:
                await self._script_injector.inject_rpc_bridge(
                    page, self._rpc_config.port
                )

            result = {
                "success": True,
                "url": page.url,
                "title": session.title,
                "status": response.status if response else None,
            }
            logger.info(f"Navigated to: {url}")
            return result

        except Exception as e:
            session.status = "error"
            logger.error(f"Navigation failed: {e}")
            return {"success": False, "error": str(e)}

    async def inject_hook(
        self,
        session_id: str,
        target: str,
        hook_type: str = "trace",
    ) -> Dict[str, Any]:
        """注入函数 Hook"""
        session, page = self._get_session(session_id)

        config = HookConfig(
            target=target,
            hook_type=HookType(hook_type),
        )

        result = await self._script_injector.inject_hook(page, target, hook_type)

        if result.get("success"):
            session.hooks.append(config)
            self._hook_manager.add_hook(session_id, config)

        return result

    async def call_function(
        self,
        session_id: str,
        func_name: str,
        args: List[Any] = None,
    ) -> JSRPCResult:
        """远程调用页面函数"""
        session, page = self._get_session(session_id)
        args = args or []

        import time
        start = time.time()

        try:
            # 构建调用脚本
            args_json = ", ".join(repr(a) if isinstance(a, str) else str(a) for a in args)
            script = f"window['{func_name}']({args_json})"
            result = await page.evaluate(script)

            duration = (time.time() - start) * 1000

            rpc_result = JSRPCResult(
                session_id=session_id,
                function=func_name,
                arguments=args,
                result=result,
                duration_ms=round(duration, 2),
                timestamp=datetime.now(),
            )

            # 记录调用
            session.captured_calls.append({
                "function": func_name,
                "args": args,
                "result": result,
                "duration_ms": round(duration, 2),
            })

            logger.info(f"Called {func_name}({args}) -> {result}")
            return rpc_result

        except Exception as e:
            duration = (time.time() - start) * 1000
            return JSRPCResult(
                session_id=session_id,
                function=func_name,
                arguments=args,
                error=str(e),
                duration_ms=round(duration, 2),
                timestamp=datetime.now(),
            )

    async def evaluate(self, session_id: str, expression: str) -> Any:
        """在页面中执行 JS 表达式"""
        _, page = self._get_session(session_id)
        return await page.evaluate(expression)

    async def inject_script(self, session_id: str, script: str, before_load: bool = False):
        """注入自定义脚本"""
        _, page = self._get_session(session_id)
        if before_load:
            await self._script_injector.inject_before_load(page, script)
        else:
            await self._script_injector.inject_after_load(page, script)

    async def inject_crypto_hooks(self, session_id: str):
        """注入加解密 Hook"""
        _, page = self._get_session(session_id)
        await self._script_injector.inject_crypto_hooks(page)

    async def inject_xhr_hooks(self, session_id: str):
        """注入 XHR/Fetch Hook"""
        _, page = self._get_session(session_id)
        await self._script_injector.inject_xhr_hooks(page)

    async def inject_cookie_hooks(self, session_id: str):
        """注入 Cookie Hook"""
        _, page = self._get_session(session_id)
        await self._script_injector.inject_cookie_hooks(page)

    async def get_hook_events(self, session_id: str) -> List[Dict[str, Any]]:
        """获取 Hook 捕获的事件"""
        _, page = self._get_session(session_id)
        events = await page.evaluate("""
        (function() {
            var events = window.__xuanjian_events__ || [];
            window.__xuanjian_events__ = [];
            return events;
        })()
        """)
        return events

    async def get_page_snapshot(self, session_id: str) -> Dict[str, Any]:
        """获取页面快照"""
        session, page = self._get_session(session_id)
        return await self._browser_manager.get_page_snapshot(page)

    async def screenshot(self, session_id: str, path: Optional[str] = None) -> bytes:
        """截取页面截图"""
        _, page = self._get_session(session_id)
        return await page.screenshot(path=path, full_page=True)

    async def get_cookies(self, session_id: str) -> List[Dict[str, Any]]:
        """获取页面 Cookie"""
        _, page = self._get_session(session_id)
        context = page.context
        return await context.cookies()

    async def close_session(self, session_id: str):
        """关闭会话"""
        if session_id in self._pages:
            page = self._pages[session_id]
            await page.close()
            del self._pages[session_id]

        if session_id in self._sessions:
            self._sessions[session_id].status = "closed"

        self._hook_manager.cleanup_session(session_id)
        logger.info(f"Closed session: {session_id}")

    async def stop(self):
        """停止引擎"""
        # 关闭所有会话
        for session_id in list(self._sessions.keys()):
            await self.close_session(session_id)

        # 停止 RPC 服务器
        await self._rpc_server.stop()

        # 关闭浏览器
        await self._browser_manager.close()

        logger.info("Browser engine stopped")

    def _get_session(self, session_id: str) -> tuple:
        """获取会话和页面对象"""
        session = self._sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        page = self._pages.get(session_id)
        if not page:
            raise ValueError(f"Page for session {session_id} not found")

        return session, page

    def get_session(self, session_id: str) -> Optional[BrowserSession]:
        """获取会话信息"""
        return self._sessions.get(session_id)

    def list_sessions(self) -> List[BrowserSession]:
        """列出所有会话"""
        return list(self._sessions.values())

    @property
    def is_running(self) -> bool:
        """引擎是否正在运行"""
        return self._browser_manager.is_running
