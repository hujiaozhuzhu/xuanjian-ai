"""
JSRPC 服务器

提供 HTTP + WebSocket 接口，用于与注入到页面中的脚本通信
支持远程函数调用、密钥捕获、实时数据推送
"""

import asyncio
import json
import logging
from typing import Dict, Set, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class RPCServer:
    """JSRPC 服务器"""

    def __init__(self, host: str = "127.0.0.1", port: int = 18800, auth_token: Optional[str] = None):
        self.host = host
        self.port = port
        self.auth_token = auth_token
        self._app = None
        self._runner = None
        self._connections: Set[Any] = set()
        self._engine = None  # BrowserEngine reference
        self._message_handlers = {}

    def set_engine(self, engine):
        """关联浏览器引擎"""
        self._engine = engine

    async def start(self):
        """启动 RPC 服务器"""
        try:
            from aiohttp import web
        except ImportError:
            raise ImportError("aiohttp is required for RPC server. Install with: pip install aiohttp")

        self._app = web.Application()
        self._setup_routes()

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()
        logger.info(f"JSRPC server started on {self.host}:{self.port}")

    async def stop(self):
        """停止 RPC 服务器"""
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        logger.info("JSRPC server stopped")

    def _setup_routes(self):
        """设置路由"""
        from aiohttp import web

        # HTTP API
        self._app.router.add_post("/call", self._handle_call)
        self._app.router.add_post("/hook", self._handle_hook)
        self._app.router.add_get("/status", self._handle_status)
        self._app.router.add_get("/keys", self._handle_get_keys)
        self._app.router.add_get("/calls", self._handle_get_calls)
        self._app.router.add_post("/navigate", self._handle_navigate)
        self._app.router.add_post("/script", self._handle_script)
        self._app.router.add_post("/inject", self._handle_inject)
        # WebSocket
        self._app.router.add_get("/ws", self._handle_websocket)
        # CORS
        self._app.router.add_options("/call", self._handle_cors)
        self._app.router.add_options("/hook", self._handle_cors)

    def _check_auth(self, request) -> bool:
        """检查认证"""
        if not self.auth_token:
            return True
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        return token == self.auth_token

    async def _handle_cors(self, request):
        """处理 CORS 预检请求"""
        from aiohttp import web
        return web.Response(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        })

    async def _handle_call(self, request):
        """处理远程调用请求"""
        from aiohttp import web

        if not self._check_auth(request):
            return web.json_response({"error": "Unauthorized"}, status=401)

        try:
            body = await request.json()
            session_id = body.get("session", "default")
            func_name = body.get("func")
            args = body.get("args", [])

            if not func_name:
                return web.json_response({"error": "Missing 'func' parameter"}, status=400)

            if not self._engine:
                return web.json_response({"error": "Engine not available"}, status=503)

            result = await self._engine.call_function(session_id, func_name, args)
            return web.json_response({"result": result})

        except Exception as e:
            logger.error(f"Call error: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_hook(self, request):
        """处理 Hook 注入请求"""
        from aiohttp import web

        if not self._check_auth(request):
            return web.json_response({"error": "Unauthorized"}, status=401)

        try:
            body = await request.json()
            session_id = body.get("session", "default")
            target = body.get("target")
            hook_type = body.get("type", "trace")

            if not target:
                return web.json_response({"error": "Missing 'target' parameter"}, status=400)

            if not self._engine:
                return web.json_response({"error": "Engine not available"}, status=503)

            result = await self._engine.inject_hook(session_id, target, hook_type)
            return web.json_response(result)

        except Exception as e:
            logger.error(f"Hook error: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_status(self, request):
        """处理状态查询"""
        from aiohttp import web

        sessions = {}
        if self._engine:
            sessions = {
                sid: {
                    "url": s.url,
                    "status": s.status,
                    "hooks": len(s.hooks),
                    "captured_calls": len(s.captured_calls),
                }
                for sid, s in self._engine._sessions.items()
            }

        return web.json_response({
            "status": "running",
            "sessions": sessions,
            "connections": len(self._connections),
            "timestamp": datetime.now().isoformat(),
        })

    async def _handle_get_keys(self, request):
        """获取捕获的密钥"""
        from aiohttp import web

        session_id = request.query.get("session", "default")
        if self._engine:
            session = self._engine._sessions.get(session_id)
            if session:
                return web.json_response({"keys": session.captured_keys})

        return web.json_response({"keys": []})

    async def _handle_get_calls(self, request):
        """获取捕获的函数调用"""
        from aiohttp import web

        session_id = request.query.get("session", "default")
        limit = int(request.query.get("limit", "100"))
        if self._engine:
            session = self._engine._sessions.get(session_id)
            if session:
                return web.json_response({"calls": session.captured_calls[-limit:]})

        return web.json_response({"calls": []})

    async def _handle_navigate(self, request):
        """处理导航请求"""
        from aiohttp import web

        if not self._check_auth(request):
            return web.json_response({"error": "Unauthorized"}, status=401)

        try:
            body = await request.json()
            session_id = body.get("session", "default")
            url = body.get("url")

            if not url:
                return web.json_response({"error": "Missing 'url' parameter"}, status=400)

            if not self._engine:
                return web.json_response({"error": "Engine not available"}, status=503)

            result = await self._engine.navigate(session_id, url)
            return web.json_response(result)

        except Exception as e:
            logger.error(f"Navigate error: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_script(self, request):
        """处理脚本执行请求"""
        from aiohttp import web

        if not self._check_auth(request):
            return web.json_response({"error": "Unauthorized"}, status=401)

        try:
            body = await request.json()
            session_id = body.get("session", "default")
            code = body.get("code")

            if not code:
                return web.json_response({"error": "Missing 'code' parameter"}, status=400)

            if not self._engine:
                return web.json_response({"error": "Engine not available"}, status=503)

            result = await self._engine.evaluate(session_id, code)
            return web.json_response({"result": result})

        except Exception as e:
            logger.error(f"Script error: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_inject(self, request):
        """处理脚本注入请求"""
        from aiohttp import web

        if not self._check_auth(request):
            return web.json_response({"error": "Unauthorized"}, status=401)

        try:
            body = await request.json()
            session_id = body.get("session", "default")
            script = body.get("script")
            inject_type = body.get("type", "after")  # before/after

            if not script:
                return web.json_response({"error": "Missing 'script' parameter"}, status=400)

            if not self._engine:
                return web.json_response({"error": "Engine not available"}, status=503)

            session = self._engine._sessions.get(session_id)
            if not session:
                return web.json_response({"error": f"Session {session_id} not found"}, status=404)

            if inject_type == "before":
                await self._engine._script_injector.inject_before_load(session.page, script)
            else:
                await self._engine._script_injector.inject_after_load(session.page, script)

            return web.json_response({"success": True})

        except Exception as e:
            logger.error(f"Inject error: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_websocket(self, request):
        """处理 WebSocket 连接"""
        from aiohttp import web
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        self._connections.add(ws)
        logger.info(f"WebSocket connected. Total: {len(self._connections)}")

        try:
            async for msg in ws:
                if msg.type == 1:  # TEXT
                    try:
                        data = json.loads(msg.data)
                        await self._process_ws_message(ws, data)
                    except json.JSONDecodeError:
                        await ws.send_json({"error": "Invalid JSON"})
                elif msg.type == 256:  # ERROR
                    logger.error(f"WebSocket error: {msg.data}")
                    break
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
        finally:
            self._connections.discard(ws)
            logger.info(f"WebSocket disconnected. Total: {len(self._connections)}")

        return ws

    async def _process_ws_message(self, ws, data: Dict[str, Any]):
        """处理 WebSocket 消息"""
        msg_type = data.get("type")

        if msg_type == "hook_call":
            # Hook 回调数据
            session_id = data.get("session_id", "default")
            if self._engine:
                session = self._engine._sessions.get(session_id)
                if session:
                    session.captured_calls.append(data.get("data", {}))

            # 广播给所有连接
            await self._broadcast(data)

        elif msg_type == "crypto_key":
            # 密钥捕获
            session_id = data.get("session_id", "default")
            if self._engine:
                session = self._engine._sessions.get(session_id)
                if session:
                    session.captured_keys.append(data.get("data", {}))

            await self._broadcast(data)

        elif msg_type == "ping":
            await ws.send_json({"type": "pong"})

    async def _broadcast(self, message: Dict[str, Any]):
        """广播消息给所有连接"""
        dead = set()
        for ws in self._connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.add(ws)
        self._connections -= dead

    @property
    def is_running(self) -> bool:
        """服务器是否正在运行"""
        return self._runner is not None
