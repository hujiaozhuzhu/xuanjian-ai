"""
JSRPC 核心引擎

整合浏览器管理、脚本注入、RPC 通信，提供统一的 API

v2.5.1 P1 优化：
- 增加动态 JS 执行能力（console 抓取、DOM 结构快照、网络请求拦截）
- 增加 JSRPC 接口逆向能力（自动发现 window 上的函数与属性）
- 兼容 paw browser-action 调用方式（navigate/click/type/snapshot/evaluate）
"""

import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional
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

# ── browser-action 动作类型（兼容 paw 调用方式） ──
BROWSER_ACTIONS = {
    "navigate", "click", "type", "select", "hover",
    "snapshot", "evaluate", "screenshot", "wait",
    "extract", "scroll", "focus",
}


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

    # ── v2.5.1 P1: 动态 JS / JSRPC 逆向能力 ──

    async def get_console_logs(
        self, session_id: str, clear: bool = True
    ) -> List[Dict[str, Any]]:
        """获取页面 console 日志（用于动态分析 API 请求）"""
        _, page = self._get_session(session_id)
        logs = await page.evaluate(
            """() => {
                const items = window.__xuanjian_console__ || [];
                return items;
            }()"""
        )
        if clear:
            await page.evaluate("window.__xuanjian_console__ = [];")
        return logs if isinstance(logs, list) else []

    async def inject_console_hook(self, session_id: str) -> None:
        """注入 console.log/info/warn/error Hook 到页面，捕获运行时输出"""
        _, page = self._get_session(session_id)
        await page.evaluate("""
        (function() {
            if (window.__xuanjian_console_injected__) return;
            window.__xuanjian_console_injected__ = true;
            window.__xuanjian_console__ = window.__xuanjian_console__ || [];
            const origLog = console.log, origInfo = console.info;
            const origWarn = console.warn, origError = console.error;
            const _push = (level, args) => {
                window.__xuanjian_console__.push({
                    level, timestamp: Date.now(),
                    data: Array.from(args).map(a => {
                        try { return typeof a === 'object' ? JSON.stringify(a) : String(a); }
                        catch (_) { return String(a); }
                    }),
                });
            };
            console.log   = function() { _push('log',   arguments); origLog.apply(console, arguments); };
            console.info  = function() { _push('info',  arguments); origInfo.apply(console, arguments); };
            console.warn  = function() { _push('warn',  arguments); origWarn.apply(console, arguments); };
            console.error = function() { _push('error', arguments); origError.apply(console, arguments); };
        })()
        """)
        logger.info(f"console hook injected for session {session_id}")

    async def get_network_requests(
        self, session_id: str, clear: bool = True
    ) -> List[Dict[str, Any]]:
        """获取页面 XHR/Fetch 请求记录（动态接口逆向）"""
        _, page = self._get_session(session_id)
        reqs = await page.evaluate(
            """() => {
                return (window.__xuanjian_network__ || []).map(r => ({
                    url: r.url,
                    method: r.method || 'GET',
                    headers: r.headers || {},
                    body: r.body || null,
                    status: r.status || null,
                    response: r.response || null,
                    timestamp: r.timestamp || null,
                }));
            }()"""
        )
        if clear:
            await page.evaluate("window.__xuanjian_network__ = [];")
        return reqs if isinstance(reqs, list) else []

    async def inject_network_hook(self, session_id: str) -> None:
        """注入 XHR/Fetch 双重 Hook，拦截所有网络请求响应"""
        _, page = self._get_session(session_id)
        await page.evaluate("""
        (function() {
            if (window.__xuanjian_network_injected__) return;
            window.__xuanjian_network_injected__ = true;
            window.__xuanjian_network__ = window.__xuanjian_network__ || [];

            // Hook XMLHttpRequest
            const OrigXHR = window.XMLHttpRequest;
            function PatchedXHR() {
                const xhr = new OrigXHR();
                const entry = { type: 'xhr', timestamp: Date.now() };
                const origOpen = xhr.open, origSend = xhr.send;
                xhr.open = function(method, url) {
                    entry.method = method; entry.url = url;
                    return origOpen.apply(this, arguments);
                };
                xhr.send = function(body) {
                    entry.body = body || null;
                    this.addEventListener('load', function() {
                        entry.status = this.status;
                        try { entry.response = this.responseText ? this.responseText.substring(0, 2000) : null; } catch(_) {}
                        window.__xuanjian_network__.push(Object.assign({}, entry));
                    });
                    return origSend.apply(this, arguments);
                };
                return xhr;
            }
            PatchedXHR.prototype = OrigXHR.prototype;
            window.XMLHttpRequest = PatchedXHR;

            // Hook fetch
            const origFetch = window.fetch;
            window.fetch = function(input, init) {
                const url = typeof input === 'string' ? input : (input.url || '');
                const method = (init && init.method) || 'GET';
                const entry = { type: 'fetch', url, method, timestamp: Date.now() };
                if (init && init.body) {
                    try { entry.body = typeof init.body === 'string' ? init.body.substring(0, 1000) : 'non-string'; } catch(_) {}
                }
                return origFetch.apply(this, arguments).then(resp => {
                    const clone = resp.clone();
                    clone.text().then(t => {
                        entry.status = resp.status;
                        entry.response = t.substring(0, 2000);
                        window.__xuanjian_network__.push(Object.assign({}, entry));
                    }).catch(() => {
                        entry.status = resp.status; entry.response = null;
                        window.__xuanjian_network__.push(Object.assign({}, entry));
                    });
                    return resp;
                });
            };
        })()
        """)
        logger.info(f"network hook injected for session {session_id}")

    async def discover_rpc_interfaces(
        self, session_id: str, prefix_filter: str = ""
    ) -> Dict[str, Any]:
        """动态发现页面 window 上的函数与对象（JSRPC 接口逆向）

        Args:
            session_id: 浏览器会话 ID
            prefix_filter: 前缀过滤（如 "api" "service" "rpc"），空则返回全部

        Returns:
            { "functions": [...], "objects": [...], "properties": [...] }
        """
        _, page = self._get_session(session_id)
        filter_js = f'var _pfx = "{prefix_filter}";' if prefix_filter else 'var _pfx = "";'
        result = await page.evaluate(filter_js + """
        (function() {
            var found = { functions: [], objects: [], properties: [] };
            var names = Object.getOwnPropertyNames(window);
            for (var i = 0; i < names.length; i++) {
                var name = names[i];
                if (_pfx && name.indexOf(_pfx) !== 0 && name.indexOf(_pfx) === -1) {
                    if (name !== _pfx && !name.toLowerCase().includes(_pfx.toLowerCase())) continue;
                }
                try {
                    var val = window[name];
                    if (typeof val === 'function') {
                        found.functions.push({
                            name: name,
                            source: val.toString().substring(0, 200),
                            isAsync: val.constructor && val.constructor.name === 'AsyncFunction',
                        });
                    } else if (typeof val === 'object' && val !== null && !Array.isArray(val)) {
                        var methods = Object.keys(val).filter(function(k) {
                            try { return typeof val[k] === 'function'; } catch(_) { return false; }
                        }).slice(0, 20);
                        if (methods.length > 0) {
                            found.objects.push({ name: name, methods: methods });
                        }
                    } else {
                        found.properties.push({ name: name, type: typeof val });
                    }
                } catch(_) {}
            }
            return found;
        })()
        """)
        if isinstance(result, dict):
            return result
        return {"functions": [], "objects": [], "properties": []}

    async def get_dom_snapshot(self, session_id: str) -> Dict[str, Any]:
        """获取简化 DOM 结构快照（用于动态界面分析）"""
        _, page = self._get_session(session_id)
        return await page.evaluate("""
        (function() {
            function _walk(el, depth) {
                if (!el || depth > 6) return null;
                var node = {
                    tag: el.tagName ? el.tagName.toLowerCase() : '',
                    id: el.id || undefined,
                    className: typeof el.className === 'string' ? el.className.substring(0, 100) : undefined,
                    text: el.children && el.children.length === 0 ? (el.textContent || '').substring(0, 100) : undefined,
                    attrs: {},
                };
                if (el.attributes) {
                    for (var i = 0; i < Math.min(el.attributes.length, 10); i++) {
                        var a = el.attributes[i];
                        if (['id','class','href','src','type','name','value','data-'].some(function(p){return a.name.startsWith(p);})) {
                            node.attrs[a.name] = a.value.substring(0, 100);
                        }
                    }
                }
                if (el.children && el.children.length > 0 && el.children.length <= 30) {
                    node.children = [];
                    for (var j = 0; j < el.children.length; j++) {
                        var child = _walk(el.children[j], depth + 1);
                        if (child) node.children.push(child);
                    }
                }
                return node;
            }
            return _walk(document.body, 0) || {};
        })()
        """)

    # ── v2.5.1 P1: 兼容 paw browser-action 调用方式 ──

    async def browser_action(
        self, session_id: str, action: str, **kwargs: Any
    ) -> Dict[str, Any]:
        """统一的浏览器动作接口（兼容 paw browser-action 调用方式）

        支持的 action:
        - navigate: {url, wait_until?}
        - click: {selector, button?}
        - type: {selector, text, clear?}
        - select: {selector, value}
        - hover: {selector}
        - focus: {selector}
        - snapshot: {}  返回 DOM 简化结构
        - evaluate: {expression}
        - screenshot: {path?}
        - wait: {timeout?, selector?}
        - extract: {selector, attribute?}
        - scroll: {direction?, amount?}
        """
        if action not in BROWSER_ACTIONS:
            return {"success": False, "error": f"Unsupported action: {action}"}

        handler_name = f"_action_{action}"
        handler = getattr(self, handler_name, None)
        if handler is None:
            return {"success": False, "error": f"No handler for action: {action}"}

        _, page = self._get_session(session_id)
        try:
            return await handler(page, **kwargs)
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _action_navigate(self, page, **kw) -> Dict[str, Any]:
        url = kw.get("url", "")
        wait_until = kw.get("wait_until", "domcontentloaded")
        resp = await page.goto(url, wait_until=wait_until)
        return {"success": True, "url": page.url, "status": resp.status if resp else None}

    async def _action_click(self, page, **kw) -> Dict[str, Any]:
        selector = kw.get("selector", "")
        button = kw.get("button", "left")
        await page.click(selector, button=button)
        return {"success": True, "clicked": selector}

    async def _action_type(self, page, **kw) -> Dict[str, Any]:
        selector = kw.get("selector", "")
        text = kw.get("text", "")
        clear = kw.get("clear", False)
        if clear:
            await page.fill(selector, "")
        await page.type(selector, text, delay=10)
        return {"success": True, "typed": text, "selector": selector}

    async def _action_select(self, page, **kw) -> Dict[str, Any]:
        selector = kw.get("selector", "")
        value = kw.get("value", "")
        await page.select_option(selector, value)
        return {"success": True, "selector": selector, "value": value}

    async def _action_hover(self, page, **kw) -> Dict[str, Any]:
        selector = kw.get("selector", "")
        await page.hover(selector)
        return {"success": True, "hovered": selector}

    async def _action_focus(self, page, **kw) -> Dict[str, Any]:
        selector = kw.get("selector", "")
        await page.focus(selector)
        return {"success": True, "focused": selector}

    async def _action_snapshot(self, page, **kw) -> Dict[str, Any]:
        dom = await self.get_dom_snapshot(self._session_id_from_page(page))
        return {"success": True, "dom": dom}

    async def _action_evaluate(self, page, **kw) -> Dict[str, Any]:
        expression = kw.get("expression", "")
        result = await page.evaluate(expression)
        return {"success": True, "result": result}

    async def _action_screenshot(self, page, **kw) -> Dict[str, Any]:
        path = kw.get("path")
        await page.screenshot(path=path, full_page=True)
        return {"success": True, "path": path}

    async def _action_wait(self, page, **kw) -> Dict[str, Any]:
        timeout = kw.get("timeout")
        selector = kw.get("selector")
        if selector:
            await page.wait_for_selector(selector, timeout=timeout or 30000)
        elif timeout:
            await page.wait_for_timeout(timeout)
        return {"success": True}

    async def _action_extract(self, page, **kw) -> Dict[str, Any]:
        selector = kw.get("selector", "")
        attribute = kw.get("attribute")
        if attribute:
            value = await page.get_attribute(selector, attribute)
        else:
            value = await page.inner_text(selector)
        return {"success": True, "value": value, "selector": selector}

    async def _action_scroll(self, page, **kw) -> Dict[str, Any]:
        direction = kw.get("direction", "down")
        amount = kw.get("amount", 300)
        delta_y = amount if direction == "down" else -amount
        await page.evaluate(f"window.scrollBy(0, {delta_y})")
        return {"success": True, "direction": direction, "amount": amount}

    def _session_id_from_page(self, page) -> str:
        """根据 page 对象反查 session_id（内部辅助）"""
        for sid, p in self._pages.items():
            if p is page:
                return sid
        # fallback: 返回第一个活跃 session
        if self._sessions:
            return next(iter(self._sessions))
        raise ValueError("No session found for page")
