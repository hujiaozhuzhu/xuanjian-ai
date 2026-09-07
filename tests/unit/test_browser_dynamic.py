"""
v2.5.1 P1: BrowserEngine 动态能力测试

覆盖:
- 动态 JS inject_console_hook / get_console_logs
- inject_network_hook / get_network_requests
- discover_rpc_interfaces
- get_dom_snapshot
- browser_action (兼容 paw 调用方式)
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fp_sentinel.browser.engine import BrowserEngine, BROWSER_ACTIONS
from fp_sentinel.models import BrowserConfig, RPCConfig, BrowserSession


def _make_engine(rpc_enabled=False):
    browser_config = BrowserConfig()
    rpc_config = RPCConfig(enabled=rpc_enabled)
    return BrowserEngine(browser_config, rpc_config)


def _setup_mock_session(engine, session_id="test-sess"):
    mock_page = AsyncMock()
    mock_page.evaluate = AsyncMock(return_value=None)
    engine._sessions[session_id] = BrowserSession(session_id=session_id)
    engine._pages[session_id] = mock_page
    return mock_page


class TestBrowserActionSet:
    """验证 BROWSER_ACTIONS 集合包含所有标准动作"""

    def test_all_actions_present(self):
        expected = {"navigate", "click", "type", "select", "hover",
                    "snapshot", "evaluate", "screenshot", "wait",
                    "extract", "scroll", "focus"}
        assert BROWSER_ACTIONS == expected


class TestBrowserActionDispatch:
    """browser_action 方法分发逻辑测试"""

    def test_invalid_action_returns_error(self):
        engine = _make_engine()
        _setup_mock_session(engine)

        async def _run():
            return await engine.browser_action("test-sess", "invalid_action")

        import asyncio
        result = asyncio.run(_run())
        assert result["success"] is False
        assert "Unsupported action" in result["error"]

    def test_navigate_action(self):
        engine = _make_engine()
        _setup_mock_session(engine)

        async def _run():
            return await engine.browser_action("test-sess", "navigate", url="https://example.com")

        import asyncio
        result = asyncio.run(_run())
        assert result["success"] is True

    def test_unsupported_action_type(self):
        engine = _make_engine()
        _setup_mock_session(engine)

        async def _run():
            return await engine.browser_action("test-sess", "nonexistent_action")

        import asyncio
        result = asyncio.run(_run())
        assert result["success"] is False


class TestDynamicJSConsoleHook:
    """动态 console Hook 注入与日志采集"""

    def test_inject_console_hook_no_exception(self):
        engine = _make_engine()
        mock_page = _setup_mock_session(engine)
        mock_page.evaluate = AsyncMock(return_value=None)
        import asyncio
        # 不应抛异常
        asyncio.run(engine.inject_console_hook("test-sess"))
        assert mock_page.evaluate.call_count >= 1

    def test_get_console_logs_empty(self):
        engine = _make_engine()
        mock_page = _setup_mock_session(engine)
        # 3 calls: inject_console_hook(1) + get_console_logs(read + clear)(2)
        mock_page.evaluate = AsyncMock(side_effect=[None, [], None])
        import asyncio
        asyncio.run(engine.inject_console_hook("test-sess"))
        logs = asyncio.run(engine.get_console_logs("test-sess", clear=True))
        assert isinstance(logs, list)
        assert logs == []

    def test_get_console_logs_with_data(self):
        engine = _make_engine()
        mock_page = _setup_mock_session(engine)
        fake_logs = [{"level": "log", "data": ["token=abc123"]}]
        # get_console_logs(clear=True) calls evaluate twice: read + clear
        mock_page.evaluate = AsyncMock(side_effect=[None, fake_logs, None])
        import asyncio
        asyncio.run(engine.inject_console_hook("test-sess"))
        logs = asyncio.run(engine.get_console_logs("test-sess", clear=True))
        assert logs == fake_logs


class TestDynamicNetworkHook:
    """动态 XHR/Fetch Hook 注入与网络请求采集"""

    def test_inject_network_hook_no_exception(self):
        engine = _make_engine()
        mock_page = _setup_mock_session(engine)
        mock_page.evaluate = AsyncMock(return_value=None)
        import asyncio
        asyncio.run(engine.inject_network_hook("test-sess"))
        assert mock_page.evaluate.call_count >= 1

    def test_get_network_requests_empty(self):
        engine = _make_engine()
        mock_page = _setup_mock_session(engine)
        # 3 calls: hook inject + read + clear
        mock_page.evaluate = AsyncMock(side_effect=[None, [], None])
        import asyncio
        asyncio.run(engine.inject_network_hook("test-sess"))
        reqs = asyncio.run(engine.get_network_requests("test-sess", clear=True))
        assert isinstance(reqs, list)
        assert reqs == []

    def test_get_network_requests_with_data(self):
        engine = _make_engine()
        mock_page = _setup_mock_session(engine)
        fake_reqs = [{"url": "/api/login", "method": "POST", "status": 200}]
        # get_network_requests(clear=True): read + clear
        mock_page.evaluate = AsyncMock(side_effect=[None, fake_reqs, None])
        import asyncio
        asyncio.run(engine.inject_network_hook("test-sess"))
        reqs = asyncio.run(engine.get_network_requests("test-sess", clear=True))
        assert len(reqs) == 1
        assert reqs[0]["url"] == "/api/login"


class TestDiscoverRpcInterfaces:
    """JSRPC 接口逆向发现测试"""

    def test_discover_returns_dict_structure(self):
        engine = _make_engine()
        mock_page = _setup_mock_session(engine)
        mock_page.evaluate = AsyncMock(return_value={
            "functions": [{"name": "apiLogin", "source": "function(){}", "isAsync": False}],
            "objects": [{"name": "apiService", "methods": ["login", "logout"]}],
            "properties": [{"name": "version", "type": "string"}],
        })
        import asyncio
        result = asyncio.run(engine.discover_rpc_interfaces("test-sess"))
        assert "functions" in result
        assert "objects" in result
        assert "properties" in result

    def test_discover_with_invalid_result(self):
        engine = _make_engine()
        mock_page = _setup_mock_session(engine)
        # 返回非 dict 时应降级为空结构
        mock_page.evaluate = AsyncMock(return_value=None)
        import asyncio
        result = asyncio.run(engine.discover_rpc_interfaces("test-sess"))
        assert isinstance(result, dict)
        assert result == {"functions": [], "objects": [], "properties": []}

    def test_discover_with_prefix_filter(self):
        engine = _make_engine()
        mock_page = _setup_mock_session(engine)
        mock_page.evaluate = AsyncMock(return_value={
            "functions": [],
            "objects": [],
            "properties": [],
        })
        import asyncio
        result = asyncio.run(engine.discover_rpc_interfaces("test-sess", prefix_filter="api"))
        assert "functions" in result


class TestDomSnapshot:
    """DOM 快照采集测试"""

    def test_get_dom_snapshot_returns_dict(self):
        engine = _make_engine()
        mock_page = _setup_mock_session(engine)
        mock_page.evaluate = AsyncMock(return_value={"tag": "body", "children": []})
        import asyncio
        result = asyncio.run(engine.get_dom_snapshot("test-sess"))
        assert isinstance(result, dict)
        assert result["tag"] == "body"

    def test_get_dom_snapshot_handles_none(self):
        engine = _make_engine()
        mock_page = _setup_mock_session(engine)
        mock_page.evaluate = AsyncMock(return_value=None)
        import asyncio
        result = asyncio.run(engine.get_dom_snapshot("test-sess"))
        # None should still return (though downstream caller needs to handle)
        assert result is None or isinstance(result, dict)


class TestSessionIdFromPage:
    """_session_id_from_page 方法测试"""

    def test_find_session_by_identity(self):
        engine = _make_engine()
        mock_page = AsyncMock()
        engine._sessions["sess-1"] = BrowserSession(session_id="sess-1")
        engine._pages["sess-1"] = mock_page
        assert engine._session_id_from_page(mock_page) == "sess-1"

    def test_fallback_to_first_session(self):
        engine = _make_engine()
        known_page = AsyncMock()
        engine._sessions["any-id"] = BrowserSession(session_id="any-id")
        engine._pages["any-id"] = known_page
        # Unknown page falls back to first session
        unknown_page = AsyncMock()
        result = engine._session_id_from_page(unknown_page)
        assert result == "any-id"

    def test_no_session_raises(self):
        engine = _make_engine()
        with pytest.raises(ValueError, match="No session found"):
            engine._session_id_from_page(AsyncMock())
