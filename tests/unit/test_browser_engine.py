"""
浏览器引擎测试 (Mock Playwright)
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from fp_sentinel.browser.engine import BrowserEngine
from fp_sentinel.browser.manager import BrowserManager
from fp_sentinel.models import BrowserConfig, RPCConfig, HookType


class TestBrowserManager:
    """浏览器管理器测试"""

    def test_create_manager(self):
        config = BrowserConfig(headless=True, stealth_mode=True)
        manager = BrowserManager(config.model_dump())
        assert manager is not None
        assert manager.headless is True
        assert manager.stealth_mode is True

    def test_manager_not_running(self):
        config = BrowserConfig()
        manager = BrowserManager(config.model_dump())
        assert manager.is_running is False

    def test_manager_config_defaults(self):
        config = BrowserConfig()
        manager = BrowserManager(config.model_dump())
        assert manager.browser_type == "chromium"
        assert manager.timeout == 30000
        assert manager.viewport_width == 1920
        assert manager.viewport_height == 1080

    def test_manager_custom_config(self):
        config = BrowserConfig(
            headless=False,
            browser_type="firefox",
            timeout=60000,
            viewport_width=1280,
            viewport_height=720,
        )
        manager = BrowserManager(config.model_dump())
        assert manager.headless is False
        assert manager.browser_type == "firefox"
        assert manager.timeout == 60000


class TestBrowserEngine:
    """浏览器引擎测试"""

    def test_create_engine(self):
        browser_config = BrowserConfig()
        rpc_config = RPCConfig()
        engine = BrowserEngine(browser_config, rpc_config)
        assert engine is not None
        assert engine.is_running is False

    def test_engine_has_managers(self):
        browser_config = BrowserConfig()
        rpc_config = RPCConfig()
        engine = BrowserEngine(browser_config, rpc_config)
        assert engine._browser_manager is not None
        assert engine._script_injector is not None
        assert engine._hook_manager is not None
        assert engine._rpc_server is not None

    def test_engine_sessions_empty(self):
        browser_config = BrowserConfig()
        rpc_config = RPCConfig()
        engine = BrowserEngine(browser_config, rpc_config)
        assert len(engine._sessions) == 0
        assert len(engine._pages) == 0

    def test_engine_list_sessions_empty(self):
        browser_config = BrowserConfig()
        rpc_config = RPCConfig()
        engine = BrowserEngine(browser_config, rpc_config)
        sessions = engine.list_sessions()
        assert len(sessions) == 0

    def test_engine_get_nonexistent_session(self):
        browser_config = BrowserConfig()
        rpc_config = RPCConfig()
        engine = BrowserEngine(browser_config, rpc_config)
        session = engine.get_session("nonexistent")
        assert session is None

    def test_engine_get_session_error(self):
        browser_config = BrowserConfig()
        rpc_config = RPCConfig()
        engine = BrowserEngine(browser_config, rpc_config)
        with pytest.raises(ValueError, match="not found"):
            engine._get_session("nonexistent")

    def test_engine_rpc_config(self):
        browser_config = BrowserConfig()
        rpc_config = RPCConfig(port=19000, host="0.0.0.0")
        engine = BrowserEngine(browser_config, rpc_config)
        assert engine._rpc_config.port == 19000
        assert engine._rpc_config.host == "0.0.0.0"

    def test_engine_script_injector_templates(self):
        browser_config = BrowserConfig()
        rpc_config = RPCConfig()
        engine = BrowserEngine(browser_config, rpc_config)
        templates = engine._script_injector.list_templates()
        assert isinstance(templates, list)

    def test_engine_hook_manager(self):
        browser_config = BrowserConfig()
        rpc_config = RPCConfig()
        engine = BrowserEngine(browser_config, rpc_config)
        from fp_sentinel.models import HookConfig
        hook = HookConfig(target="window.encrypt", hook_type=HookType.TRACE)
        engine._hook_manager.add_hook("test-session", hook)
        hooks = engine._hook_manager.get_hooks("test-session")
        assert len(hooks) == 1


class TestBrowserEngineAsync:
    """浏览器引擎异步测试"""

    @pytest.mark.asyncio
    async def test_start_creates_session(self):
        """启动创建会话"""
        browser_config = BrowserConfig()
        rpc_config = RPCConfig(enabled=False)
        engine = BrowserEngine(browser_config, rpc_config)

        # Mock
        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(return_value=None)
        engine._browser_manager.launch = AsyncMock()
        engine._browser_manager.new_page = AsyncMock(return_value=mock_page)
        engine._browser_manager._context = MagicMock()

        session = await engine.start(enable_rpc=False)
        assert session is not None
        assert session.session_id is not None
        assert session.status == "created"

    @pytest.mark.asyncio
    async def test_navigate(self):
        """导航测试"""
        browser_config = BrowserConfig()
        rpc_config = RPCConfig(enabled=False)
        engine = BrowserEngine(browser_config, rpc_config)

        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(return_value=None)
        mock_page.goto = AsyncMock(return_value=MagicMock(status=200))
        mock_page.title = AsyncMock(return_value="Test Page")
        mock_page.url = "https://example.com"

        engine._browser_manager.launch = AsyncMock()
        engine._browser_manager.new_page = AsyncMock(return_value=mock_page)
        engine._browser_manager._context = MagicMock()

        session = await engine.start(enable_rpc=False)
        result = await engine.navigate(session.session_id, "https://example.com")
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_evaluate(self):
        """执行JS测试"""
        browser_config = BrowserConfig()
        rpc_config = RPCConfig(enabled=False)
        engine = BrowserEngine(browser_config, rpc_config)

        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(return_value=42)
        engine._browser_manager.launch = AsyncMock()
        engine._browser_manager.new_page = AsyncMock(return_value=mock_page)
        engine._browser_manager._context = MagicMock()

        session = await engine.start(enable_rpc=False)
        result = await engine.evaluate(session.session_id, "1+1")
        assert result == 42

    @pytest.mark.asyncio
    async def test_close_session(self):
        """关闭会话测试"""
        browser_config = BrowserConfig()
        rpc_config = RPCConfig(enabled=False)
        engine = BrowserEngine(browser_config, rpc_config)

        mock_page = AsyncMock()
        mock_page.close = AsyncMock()
        mock_page.evaluate = AsyncMock(return_value=None)
        engine._browser_manager.launch = AsyncMock()
        engine._browser_manager.new_page = AsyncMock(return_value=mock_page)
        engine._browser_manager._context = MagicMock()

        session = await engine.start(enable_rpc=False)
        session_id = session.session_id
        await engine.close_session(session_id)
        # 会话状态应为closed
        closed_session = engine.get_session(session_id)
        assert closed_session.status == "closed"
