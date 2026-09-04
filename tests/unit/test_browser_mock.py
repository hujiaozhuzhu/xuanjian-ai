"""
浏览器引擎 Mock 测试

不依赖真实 Playwright，通过 Mock 测试核心逻辑
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fp_sentinel.models import BrowserConfig, RPCConfig, HookConfig, HookType, BrowserSession


class TestBrowserConfig:
    """浏览器配置测试"""

    def test_default_config(self):
        config = BrowserConfig()
        assert config.headless is True
        assert config.browser_type == "chromium"
        assert config.stealth_mode is True
        assert config.timeout == 30000

    def test_custom_config(self):
        config = BrowserConfig(
            headless=False,
            browser_type="firefox",
            stealth_mode=False,
            timeout=60000,
        )
        assert config.headless is False
        assert config.browser_type == "firefox"

    def test_rpc_config(self):
        config = RPCConfig()
        assert config.port == 18800
        assert config.host == "127.0.0.1"
        assert config.enabled is True

    def test_hook_config(self):
        config = HookConfig(target="window.encrypt")
        assert config.target == "window.encrypt"
        assert config.hook_type == HookType.TRACE
        assert config.capture_args is True


class TestBrowserSession:
    """浏览器会话测试"""

    def test_create_session(self):
        session = BrowserSession(session_id="test-001")
        assert session.session_id == "test-001"
        assert session.status == "created"
        assert len(session.hooks) == 0
        assert len(session.captured_keys) == 0
        assert len(session.captured_calls) == 0

    def test_session_with_hooks(self):
        hook = HookConfig(target="window.encrypt", hook_type=HookType.TRACE)
        session = BrowserSession(
            session_id="test-002",
            hooks=[hook],
        )
        assert len(session.hooks) == 1


class TestHookManager:
    """Hook管理器测试"""

    def test_import_hook_manager(self):
        from fp_sentinel.browser.hook_manager import HookManager
        manager = HookManager()
        assert manager is not None

    def test_add_hook(self):
        from fp_sentinel.browser.hook_manager import HookManager
        manager = HookManager()
        hook = HookConfig(target="window.encrypt", hook_type=HookType.TRACE)
        manager.add_hook("session-1", hook)
        hooks = manager.get_hooks("session-1")
        assert len(hooks) == 1

    def test_remove_hook(self):
        from fp_sentinel.browser.hook_manager import HookManager
        manager = HookManager()
        hook = HookConfig(target="window.encrypt", hook_type=HookType.TRACE)
        manager.add_hook("session-1", hook)
        manager.remove_hook("session-1", "window.encrypt")
        hooks = manager.get_hooks("session-1")
        assert len(hooks) == 0

    def test_add_result(self):
        from fp_sentinel.browser.hook_manager import HookManager
        manager = HookManager()
        manager.add_result("session-1", {"type": "hook_call", "target": "encrypt"})
        results = manager.get_results("session-1")
        assert len(results) == 1

    def test_get_statistics(self):
        from fp_sentinel.browser.hook_manager import HookManager
        manager = HookManager()
        hook = HookConfig(target="window.encrypt", hook_type=HookType.TRACE)
        manager.add_hook("session-1", hook)
        manager.add_result("session-1", {"type": "hook_call", "target": "encrypt"})
        stats = manager.get_statistics("session-1")
        assert stats["total_hooks"] == 1
        assert stats["total_captures"] == 1

    def test_cleanup_session(self):
        from fp_sentinel.browser.hook_manager import HookManager
        manager = HookManager()
        hook = HookConfig(target="window.encrypt", hook_type=HookType.TRACE)
        manager.add_hook("session-1", hook)
        manager.cleanup_session("session-1")
        hooks = manager.get_hooks("session-1")
        assert len(hooks) == 0


class TestScriptInjector:
    """脚本注入器测试"""

    def test_import_script_injector(self):
        from fp_sentinel.browser.script_injector import ScriptInjector
        injector = ScriptInjector()
        assert injector is not None

    def test_list_templates(self):
        from fp_sentinel.browser.script_injector import ScriptInjector
        injector = ScriptInjector()
        templates = injector.list_templates()
        # 应该有内置模板
        assert isinstance(templates, list)

    def test_register_template(self):
        from fp_sentinel.browser.script_injector import ScriptInjector
        injector = ScriptInjector()
        injector.register_template("test_script", "console.log('test')")
        template = injector.get_template("test_script")
        assert template == "console.log('test')"

    def test_generate_hook_trace(self):
        from fp_sentinel.browser.script_injector import ScriptInjector
        injector = ScriptInjector()
        script = injector._generate_trace_hook("window.encrypt")
        assert "window.encrypt" in script
        assert "__original" in script

    def test_generate_hook_before(self):
        from fp_sentinel.browser.script_injector import ScriptInjector
        injector = ScriptInjector()
        script = injector._generate_before_hook("window.encrypt")
        assert "window.encrypt" in script

    def test_generate_hook_after(self):
        from fp_sentinel.browser.script_injector import ScriptInjector
        injector = ScriptInjector()
        script = injector._generate_after_hook("window.encrypt")
        assert "window.encrypt" in script
