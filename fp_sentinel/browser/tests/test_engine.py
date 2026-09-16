"""browser/engine.py 核心测试 — 不启动真实浏览器，用 mock page 验证调用链。"""

import asyncio
import base64
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime


def _run(coro):
    """Helper to run coroutine synchronously."""
    return asyncio.get_event_loop().run_until_complete(coro)


class TestBrowserEngineWithMock(unittest.TestCase):
    """用 mock page 验证 engine 行为，不需要启动真实浏览器。"""

    def _make_engine(self):
        """Create a BrowserEngine with mocked dependencies."""
        # Patch out heavy dependencies at module level
        with patch("fp_sentinel.browser.engine.RPCServer") as mock_rpc_cls, \
             patch("fp_sentinel.browser.engine.HookManager") as mock_hook_cls, \
             patch("fp_sentinel.browser.engine.ScriptInjector") as mock_si_cls, \
             patch("fp_sentinel.browser.engine.BrowserManager") as mock_bm_cls:

            # Create instance with mocked __init__
            # We re-import inside the patch to get the patched classes
            from fp_sentinel.browser.engine import BrowserEngine

            # Construct engine without calling __init__ to avoid real setup
            engine = BrowserEngine.__new__(BrowserEngine)

            # Set up lightweight magic mocks for internals
            engine._browser_config = MagicMock()
            engine._rpc_config = MagicMock()
            engine._rpc_config.enabled = True
            engine._rpc_config.port = 18800
            engine._rpc_config.host = "127.0.0.1"

            mock_bm = mock_bm_cls.return_value
            engine._browser_manager = mock_bm

            mock_si = mock_si_cls.return_value
            engine._script_injector = mock_si

            mock_hm = mock_hook_cls.return_value
            engine._hook_manager = mock_hm

            mock_rpc = mock_rpc_cls.return_value
            mock_rpc.set_engine = MagicMock()
            engine._rpc_server = mock_rpc

            engine._sessions = {}
            engine._pages = {}

            # Create a mock page
            mock_page = MagicMock()

            # Mock async methods with AsyncMock
            mock_page.goto = AsyncMock(return_value=MagicMock(status=200))
            mock_page.title = AsyncMock(return_value="Test Page")
            mock_page.evaluate = AsyncMock(return_value={"result": "ok"})
            mock_page.screenshot = AsyncMock(return_value=b"\x89PNG\r\n\x1a\nfake_png_bytes")
            mock_page.close = AsyncMock()
            mock_page.click = AsyncMock()
            mock_page.type = AsyncMock()
            mock_page.fill = AsyncMock()
            mock_page.hover = AsyncMock()
            mock_page.focus = AsyncMock()
            mock_page.select_option = AsyncMock()
            mock_page.get_attribute = AsyncMock(return_value="attr_val")
            mock_page.inner_text = AsyncMock(return_value="text content")
            mock_page.url = "https://example.com/page"

            # Mock context for cookies
            mock_context = MagicMock()
            mock_context.cookies = AsyncMock(return_value=[
                {"name": "session", "value": "abc123"},
                {"name": "csrftoken", "value": "xyz789"},
            ])
            mock_page.context = mock_context

            # Set up script_injector mock methods
            mock_si.inject_rpc_bridge = AsyncMock(return_value={"success": True})
            mock_si.inject_hook = AsyncMock(return_value={"success": True})
            mock_si.inject_before_load = AsyncMock(return_value=None)
            mock_si.inject_after_load = AsyncMock(return_value=None)
            mock_si.inject_crypto_hooks = AsyncMock(return_value=None)
            mock_si.inject_xhr_hooks = AsyncMock(return_value=None)
            mock_si.inject_cookie_hooks = AsyncMock(return_value=None)

            # Register a session with the mock page
            from fp_sentinel.models import BrowserSession
            session = BrowserSession(
                session_id="test123",
                status="ready",
                url="https://example.com",
                title="Test Page",
                created_at=datetime.now(),
            )
            engine._sessions["test123"] = session
            engine._pages["test123"] = mock_page

            return engine, mock_page, session

    def test_navigate_success(self):
        """Verify engine.navigate passes URL through to page.goto."""
        engine, mock_page, _ = self._make_engine()
        result = _run(engine.navigate("test123", "https://example.com/login"))
        mock_page.goto.assert_called_once_with(
            "https://example.com/login", wait_until="domcontentloaded"
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["url"], "https://example.com/page")

    def test_evaluate_expression(self):
        """Verify engine.evaluate passes expression to page.evaluate."""
        engine, mock_page, _ = self._make_engine()
        result = _run(engine.evaluate("test123", "document.title"))
        mock_page.evaluate.assert_called_once_with("document.title")
        self.assertEqual(result, {"result": "ok"})

    def test_inject_hook_triggers_script(self):
        """Verify engine.inject_hook triggers script_injector."""
        engine, mock_page, _ = self._make_engine()
        result = _run(engine.inject_hook("test123", "window.encrypt", "trace"))
        engine._script_injector.inject_hook.assert_called_once_with(
            mock_page, "window.encrypt", "trace"
        )
        self.assertTrue(result["success"])

    def test_call_function_with_args(self):
        """Verify engine.call_function merges function_name and args into script."""
        engine, mock_page, _ = self._make_engine()
        result = _run(engine.call_function("test123", "myFunc", ["arg1", 42]))
        # The call should pass a script like: window['myFunc']('arg1', 42)
        call_args = mock_page.evaluate.call_args
        script = call_args[0][0]
        self.assertIn("myFunc", script)
        self.assertIn("arg1", script)
        self.assertIn("42", script)
        # Verify returned JSRPCResult-like structure
        self.assertEqual(result.function, "myFunc")
        self.assertEqual(result.arguments, ["arg1", 42])

    def test_screenshot_returns_bytes(self):
        """Verify engine.screenshot returns raw bytes from page.screenshot."""
        engine, mock_page, _ = self._make_engine()
        result = _run(engine.screenshot("test123"))
        mock_page.screenshot.assert_called_once()
        # Result is raw bytes from page.screenshot
        self.assertIsInstance(result, bytes)
        self.assertTrue(result.startswith(b"\x89PNG"))

    def test_get_cookies_returns_list(self):
        """Verify get_cookies reads from page.context.cookies()."""
        engine, mock_page, _ = self._make_engine()
        result = _run(engine.get_cookies("test123"))
        mock_page.context.cookies.assert_called_once()
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["name"], "session")

    def test_close_session(self):
        """Verify close_session sets status to closed, removes page, and closes page."""
        engine, mock_page, session = self._make_engine()
        _run(engine.close_session("test123"))
        mock_page.close.assert_called_once()
        # close_session removes page from dict but keeps session with "closed" status
        self.assertNotIn("test123", engine._pages)
        self.assertEqual(session.status, "closed")

    def test_inject_hook_appends_to_session(self):
        """Verify successful hook injection adds config to session.hooks."""
        engine, mock_page, session = self._make_engine()
        _run(engine.inject_hook("test123", "fetch", "trace"))
        self.assertEqual(len(session.hooks), 1)
        self.assertEqual(session.hooks[0].target, "fetch")

    def test_browser_action_navigate(self):
        """Verify browser_action with 'navigate' delegates to _action_navigate."""
        engine, mock_page, _ = self._make_engine()
        result = _run(engine.browser_action("test123", "navigate", url="https://other.com"))
        self.assertTrue(result["success"])
        self.assertEqual(result["url"], "https://example.com/page")

    def test_browser_action_unsupported(self):
        """Verify unsupported action returns error dict."""
        engine, _, _ = self._make_engine()
        result = _run(engine.browser_action("test123", "invalid_action"))
        self.assertFalse(result["success"])
        self.assertIn("Unsupported", result["error"])


if __name__ == "__main__":
    unittest.main()
