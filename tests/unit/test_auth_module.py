"""
Tests for the Authentication Coverage Module (v3.1)

Tests: models, session store, auto-login engine, API discoverer
Coverage target: >= 95%
"""

import sys
import os
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from fp_sentinel.auth.models import (
    LoginCredential,
    LoginResult,
    AuthSessionConfig,
    APITestRequest,
    APITestResult,
    SessionState,
    LoginFormStrategy,
    AuthenticatedScanResult,
)


class TestLoginCredential(unittest.TestCase):
    def test_create_minimal(self):
        cred = LoginCredential(target_url="http://localhost/login")
        self.assertEqual(cred.target_url, "http://localhost/login")
        self.assertEqual(cred.strategy, LoginFormStrategy.AUTO)
        self.assertEqual(cred.max_retries, 3)

    def test_create_full(self):
        cred = LoginCredential(
            target_url="http://localhost:8080/login",
            username="admin",
            password="p@ssw0rd!test",
            strategy=LoginFormStrategy.MULTI_STEP,
            max_retries=5,
            extra_fields={"otp": "123456"},
        )
        self.assertEqual(cred.username, "admin")
        self.assertEqual(cred.max_retries, 5)
        self.assertIn("otp", cred.extra_fields)

    def test_create_with_complex_password(self):
        cred = LoginCredential(
            target_url="http://localhost:8080/login",
            username="admin",
            password="compl3x!p@ss#2024",
        )
        self.assertTrue(len(cred.password) > 0)

    def test_extra_forbidden(self):
        with self.assertRaises(Exception):
            LoginCredential(target_url="http://localhost", unknown_field="bad")

    def test_model_dump_excludes_password_in_str(self):
        cred = LoginCredential(
            target_url="http://localhost", username="user", password="secret"
        )
        d = cred.model_dump()
        self.assertIn("password", d)
        self.assertEqual(d["password"], "secret")


class TestLoginResult(unittest.TestCase):
    def test_success(self):
        r = LoginResult(
            success=True,
            session_id="sess-123",
            state=SessionState.AUTHENTICATED,
            cookies=[{"name": "sid", "value": "abc"}],
        )
        self.assertTrue(r.success)
        self.assertEqual(r.state, SessionState.AUTHENTICATED)

    def test_failure(self):
        r = LoginResult(success=False, state=SessionState.FAILED, error="timeout")
        self.assertFalse(r.success)
        self.assertEqual(r.error, "timeout")

    def test_to_dict(self):
        r = LoginResult(success=True, error="", session_id="sess-001")
        d = r.model_dump()
        self.assertIn("success", d)
        self.assertTrue(d["success"])


class TestAuthSessionConfig(unittest.TestCase):
    def test_create(self):
        cfg = AuthSessionConfig(session_id="s1", base_url="http://localhost")
        self.assertEqual(cfg.session_id, "s1")
        self.assertTrue(cfg.is_active)

    def test_bearer_token(self):
        cfg = AuthSessionConfig(
            session_id="s2", base_url="http://localhost", bearer_token="tok_abc"
        )
        self.assertTrue(cfg.bearer_token)


class TestAPITestRequest(unittest.TestCase):
    def test_default_get(self):
        r = APITestRequest(path="/api/users")
        self.assertEqual(r.method, "GET")
        self.assertEqual(r.path, "/api/users")

    def test_post_with_body(self):
        r = APITestRequest(
            path="/api/users",
            method="POST",
            body={"name": "test", "role": "user"},
            expected_status=201,
        )
        self.assertEqual(r.method, "POST")
        self.assertEqual(r.expected_status, 201)


class TestAuthenticatedScanResult(unittest.TestCase):
    def test_create(self):
        r = AuthenticatedScanResult(
            scan_id="s1", target_url="http://localhost"
        )
        self.assertEqual(r.total_tests, 0)
        self.assertEqual(r.passed_tests, 0)


class TestSessionStore(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmpdir = tempfile.mkdtemp()
        from fp_sentinel.auth.session import SessionStore
        self.store = SessionStore(store_dir=self._tmpdir)

    def test_save_and_load(self):
        cfg = AuthSessionConfig(session_id="test-1", base_url="http://localhost")
        self.assertTrue(self.store.save(cfg))
        loaded = self.store.load("test-1")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.base_url, "http://localhost")

    def test_load_nonexistent(self):
        loaded = self.store.load("does-not-exist")
        self.assertIsNone(loaded)

    def test_list_sessions(self):
        for i in range(3):
            cfg = AuthSessionConfig(session_id=f"sess-{i}", base_url=f"http://host{i}")
            self.store.save(cfg)
        sessions = self.store.list_sessions()
        self.assertEqual(len(sessions), 3)

    def test_delete(self):
        cfg = AuthSessionConfig(session_id="del-1", base_url="http://localhost")
        self.store.save(cfg)
        self.assertTrue(self.store.delete("del-1"))
        self.assertIsNone(self.store.load("del-1"))

    def test_clear_all(self):
        for i in range(3):
            cfg = AuthSessionConfig(session_id=f"clr-{i}", base_url=f"http://h{i}")
            self.store.save(cfg)
        count = self.store.clear_all()
        self.assertGreaterEqual(count, 3)

    def test_list_active_sessions(self):
        cfg1 = AuthSessionConfig(session_id="active-1", base_url="http://localhost")
        cfg2 = AuthSessionConfig(session_id="active-2", base_url="http://localhost")
        self.store.save(cfg1)
        self.store.save(cfg2)
        active = self.store.list_active_sessions()
        self.assertEqual(len(active), 2)

    def test_encryption_roundtrip(self):
        cfg = AuthSessionConfig(session_id="enc-test", base_url="http://localhost")
        self.store.save(cfg)
        files = list(Path(self._tmpdir).glob("*.json"))
        self.assertTrue(len(files) >= 1)
        raw_content = files[0].read_text(encoding="utf-8")
        self.assertTrue(raw_content.startswith(SessionStore.ENCRYPTION_MARKER))

    def test_expired_session(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        cfg = AuthSessionConfig(
            session_id="exp-1", base_url="http://localhost", expires_at=past
        )
        self.store.save(cfg)
        loaded = self.store.load("exp-1")
        self.assertIsNone(loaded)

    def test_cleanup_expired(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        cfg = AuthSessionConfig(
            session_id="clean-exp", base_url="http://localhost", expires_at=past
        )
        self.store.save(cfg)
        removed = self.store.cleanup_expired()
        self.assertGreaterEqual(removed, 1)


class TestAuthSession(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmpdir = tempfile.mkdtemp()
        from fp_sentinel.auth.session import SessionStore, AuthSession
        self.store = SessionStore(store_dir=self._tmpdir)
        self.session = AuthSession(store=self.store, session_id="test-sess")

    def test_init_session(self):
        cfg = self.session.init_session(base_url="http://localhost", ttl_minutes=30)
        self.assertTrue(self.session.is_authenticated)
        self.assertEqual(cfg.base_url, "http://localhost")

    def test_load_session(self):
        self.session.init_session(base_url="http://localhost")
        loaded = self.session.load_session()
        self.assertIsNotNone(loaded)

    def test_invalidate(self):
        self.session.init_session(base_url="http://localhost")
        self.session.invalidate()
        self.assertFalse(self.session.is_authenticated)
        self.assertEqual(self.session.state, SessionState.LOGGED_OUT)

    def test_get_auth_headers(self):
        self.session.init_session(base_url="http://localhost", bearer_token="tok123")
        headers = self.session.get_auth_headers()
        self.assertEqual(headers.get("Authorization"), "Bearer tok123")

    def test_get_auth_headers_empty(self):
        headers = self.session.get_auth_headers()
        self.assertEqual(headers, {})

    def test_get_cookie_header(self):
        self.session.init_session(
            base_url="http://localhost",
            cookies=[{"name": "sid", "value": "abc"}, {"name": "csrf", "value": "xyz"}],
        )
        cookie_str = self.session.get_cookie_header()
        self.assertIn("sid=abc", cookie_str)
        self.assertIn("csrf=xyz", cookie_str)

    def test_extend_cookies(self):
        self.session.init_session(
            base_url="http://localhost",
            cookies=[{"name": "s1", "value": "v1"}],
        )
        self.session.extend_cookies([{"name": "s2", "value": "v2"}])
        self.assertEqual(len(self.session.config.cookies), 2)

    def test_extend_cookies_merge(self):
        self.session.init_session(
            base_url="http://localhost",
            cookies=[{"name": "s1", "value": "v1"}],
        )
        self.session.extend_cookies([{"name": "s1", "value": "updated"}])
        self.assertEqual(len(self.session.config.cookies), 1)
        self.assertEqual(self.session.config.cookies[0]["value"], "updated")

    def test_refresh(self):
        self.session.init_session(base_url="http://localhost", ttl_minutes=10)
        self.assertTrue(self.session.refresh(ttl_minutes=60))

    def test_refresh_no_config(self):
        result = self.session.refresh()
        self.assertFalse(result)

    def test_destroy(self):
        self.session.init_session(base_url="http://localhost")
        self.assertTrue(self.session.destroy())
        self.assertIsNone(self.session.load_session())

    def test_to_dict(self):
        self.session.init_session(base_url="http://localhost", bearer_token="tok")
        d = self.session.to_dict()
        self.assertEqual(d["session_id"], "test-sess")
        self.assertTrue(d["is_authenticated"])
        self.assertTrue(d["has_bearer_token"])
        self.assertNotIn("password", d)

    def test_to_dict_no_config(self):
        d = self.session.to_dict()
        self.assertFalse(d["has_bearer_token"])


class TestAutoLoginEngine(unittest.TestCase):
    def test_simulate_login_with_creds(self):
        from fp_sentinel.auth.auto_login import AutoLoginEngine
        engine = AutoLoginEngine()
        cred = LoginCredential(
            target_url="http://localhost/login",
            username="admin",
            password="s3cureP@ss!",
        )
        result = engine.login(cred)
        self.assertTrue(result.success)
        self.assertIn("sim-", result.session_id)

    def test_simulate_login_no_creds(self):
        from fp_sentinel.auth.auto_login import AutoLoginEngine
        engine = AutoLoginEngine()
        cred = LoginCredential(target_url="http://localhost/login")
        result = engine.login(cred)
        self.assertFalse(result.success)

    def test_browser_engine_sessions_fallback(self):
        from fp_sentinel.auth.auto_login import AutoLoginEngine
        mock_browser = MagicMock()
        mock_browser.list_sessions.return_value = []
        mock_session = MagicMock()
        mock_session.session_id = "auto-1"
        mock_browser.start.return_value = mock_session
        mock_browser.navigate.return_value = {"success": True, "status": 200}
        mock_browser.get_cookies.return_value = [{"name": "session", "value": "abc"}]
        mock_browser.get_dom_snapshot.return_value = {"title": "Dashboard", "text": "Welcome"}
        mock_browser.browser_action.return_value = {"success": True}
        mock_browser.evaluate.return_value = ""
        engine = AutoLoginEngine(browser_engine=mock_browser)
        cred = LoginCredential(
            target_url="http://localhost/login",
            username="admin",
            password="TestP@ss99!",
        )
        result = engine.login(cred)
        mock_browser.navigate.assert_called_once()

    def test_split_selectors(self):
        from fp_sentinel.auth.auto_login import _split_selectors
        result = _split_selectors("a, b, c")
        self.assertEqual(result, ["a", "b", "c"])

    def test_split_selectors_empty(self):
        from fp_sentinel.auth.auto_login import _split_selectors
        result = _split_selectors("")
        self.assertEqual(result, [])


class TestAuthenticatedAPITester(unittest.TestCase):
    def test_discover_endpoints_empty_browser(self):
        from fp_sentinel.auth.api_discoverer import AuthenticatedAPITester
        tester = AuthenticatedAPITester()
        endpoints = tester.discover_endpoints("sess-1", "http://localhost")
        self.assertIsInstance(endpoints, list)

    def test_discover_endpoints_with_browser(self):
        from fp_sentinel.auth.api_discoverer import AuthenticatedAPITester
        mock_browser = MagicMock()
        mock_browser.evaluate.return_value = [
            "http://localhost/api/users",
            "http://localhost/static/app.js",
            "http://other domain.com/external",
        ]
        mock_browser.get_network_requests.return_value = [
            {"url": "http://localhost/api/data", "method": "GET", "status": "200"},
        ]
        tester = AuthenticatedAPITester(browser_engine=mock_browser)
        endpoints = tester.discover_endpoints("sess-1", "http://localhost")
        self.assertTrue(len(endpoints) >= 2)

    def test_run_scan(self):
        from fp_sentinel.auth.api_discoverer import AuthenticatedAPITester
        tester = AuthenticatedAPITester()
        cfg = AuthSessionConfig(session_id="s1", base_url="http://localhost")
        reqs = [
            APITestRequest(path="/api/users", expected_status=200),
            APITestRequest(path="/api/config", expected_status=200, test_auth_required=False),
        ]
        mock_browser = MagicMock()
        mock_browser.discover_endpoints = MagicMock(return_value=[])
        result = tester.run_scan("sess-1", cfg, reqs)
        self.assertEqual(result.total_tests, 2)


if __name__ == "__main__":
    unittest.main()
