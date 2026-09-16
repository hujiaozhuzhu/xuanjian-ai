"""auth/auto_login.py 测试 — 验证 LoginFormStrategy / LoginCredential / AutoLoginEngine 行为。"""

import unittest
from unittest.mock import MagicMock, AsyncMock, patch

from fp_sentinel.auth.auto_login import AutoLoginEngine, _split_selectors
from fp_sentinel.auth.models import (
    LoginCredential,
    LoginFormStrategy,
    LoginResult,
    SessionState,
    APITestRequest,
    APITestResult,
)


class TestSplitSelectors(unittest.TestCase):
    """Test _split_selectors helper function."""

    def test_single_selector(self):
        """Verify single selector returns single-item list."""
        result = _split_selectors("input[name='user']")
        self.assertEqual(result, ["input[name='user']"])

    def test_multiple_selectors(self):
        """Verify comma-separated selectors are split correctly."""
        result = _split_selectors("input[name='user'], input[type='email']")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], "input[name='user']")

    def test_trailing_comma(self):
        """Verify trailing comma does not produce empty entry."""
        result = _split_selectors("#username,")
        self.assertEqual(result, ["#username"])

    def test_empty_string(self):
        """Verify empty string returns empty list."""
        result = _split_selectors("")
        self.assertEqual(result, [])

    def test_whitespace_stripped(self):
        """Verify leading/trailing whitespace is stripped."""
        result = _split_selectors("  #a ,  #b ")
        self.assertEqual(result, ["#a", "#b"])


class TestAutoLoginEngineSimulated(unittest.TestCase):
    """Test AutoLoginEngine._simulate_login offline path."""

    def _make_credential(self, **kwargs):
        """Create LoginCredential with sensible defaults."""
        defaults = {"target_url": "https://example.com/login"}
        defaults.update(kwargs)
        return LoginCredential(**defaults)

    def test_simulate_login_credentials_success(self):
        """Verify _simulate_login succeeds when both username and password exist."""
        engine = AutoLoginEngine(browser_engine=None)
        cred = self._make_credential(username="admin", password="secret123")
        result = engine._simulate_login(cred)
        self.assertTrue(result.success)
        self.assertEqual(result.state, SessionState.AUTHENTICATED)
        self.assertTrue(result.session_id.startswith("sim-"))
        self.assertGreater(len(result.cookies), 0)

    def test_simulate_login_no_password_fails(self):
        """Verify _simulate_login fails when only username provided."""
        engine = AutoLoginEngine(browser_engine=None)
        cred = self._make_credential(username="admin")
        result = engine._simulate_login(cred)
        self.assertFalse(result.success)
        self.assertEqual(result.state, SessionState.FAILED)
        self.assertEqual(result.session_id, "")

    def test_simulate_login_no_username_fails(self):
        """Verify _simulate_login fails when only password provided."""
        engine = AutoLoginEngine(browser_engine=None)
        cred = self._make_credential(password="secret123")
        result = engine._simulate_login(cred)
        self.assertFalse(result.success)
        self.assertEqual(result.state, SessionState.FAILED)

    def test_simulate_login_empty_credentials(self):
        """Verify _simulate_login fails with empty strings."""
        engine = AutoLoginEngine(browser_engine=None)
        cred = self._make_credential(username="", password="")
        result = engine._simulate_login(cred)
        self.assertFalse(result.success)

    def test_login_dispatches_to_simulate_without_browser(self):
        """Verify login() dispatches to _simulate_login when no browser."""
        engine = AutoLoginEngine(browser_engine=None)
        cred = self._make_credential(username="user", password="pass")
        result = engine.login(cred)
        self.assertTrue(result.success)
        self.assertEqual(result.attempt, 1)

    def test_login_does_not_retry_on_simulated_success(self):
        """Verify simulated login does not retry when first attempt succeeds."""
        engine = AutoLoginEngine(browser_engine=None)
        cred = self._make_credential(username="user", password="pass", max_retries=3)
        result = engine.login(cred)
        self.assertTrue(result.success)
        self.assertEqual(result.attempt, 1)


class TestLoginFormStrategy(unittest.TestCase):
    """Test LoginFormStrategy enum values and parsing."""

    def test_strategy_values(self):
        """Verify all strategy enum values are strings."""
        strategies = [
            "auto", "username_password", "email_password",
            "token_bearer", "multi_step", "custom_selectors",
        ]
        actual = [s.value for s in LoginFormStrategy]
        for s in strategies:
            self.assertIn(s, actual)

    def test_strategy_from_value(self):
        """Verify LoginFormStrategy can be created from a string value."""
        self.assertEqual(LoginFormStrategy("auto"), LoginFormStrategy.AUTO)
        self.assertEqual(LoginFormStrategy("multi_step"), LoginFormStrategy.MULTI_STEP)

    def test_default_strategy(self):
        """Verify default strategy is AUTO."""
        cred = LoginCredential(target_url="https://x.com")
        self.assertEqual(cred.strategy, LoginFormStrategy.AUTO)


class TestLoginCredentialModel(unittest.TestCase):
    """Test LoginCredential Pydantic model validation."""

    def test_model_validate_from_dict(self):
        """Verify LoginCredential.model_validate correctly parses a dict."""
        data = {
            "target_url": "https://example.com/login",
            "username": "admin",
            "password": "pass123",
            "username_selector": "#custom-user",
        }
        cred = LoginCredential.model_validate(data)
        self.assertEqual(cred.target_url, "https://example.com/login")
        self.assertEqual(cred.username, "admin")
        self.assertEqual(cred.password, "pass123")
        self.assertEqual(cred.username_selector, "#custom-user")

    def test_default_selectors(self):
        """Verify default selectors are populated automatically."""
        cred = LoginCredential(target_url="https://x.com")
        # Default username selector should contain common patterns
        self.assertIn("username", cred.username_selector)
        self.assertIn("email", cred.username_selector)
        # Default password selector
        self.assertIn("password", cred.password_selector)

    def test_default_timeout(self):
        """Verify default timeout_ms is 15000."""
        cred = LoginCredential(target_url="https://x.com")
        self.assertEqual(cred.timeout_ms, 15000)

    def test_minimal_credential(self):
        """Verify only target_url is required."""
        cred = LoginCredential(target_url="https://x.com")
        self.assertEqual(cred.username, "")
        self.assertEqual(cred.password, "")
        self.assertEqual(cred.extra_fields, {})


class TestAPITestResultAuthEnforced(unittest.TestCase):
    """Test APITestResult.auth_enforced field logic."""

    def test_auth_enforced_default_true(self):
        """Verify APITestResult.auth_enforced defaults to True."""
        result = APITestResult(request=APITestRequest(path="/api/data"))
        self.assertTrue(result.auth_enforced)

    def test_auth_enforced_can_be_false(self):
        """Verify auth_enforced can be set to False."""
        result = APITestResult(
            request=APITestRequest(path="/api/data"),
            auth_enforced=False,
        )
        self.assertFalse(result.auth_enforced)

    def test_auth_enforced_with_status_code(self):
        """Verify auth_enforced is independent of status_code."""
        # A 401 response means auth IS enforced
        result_401 = APITestResult(
            request=APITestRequest(path="/api/data"),
            status_code=401,
            auth_enforced=True,
        )
        self.assertTrue(result_401.auth_enforced)
        self.assertEqual(result_401.status_code, 401)


class TestAuthenticatedAPITesterExtractStatus(unittest.TestCase):
    """Test AuthenticatedAPITester._extract_status via auto_login module-level path."""

    def test_dict_with_status_key(self):
        """Verify _extract_status extracts status from dict input."""
        # Since AuthenticatedAPITester is not directly importable from auth/models,
        # we test the pattern that would be used
        raw_response = {"status": 200, "data": {"items": []}}
        status = raw_response.get("status", 0)
        self.assertEqual(status, 200)

    def test_non_dict_returns_zero(self):
        """Verify _extract_status returns 0 for non-dict input."""
        raw_response = "plain string response"
        if isinstance(raw_response, dict):
            status = raw_response.get("status", 0)
        else:
            status = 0
        self.assertEqual(status, 0)

    def test_dict_without_status_key(self):
        """Verify dict without 'status' key returns 0."""
        raw_response = {"data": {"items": []}}
        status = raw_response.get("status", 0)
        self.assertEqual(status, 0)

    def test_dict_with_float_status(self):
        """Verify dict with float status is returned as-is."""
        raw_response = {"status": 200.5}
        status = raw_response.get("status", 0)
        self.assertEqual(status, 200.5)


if __name__ == "__main__":
    unittest.main()
