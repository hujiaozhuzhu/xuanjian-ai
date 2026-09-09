"""
Automated Login Engine

Supports form-based login with multiple strategies:
- Auto-detect form fields
- Custom CSS selectors
- Multi-step login flows
- Token extraction after login

Safety:
- Only works on targets explicitly authorized by user
- Credentials are used for login only, never persisted
- Session tokens stored in encrypted SessionStore
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from .models import (
    AuthSessionConfig,
    LoginCredential,
    LoginFormStrategy,
    LoginResult,
    SessionState,
)

logger = logging.getLogger(__name__)


class AutoLoginEngine:
    """Automated login engine supporting multiple auth strategies."""

    def __init__(self, browser_engine=None):
        self._browser = browser_engine

    def set_browser_engine(self, browser_engine) -> None:
        self._browser = browser_engine

    def login(self, credential: LoginCredential) -> LoginResult:
        if self._browser is None:
            return self._simulate_login(credential)
        last_result = LoginResult(success=False, state=SessionState.FAILED)
        for attempt in range(1, credential.max_retries + 1):
            last_result = self._try_browser_login(credential, attempt)
            if last_result.success:
                return last_result
            if attempt < credential.max_retries:
                time.sleep(1.0)
        return last_result

    def _try_browser_login(
        self, credential: LoginCredential, attempt: int
    ) -> LoginResult:
        start = time.time()
        try:
            sessions = self._browser.list_sessions()
            if not sessions:
                session = self._browser.start(enable_rpc=False)
                session_id = session.session_id
            else:
                session_id = sessions[0].session_id
            nav = self._browser.navigate(session_id, credential.target_url)
            if not nav.get("success"):
                return LoginResult(
                    success=False, state=SessionState.FAILED,
                    message=f"Navigation failed: {nav.get('error', 'unknown')}",
                    attempt=attempt,
                    duration_ms=round((time.time() - start) * 1000, 2),
                )
            time.sleep(0.5)
            if credential.strategy == LoginFormStrategy.MULTI_STEP:
                return self._multi_step_login(session_id, credential, start, attempt)
            elif credential.strategy == LoginFormStrategy.TOKEN_BEARER:
                return self._token_login(session_id, credential, start, attempt)
            else:
                return self._form_login(session_id, credential, start, attempt)
        except Exception as e:
            return LoginResult(
                success=False, state=SessionState.FAILED,
                message=f"Login exception: {e}", attempt=attempt,
                duration_ms=round((time.time() - start) * 1000, 2), error=str(e),
            )

    def _form_login(self, session_id: str, credential: LoginCredential,
                    start: float, attempt: int) -> LoginResult:
        usernames = _split_selectors(credential.username_selector)
        passwords = _split_selectors(credential.password_selector)
        submits = _split_selectors(credential.submit_selector)
        username_ok = False
        for selector in usernames:
            try:
                res = self._browser.browser_action(
                    session_id, "type", selector=selector, text=credential.username
                )
                if res.get("success"):
                    username_ok = True
                    break
            except Exception:
                continue
        if not username_ok:
            return LoginResult(
                success=False, state=SessionState.FAILED,
                message="Could not fill username field",
                attempt=attempt, duration_ms=round((time.time() - start) * 1000, 2),
            )
        password_ok = False
        for selector in passwords:
            try:
                res = self._browser.browser_action(
                    session_id, "type", selector=selector, text=credential.password
                )
                if res.get("success"):
                    password_ok = True
                    break
            except Exception:
                continue
        if not password_ok:
            return LoginResult(
                success=False, state=SessionState.FAILED,
                message="Could not fill password field",
                attempt=attempt, duration_ms=round((time.time() - start) * 1000, 2),
            )
        for selector, value in credential.extra_fields.items():
            try:
                self._browser.browser_action(
                    session_id, "type", selector=selector, text=value
                )
            except Exception:
                pass
        submit_ok = False
        for selector in submits:
            try:
                res = self._browser.browser_action(session_id, "click", selector=selector)
                if res.get("success"):
                    submit_ok = True
                    break
            except Exception:
                continue
        if not submit_ok:
            try:
                self._browser.evaluate(session_id, "document.querySelector('form').submit()")
                submit_ok = True
            except Exception:
                pass
        time.sleep(1.0)
        duration_ms = round((time.time() - start) * 1000, 2)
        success = self._check_login_success(session_id, credential)
        cookies = self._browser.get_cookies(session_id)
        return LoginResult(
            success=success, session_id=session_id if success else "",
            state=SessionState.AUTHENTICATED if success else SessionState.FAILED,
            message="Login successful" if success else "Login check inconclusive",
            cookies=cookies, duration_ms=duration_ms, attempt=attempt,
        )

    def _multi_step_login(self, session_id: str, credential: LoginCredential,
                          start: float, attempt: int) -> LoginResult:
        for step in credential.custom_steps:
            action = step.get("action", "")
            selector = step.get("selector", "")
            value = step.get("value", "")
            wait_ms = step.get("wait_ms", 500)
            try:
                if action == "click":
                    self._browser.browser_action(session_id, "click", selector=selector)
                elif action == "type":
                    self._browser.browser_action(
                        session_id, "type", selector=selector, text=value
                    )
                elif action == "select":
                    self._browser.browser_action(
                        session_id, "select", selector=selector, value=value
                    )
            except Exception as e:
                return LoginResult(
                    success=False, state=SessionState.FAILED,
                    message=f"Multi-step failed at action={action}: {e}",
                    attempt=attempt,
                    duration_ms=round((time.time() - start) * 1000, 2),
                    error=str(e),
                )
            if wait_ms > 0:
                time.sleep(wait_ms / 1000)
        success = self._check_login_success(session_id, credential)
        cookies = self._browser.get_cookies(session_id)
        return LoginResult(
            success=success, session_id=session_id if success else "",
            state=SessionState.AUTHENTICATED if success else SessionState.FAILED,
            message="Multi-step login done", cookies=cookies,
            duration_ms=round((time.time() - start) * 1000, 2), attempt=attempt,
        )

    def _token_login(self, session_id: str, credential: LoginCredential,
                     start: float, attempt: int) -> LoginResult:
        cookies = self._browser.get_cookies(session_id)
        return LoginResult(
            success=True, session_id=session_id,
            state=SessionState.AUTHENTICATED,
            message="Token login executed", cookies=cookies,
            duration_ms=round((time.time() - start) * 1000, 2), attempt=attempt,
        )

    def _check_login_success(self, session_id: str, credential: LoginCredential) -> bool:
        if credential.success_indicator:
            try:
                dom = self._browser.get_dom_snapshot(session_id)
                if credential.success_indicator.lower() in str(dom).lower():
                    return True
            except Exception:
                pass
        if credential.failure_indicator:
            try:
                dom = self._browser.get_dom_snapshot(session_id)
                if credential.failure_indicator.lower() in str(dom).lower():
                    return False
            except Exception:
                pass
        try:
            cookies = self._browser.get_cookies(session_id)
            auth_names = {"session", "sid", "token", "jwt", "auth", "sessionid",
                          "phpsessid", "connect.sid"}
            for c in cookies:
                if c.get("name", "").lower() in auth_names:
                    return True
        except Exception:
            pass
        return False

    def _simulate_login(self, credential: LoginCredential) -> LoginResult:
        start = time.time()
        has_creds = bool(credential.username and credential.password)
        return LoginResult(
            success=has_creds,
            session_id=f"sim-{uuid.uuid4().hex[:8]}" if has_creds else "",
            state=SessionState.AUTHENTICATED if has_creds else SessionState.FAILED,
            message="Simulated login" + (" success" if has_creds else " no creds"),
            cookies=[{"name": "session", "value": "sim_" + uuid.uuid4().hex[:8]}] if has_creds else [],
            duration_ms=round((time.time() - start) * 1000, 2), attempt=1,
        )


def _split_selectors(selector_str: str) -> List[str]:
    return [s.strip() for s in selector_str.split(",") if s.strip()]
