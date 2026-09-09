"""
Authentication Module Data Models

Defines all data structures for identity authentication coverage:
login credentials, session state, API test requests/results.

Security: S1/S2/S4 compliant - credentials never leave local store.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class SessionState(str, Enum):
    """Authentication session lifecycle states."""
    INITIAL = "initial"
    LOGIN_IN_PROGRESS = "login_in_progress"
    AUTHENTICATED = "authenticated"
    EXPIRED = "expired"
    FAILED = "failed"
    LOGGED_OUT = "logged_out"


class LoginFormStrategy(str, Enum):
    """Supported login form detection strategies."""
    AUTO = "auto"
    USERNAME_PASSWORD = "username_password"
    EMAIL_PASSWORD = "email_password"
    TOKEN_BEARER = "token_bearer"
    MULTI_STEP = "multi_step"
    CUSTOM_SELECTORS = "custom_selectors"


class LoginCredential(BaseModel):
    """Login credential configuration."""
    model_config = {"extra": "forbid"}

    target_url: str = Field(..., description="Login page URL (must be authorized scope)")
    username: str = Field("", description="Username or email")
    password: str = Field(default="", description="Password (never serialized to logs)")
    username_selector: str = Field(
        "input[name='username'], input[name='email'], input[type='email'], #username, #email",
        description="CSS selector for username field")
    password_selector: str = Field(
        "input[name='password'], input[type='password'], #password",
        description="CSS selector for password field")
    submit_selector: str = Field(
        "button[type='submit'], input[type='submit'], #login-btn, .login-btn",
        description="CSS selector for submit button")
    success_indicator: str = Field("",
                                   description="CSS selector/text indicating successful login")
    failure_indicator: str = Field("",
                                   description="CSS selector/text indicating failed login")
    strategy: LoginFormStrategy = Field(default=LoginFormStrategy.AUTO,
                                        description="Login strategy to use")
    extra_fields: Dict[str, str] = Field(default_factory=dict,
                                        description="Extra form fields")
    headers: Dict[str, str] = Field(default_factory=dict,
                                   description="Additional HTTP headers")
    custom_steps: List[Dict[str, Any]] = Field(default_factory=list,
                                               description="Multi-step flow definitions")
    timeout_ms: int = Field(15000, ge=1000, le=120000,
                            description="Login timeout in ms")
    max_retries: int = Field(3, ge=0, le=10, description="Max retry attempts")


class LoginResult(BaseModel):
    """Result of a login attempt."""
    model_config = {"extra": "forbid"}

    success: bool = Field(..., description="Whether login succeeded")
    session_id: str = Field("", description="Session identifier if successful")
    state: SessionState = Field(default=SessionState.INITIAL)
    message: str = Field("", description="Human-readable result message")
    cookies: List[Dict[str, Any]] = Field(default_factory=list,
                                         description="Session cookies captured")
    tokens: Dict[str, str] = Field(default_factory=dict,
                                  description="Bearer/JWT tokens extracted")
    redirect_url: str = Field("", description="URL after login redirect")
    response_status: int = Field(0, description="HTTP status of login request")
    duration_ms: float = Field(0.0, ge=0, description="Login duration in ms")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attempt: int = Field(1, ge=1, description="Attempt number")
    error: str = Field("", description="Error message if failed")


class AuthSessionConfig(BaseModel):
    """Configuration for an authenticated browser session."""
    model_config = {"extra": "forbid"}

    session_id: str = Field(..., description="Session identifier")
    base_url: str = Field("", description="Base URL for API calls")
    cookies: List[Dict[str, Any]] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    bearer_token: str = Field(default="", description="Bearer str for Authorization header")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: Optional[str] = Field(None, description="Session expiry timestamp")
    is_active: bool = Field(True, description="Whether session is currently active")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class APITestRequest(BaseModel):
    """A single API test request within an authenticated session."""
    model_config = {"extra": "forbid"}

    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"] = Field(default="GET")
    path: str = Field(..., description="API path relative to base_url")
    params: Dict[str, Any] = Field(default_factory=dict, description="Query parameters")
    body: Optional[Dict[str, Any]] = Field(None, description="Request body (JSON)")
    headers: Dict[str, str] = Field(default_factory=dict,
                                   description="Extra headers for this request")
    expected_status: int = Field(200, description="Expected HTTP status code")
    description: str = Field("", description="Human-readable test description")
    test_auth_required: bool = Field(True,
                                     description="Whether to test auth requirement")


class APITestResult(BaseModel):
    """Result of a single API test."""
    model_config = {"extra": "forbid"}

    request: APITestRequest = Field(..., description="The request that was made")
    status_code: int = Field(0, description="Actual HTTP status code")
    response_body: Any = Field(None, description="Parsed response body")
    response_headers: Dict[str, str] = Field(default_factory=dict)
    duration_ms: float = Field(0.0)
    success: bool = Field(False, description="Whether test passed")
    auth_enforced: bool = Field(True,
                                description="Whether auth is enforced")
    findings: List[str] = Field(default_factory=list,
                                description="Security findings from this test")
    error: str = Field("", description="Error if request failed")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AuthenticatedScanResult(BaseModel):
    """Complete result of an authenticated scan session."""
    model_config = {"extra": "forbid"}

    scan_id: str = Field(..., description="Unique scan session ID")
    target_url: str = Field(..., description="Target base URL")
    login_result: Optional[LoginResult] = Field(None)
    api_results: List[APITestResult] = Field(default_factory=list)
    endpoints_discovered: List[str] = Field(default_factory=list,
                                           description="URLs discovered post-login")
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = Field(None)
    total_tests: int = Field(0)
    passed_tests: int = Field(0)
    failed_tests: int = Field(0)
    auth_bypass_findings: List[str] = Field(default_factory=list)
