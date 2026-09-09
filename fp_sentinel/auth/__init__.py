"""
玄鉴 v3.1 - Identity Authentication Coverage Module

Provides automated login, session persistence, and authenticated interface testing.

Security red lines:
- S1: All targets restricted to authorized test scope only
- S2: No modification of source files at the target
- S4: Credentials stored in encrypted local cache only, never exfiltrated
- Zero network leakage: session data stays on local machine

Submodules:
- session: Session persistence (save/load/clear, encrypted store)
- auto_login: Automated login engine (form-based, JSON-based, multi-step)
- api_discoverer: Discover and test authenticated interfaces
- models: Pydantic data models
"""

from .models import (
    LoginCredential,
    LoginResult,
    AuthSessionConfig,
    APITestResult,
    APITestRequest,
    SessionState,
    LoginFormStrategy,
    AuthenticatedScanResult,
)
from .session import SessionStore, AuthSession
from .auto_login import AutoLoginEngine
from .api_discoverer import AuthenticatedAPITester

__all__ = [
    # Models
    "LoginCredential",
    "LoginResult",
    "AuthSessionConfig",
    "APITestResult",
    "APITestRequest",
    "SessionState",
    "LoginFormStrategy",
    "AuthenticatedScanResult",
    # Core classes
    "SessionStore",
    "AuthSession",
    "AutoLoginEngine",
    "AuthenticatedAPITester",
]
