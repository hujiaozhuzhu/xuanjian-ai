"""
Harmless Auto-Verification Engine

Verifies vulnerability findings using harmless markers only.

Features:
- Static source-level sink tracing (default; no dependencies)
- DOM-based verification (opt-in via dom_verify=True, uses playwright/jsdom/python)
"""

from .verifier import (
    HarmlessVerifier,
    HarmlessVerifyResult,
    HarmlessVerifyStep,
    VerifyConfidence,
)
from .step_generator import (
    generate_reproducible_steps,
    build_verification_report,
)

# DOM verify (optional; may pull in executor deps)
try:
    from ..dom_verify import (  # noqa: F401
        SafeJsExecutor,
        VerifyBackend,
        ExecutionResult,
        MarkerHit,
    )
    _DOM_VERIFY_AVAILABLE = True
except ImportError:
    _DOM_VERIFY_AVAILABLE = False

__all__ = [
    "HarmlessVerifier",
    "HarmlessVerifyResult",
    "HarmlessVerifyStep",
    "VerifyConfidence",
    "generate_reproducible_steps",
    "build_verification_report",
]

if _DOM_VERIFY_AVAILABLE:
    __all__ += ["SafeJsExecutor", "VerifyBackend", "ExecutionResult", "MarkerHit"]
