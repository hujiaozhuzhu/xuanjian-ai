"""DOM-based harmless verification — executes JS payloads in isolated context and detects markers.

Backends (auto-selected):
1. PlaywrightBackend — real Chromium via Playwright (highest fidelity)
2. JSDomBackend — Node.js + jsdom (DOM simulation, no real rendering)
3. PythonJSBackend — pure-Python minimal JS interpreter (last resort; marker detection only)

All backends run inside an isolated context with NO network egress (requests are intercepted).
Marker scheme: `window.__fp_verify__['<vuln_type>'] = { fired: true, ts: <time> }`
"""

from .executor import (
    SafeJsExecutor,
    ExecutionResult,
    MarkerHit,
    VerifyBackend,
)

__all__ = [
    "SafeJsExecutor",
    "ExecutionResult",
    "MarkerHit",
    "VerifyBackend",
]
