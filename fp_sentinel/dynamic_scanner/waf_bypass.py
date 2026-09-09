"""
WAF Bypass Testing Engine

Tests WAF/IDS bypass using 15 encoding/format techniques.
Only uses harmless marker payloads (fp_sentinel_verify).
Safety: S4 - payloads are markers only, not real attacks.
"""

from __future__ import annotations

import base64
import logging
import time
import urllib.parse
from typing import Dict, List, Optional

from .models import (
    BypassResult,
    BypassTechnique,
    DynamicScanConfig,
)

logger = logging.getLogger(__name__)

ALL_TECHNIQUES = list(BypassTechnique)


class WAFBypassTester:
    """Tests WAF rules with multiple bypass techniques."""

    def __init__(self, browser_engine=None):
        self._browser = browser_engine

    def set_browser_engine(self, browser_engine) -> None:
        self._browser = browser_engine

    def test_all_techniques(
        self, url: str, param: str = "q", config: Optional[DynamicScanConfig] = None,
    ) -> List[BypassResult]:
        """Run all configured bypass techniques against a target URL."""
        if config is None:
            config = DynamicScanConfig(target_url=url)
        results = []
        techniques = config.enabled_techniques[:config.max_waf_techniques]
        for technique in techniques:
            result = self._test_technique(url, param, technique, config.test_payload)
            results.append(result)
        return results

    def test_single_technique(
        self, url: str, param: str, technique: BypassTechnique, payload: str = "fp_sentinel_verify",
    ) -> BypassResult:
        """Test a single WAF bypass technique."""
        return self._test_technique(url, param, technique, payload)

    def _test_technique(
        self, url: str, param: str, technique: BypassTechnique, payload: str,
    ) -> BypassResult:
        start = time.time()
        encoded_payload = _encode_payload(payload, technique)
        try:
            if self._browser is not None:
                return self._browser_test(url, param, encoded_payload, technique, start)
            return self._simulated_test(url, param, encoded_payload, technique, start)
        except Exception as e:
            return BypassResult(
                technique=technique, payload=encoded_payload,
                target_url=url, blocked=True,
                duration_ms=round((time.time() - start) * 1000, 2),
                evidence=f"Error: {e}",
            )

    def _browser_test(
        self, url: str, param: str, encoded_payload: str,
        technique: BypassTechnique, start: float,
    ) -> BypassResult:
        separator = "&" if "?" in url else "?"
        full_url = f"{url}{separator}{param}={urllib.parse.quote(encoded_payload)}"
        try:
            sessions = self._browser.list_sessions()
            if not sessions:
                session = self._browser.start(enable_rpc=False)
                session_id = session.session_id
            else:
                session_id = sessions[0].session_id
            nav_result = self._browser.navigate(session_id, full_url)
            response_size = 0
            status_code = nav_result.get("status", 0) or 0
            try:
                snapshot = self._browser.get_page_snapshot(session_id)
                response_size = len(str(snapshot))
            except Exception:
                pass
            blocked = status_code in (403, 406, 444, 499, 501, 502, 503) or response_size < 50
            return BypassResult(
                technique=technique, payload=encoded_payload,
                target_url=url, status_code=status_code,
                response_size=response_size, blocked=blocked,
                duration_ms=round((time.time() - start) * 1000, 2),
                evidence=f"HTTP {status_code}, response_size={response_size}",
            )
        except Exception as e:
            return BypassResult(
                technique=technique, payload=encoded_payload,
                target_url=url, blocked=True,
                duration_ms=round((time.time() - start) * 1000, 2),
                evidence=f"Browser error: {e}",
            )

    def _simulated_test(
        self, url: str, param: str, encoded_payload: str,
        technique: BypassTechnique, start: float,
    ) -> BypassResult:
        time.sleep(0.01)
        blocked = technique in (BypassTechnique.NULL_BYTE, BypassTechnique.HEADER_INJECT)
        status_code = 403 if blocked else 200
        response_size = 0 if blocked else 1024
        return BypassResult(
            technique=technique, payload=encoded_payload,
            target_url=url, status_code=status_code,
            response_size=response_size, blocked=blocked,
            duration_ms=round((time.time() - start) * 1000, 2),
            evidence=f"Simulated: {'blocked' if blocked else 'passed'} via {technique.value}",
        )


def _encode_payload(payload: str, technique: BypassTechnique) -> str:
    """Encode a harmless payload using the specified technique."""
    if technique == BypassTechnique.URL_ENCODE:
        return urllib.parse.quote(payload)
    elif technique == BypassTechnique.DOUBLE_ENCODE:
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif technique == BypassTechnique.BASE64:
        return base64.b64encode(payload.encode()).decode()
    elif technique == BypassTechnique.HEX_ENCODE:
        return "%" + "%".join(f"{b:02x}" for b in payload.encode())
    elif technique == BypassTechnique.UNICODE_ESCAPE:
        return "".join(f"\\u{ord(c):04x}" if ord(c) < 128 else c for c in payload)
    elif technique == BypassTechnique.CASE_VARIATION:
        return "".join(
            c.upper() if i % 2 == 0 and c.isalpha() else c.lower() if c.isalpha() else c
            for i, c in enumerate(payload)
        )
    elif technique == BypassTechnique.WHITESPACE_INJECT:
        return " ".join(payload)
    elif technique == BypassTechnique.COMMENT_INJECT:
        chars = list(payload)
        mid = len(chars) // 2
        return "".join(chars[:mid]) + "/**/" + "".join(chars[mid:])
    elif technique == BypassTechnique.PARAM_POLLUTION:
        return f"{payload}&duplicate={payload}"
    elif technique == BypassTechnique.NULL_BYTE:
        return payload + "%00"
    else:
        return payload
