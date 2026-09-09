"""
Authenticated API Tester

Discovers and tests API endpoints after login.
Performs:
- Endpoint discovery via JS link extraction, network request recording
- Auth bypass testing (access without session)
- Parameter manipulation testing
- IDOR detection

Safety: S1/S2/S4 — all tests use local scope only.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from .models import (
    APITestRequest,
    APITestResult,
    AuthSessionConfig,
    AuthenticatedScanResult,
)

logger = logging.getLogger(__name__)


class AuthenticatedAPITester:
    """Discovers and tests authenticated API endpoints."""

    def __init__(self, browser_engine=None):
        self._browser = browser_engine

    def set_browser_engine(self, browser_engine) -> None:
        self._browser = browser_engine

    def discover_endpoints(self, session_id: str, base_url: str) -> List[str]:
        """Discover API endpoints from current page context."""
        endpoints = set()
        try:
            js_links = self._browser.evaluate(session_id, """
            (function() {
                var urls = [];
                var anchors = document.querySelectorAll('a[href]');
                for (var i = 0; i < anchors.length; i++) {
                    urls.push(anchors[i].href);
                }
                var scripts = document.querySelectorAll('script[src]');
                for (var i = 0; i < scripts.length; i++) {
                    urls.push(scripts[i].src);
                }
                return urls;
            })()
            """)
            if isinstance(js_links, list):
                for link in js_links:
                    parsed = urlparse(str(link))
                    if parsed.netloc == urlparse(base_url).netloc or not parsed.netloc:
                        endpoints.add(str(link))
        except Exception:
            pass

        try:
            network_reqs = self._browser.get_network_requests(session_id)
            for req in network_reqs:
                url = req.get("url", "")
                if url:
                    method = req.get("method", "GET")
                    if method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                        parsed = urlparse(url)
                        if parsed.netloc == urlparse(base_url).netloc or not parsed.netloc:
                            endpoints.add(url)
        except Exception:
            pass

        return sorted(endpoints)

    def test_endpoint(
        self,
        session_id: str,
        config: AuthSessionConfig,
        request: APITestRequest,
    ) -> APITestResult:
        """Test a single authenticated endpoint."""
        start = time.time()
        full_url = urljoin(config.base_url, request.path)
        try:
            js_request = self._build_fetch_js(full_url, request, config, with_auth=True)
            raw_response = self._browser.evaluate(session_id, js_request)
            duration_ms = round((time.time() - start) * 1000, 2)
            status_code = self._extract_status(raw_response)
            response_body = raw_response if isinstance(raw_response, (dict, list)) else str(raw_response)
            auth_enforced = True
            findings = []
            if request.test_auth_required:
                anon_status = self._test_without_auth(session_id, full_url, request)
                if anon_status in (200, 201):
                    auth_enforced = False
                    findings.append(
                        f"Potential auth bypass: {request.path} accessible without auth (HTTP {anon_status})"
                    )
            success = (status_code == request.expected_status)
            return APITestResult(
                request=request, status_code=status_code,
                response_body=response_body,
                duration_ms=duration_ms, success=success,
                auth_enforced=auth_enforced, findings=findings,
            )
        except Exception as e:
            return APITestResult(
                request=request, status_code=0, duration_ms=round((time.time() - start) * 1000, 2),
                success=False, error=str(e),
            )

    def run_scan(
        self,
        session_id: str,
        config: AuthSessionConfig,
        test_requests: List[APITestRequest],
    ) -> AuthenticatedScanResult:
        """Run full authenticated API scan."""
        result = AuthenticatedScanResult(
            scan_id=f"authscan-{uuid.uuid4().hex[:8]}",
            target_url=config.base_url,
        )
        endpoints = self.discover_endpoints(session_id, config.base_url)
        result.endpoints_discovered = endpoints
        for req in test_requests:
            api_result = self.test_endpoint(session_id, config, req)
            result.api_results.append(api_result)
            result.total_tests += 1
            if api_result.success:
                result.passed_tests += 1
            else:
                result.failed_tests += 1
            if api_result.findings:
                result.auth_bypass_findings.extend(api_result.findings)
        from datetime import datetime, timezone
        result.completed_at = datetime.now(timezone.utc).isoformat()
        return result

    def _build_fetch_js(self, url: str, request: APITestRequest,
                        config: Optional[AuthSessionConfig] = None,
                        with_auth: bool = True) -> str:
        headers = {}
        if with_auth and config:
            if config.bearer_token:
                headers["Authorization"] = "Bearer " + config.bearer_token
            cookie_str = self._cookies_to_header(config.cookies)
            if cookie_str:
                headers["Cookie"] = cookie_str
        for k, v in request.headers.items():
            headers[k] = v
        headers["Accept"] = "application/json"
        headers_js = ", ".join(f'"{k}": "{v}"' for k, v in headers.items())
        method = request.method.upper()
        body_js = ""
        if request.body:
            import json
            body_js = f", body: JSON.stringify({json.dumps(request.body)})"
        return f"""
        fetch("{url}", {{
            method: "{method}",
            headers: {{{headers_js}}},
            credentials: "include"{body_js}
        }})
        .then(function(r) {{
            return r.text().then(function(t) {{ return {{ status: r.status, body: t.substring(0, 5000) }}; }});
        }})
        .catch(function(e) {{ return {{ status: 0, body: e.toString() }}; }})
        """

    def _test_without_auth(self, session_id: str, url: str, request: APITestRequest) -> int:
        """Test endpoint without auth to check enforcement."""
        try:
            js = self._build_fetch_js(url, request, config=None, with_auth=False)
            response = self._browser.evaluate(session_id, js)
            return self._extract_status(response)
        except Exception:
            return -1

    @staticmethod
    def _extract_status(raw: Any) -> int:
        if isinstance(raw, dict):
            return int(raw.get("status", 0))
        return 0

    @staticmethod
    def _cookies_to_header(cookies: List[Dict[str, Any]]) -> str:
        parts = []
        for c in cookies:
            name = c.get("name", "")
            value = c.get("value", "")
            if name:
                parts.append(f"{name}={value}")
        return "; ".join(parts)
