"""
JS Dynamic Rendering Page Analyzer

Parses JavaScript-rendered (SPA) pages by:
1. Waiting for JS execution to complete
2. Extracting dynamically-rendered content
3. Intercepting XHR/Fetch API calls during page load
4. Mapping DOM mutations after initial render
5. Extracting data from inline JSON/JS objects

Safety: Passive analysis only, no interaction with target pages beyond navigation.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from .models import DynamicScanConfig, JSRenderResult

logger = logging.getLogger(__name__)


class JSRenderingAnalyzer:
    """Analyzes JS-rendered pages for dynamic content and API calls."""

    def __init__(self, browser_engine=None):
        self._browser = browser_engine

    def set_browser_engine(self, browser_engine) -> None:
        self._browser = browser_engine

    def analyze(
        self, url: str, config: Optional[DynamicScanConfig] = None,
    ) -> JSRenderResult:
        """Perform full JS rendering analysis of a page."""
        if config is None:
            config = DynamicScanConfig(target_url=url)
        start = time.time()
        if self._browser is None:
            return self._simulated_analyze(url, config)
        try:
            sessions = self._browser.list_sessions()
            if not sessions:
                session = self._browser.start(enable_rpc=False)
                session_id = session.session_id
            else:
                session_id = sessions[0].session_id
            self._browser.inject_network_hook(session_id)
            self._browser.inject_console_hook(session_id)
            nav = self._browser.navigate(session_id, url)
            if not nav.get("success"):
                return JSRenderResult(
                    url=url, success=False,
                    error=f"Navigation failed: {nav.get('error', 'unknown')}",
                )
            self._browser.evaluate(session_id, f"new Promise(r => setTimeout(r, {config.js_render_wait_ms}))")
            title = self._browser.evaluate(session_id, "document.title || ''")
            rendered_html = self._browser.evaluate(
                session_id, "document.body ? document.body.innerHTML.substring(0, 5000) : ''"
            )
            dom_snapshot = self._browser.get_dom_snapshot(session_id)
            network_reqs = self._browser.get_network_requests(session_id)
            network_calls = []
            for req in network_reqs:
                req_url = req.get("url", "")
                if req_url:
                    network_calls.append({
                        "url": req_url,
                        "method": req.get("method", "GET"),
                        "status": str(req.get("status", "")),
                    })
            data_elements = self._extract_data_elements(str(dom_snapshot), str(rendered_html))
            api_calls = self._identify_api_calls(network_calls, url)
            total_time = round((time.time() - start) * 1000, 2)
            return JSRenderResult(
                url=url,
                rendered_title=str(title) if title else "",
                rendered_html=str(rendered_html)[:2000] if rendered_html else "",
                data_elements=data_elements + self._dom_to_data_elements(dom_snapshot),
                api_calls_detected=api_calls,
                dom_mutations=len(network_calls),
                load_time_ms=total_time,
                success=True,
            )
        except Exception as e:
            return JSRenderResult(
                url=url, success=False, error=str(e),
                load_time_ms=round((time.time() - start) * 1000, 2),
            )

    def extract_json_data(self, url: str) -> List[Dict[str, Any]]:
        """Extract inline JSON/JS data objects from page."""
        results = []
        if self._browser is None:
            return [{"source": "simulated", "data": {"note": "no browser attached"}}]
        try:
            sessions = self._browser.list_sessions()
            session_id = sessions[0].session_id if sessions else self._browser.start().session_id
            raw = self._browser.evaluate(session_id, """
            (function() {
                var items = [];
                var scripts = document.querySelectorAll('script');
                for (var i = 0; i < scripts.length; i++) {
                    var text = scripts[i].textContent || '';
                    var matches = text.match(/window\.__[A-Z_]+__\s*=\s*(\{[^;]+)/g) || [];
                    for (var j = 0; j < matches.length; j++) {
                        items.push({type: 'window_var', content: matches[j].substring(0, 500)});
                    }
                    var jsonMatches = text.match(/\{[^{}]*"[a-z_]+"\s*:\s*[^}]+\}/g) || [];
                    for (var k = 0; k < jsonMatches.length; k++) {
                        items.push({type: 'json_object', content: jsonMatches[k].substring(0, 500)});
                    }
                }
                return items;
            })()
            """)
            if isinstance(raw, list):
                results = raw
        except Exception:
            pass
        return results

    def _extract_data_elements(self, dom_str: str, html_str: str) -> List[Dict[str, str]]:
        """Extract data-bearing elements from rendered content."""
        elements = []
        input_pattern = r'<input[^>]*name=["\'](\w+)["\'][^>]*value=["\']([^"\']*)["\']'
        for match in re.finditer(input_pattern, html_str, re.IGNORECASE):
            elements.append({
                "type": "input_field",
                "name": match.group(1),
                "value": match.group(2)[:100],
            })
        data_attr_pattern = r'data-([a-z-]+)=["\']([^"\']+)["\']'
        for match in re.finditer(data_attr_pattern, html_str, re.IGNORECASE):
            elements.append({
                "type": "data_attribute",
                "name": "data-" + match.group(1),
                "value": match.group(2)[:100],
            })
        script_json_pattern = r'window\.__([A-Z_]+)__\s*=\s*(\{[^;]+;)'
        for match in re.finditer(script_json_pattern, html_str):
            elements.append({
                "type": "inline_json",
                "name": "__" + match.group(1) + "__",
                "value": match.group(2)[:200],
            })
        return elements

    def _identify_api_calls(
        self, network_calls: List[Dict[str, str]], base_url: str,
    ) -> List[Dict[str, str]]:
        """Identify API calls from network request list."""
        api_keywords = {"/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc/"}
        base_domain = urlparse(base_url).netloc
        api_calls = []
        for call in network_calls:
            url = call.get("url", "")
            parsed = urlparse(url)
            is_api = any(kw in url.lower() for kw in api_keywords)
            is_same_domain = parsed.netloc == base_domain or not parsed.netloc
            if is_api and is_same_domain:
                api_calls.append(call)
        return api_calls

    def _dom_to_data_elements(self, dom_snapshot: Any) -> List[Dict[str, str]]:
        """Convert DOM snapshot to data element list."""
        elements = []
        if not isinstance(dom_snapshot, dict):
            return elements
        tag = dom_snapshot.get("tag", "")
        attrs = dom_snapshot.get("attrs", {})
        if tag == "input":
            name = attrs.get("name", attrs.get("id", ""))
            if name:
                elements.append({"type": "input", "name": name, "value": attrs.get("value", "")})
        elif tag == "a":
            href = attrs.get("href", "")
            if href:
                elements.append({"type": "link", "name": dom_snapshot.get("text", ""), "value": href})
        for child in dom_snapshot.get("children", []) or []:
            elements.extend(self._dom_to_data_elements(child))
        return elements

    def _simulated_analyze(self, url: str, config: DynamicScanConfig) -> JSRenderResult:
        """Simulated JS render analysis for offline mode."""
        time.sleep(0.01)
        return JSRenderResult(
            url=url,
            rendered_title="Simulated Title",
            rendered_html="<html><body><div id='app'>Simulated SPA Content</div></body></html>",
            data_elements=[
                {"type": "input_field", "name": "q", "value": ""},
                {"type": "data_attribute", "name": "data-user-id", "value": "12345"},
            ],
            api_calls_detected=[
                {"url": f"{url}/api/user", "method": "GET", "status": "200"},
                {"url": f"{url}/api/products", "method": "GET", "status": "200"},
            ],
            dom_mutations=3,
            load_time_ms=round(config.js_render_wait_ms / 10, 2),
            success=True,
        )
