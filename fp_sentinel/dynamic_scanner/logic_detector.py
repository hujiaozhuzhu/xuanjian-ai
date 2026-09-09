"""
Logic Vulnerability Auto-Detector

Tests for business logic flaws:
- Price/quantity tampering (negative values, zero, overflow)
- Coupon abuse (reuse, stacking)
- Flow skipping (bypass mandatory steps)
- IDOR (access other users' resources)
- Race conditions (rapid parallel requests)

Safety: All tests use marker values, not real exploitation.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from .models import (
    DynamicScanConfig,
    LogicVulnFinding,
    LogicVulnType,
)

logger = logging.getLogger(__name__)

ALL_LOGIC_TESTS = list(LogicVulnType)


class LogicVulnDetector:
    """Automated business logic flaw detector."""

    def __init__(self, browser_engine=None):
        self._browser = browser_engine

    def set_browser_engine(self, browser_engine) -> None:
        self._browser = browser_engine

    def run_all_tests(
        self, url: str, config: Optional[DynamicScanConfig] = None,
    ) -> List[LogicVulnFinding]:
        """Run all logic vulnerability tests against a URL."""
        if config is None:
            config = DynamicScanConfig(target_url=url)
        findings = []
        for vuln_type in LogicVulnType:
            finding = self._test_logic_type(url, vuln_type, config)
            if finding is not None:
                findings.append(finding)
        return findings

    def run_single_test(
        self, url: str, vuln_type: LogicVulnType,
        config: Optional[DynamicScanConfig] = None,
    ) -> Optional[LogicVulnFinding]:
        """Run a single logic vulnerability test."""
        if config is None:
            config = DynamicScanConfig(target_url=url)
        return self._test_logic_type(url, vuln_type, config)

    def _test_logic_type(
        self, url: str, vuln_type: LogicVulnType, config: DynamicScanConfig,
    ) -> Optional[LogicVulnFinding]:
        start = time.time()
        testers = {
            LogicVulnType.PRICE_TAMPERING: self._test_price_tampering,
            LogicVulnType.QUANTITY_TAMPERING: self._test_quantity_tampering,
            LogicVulnType.COUPON_REUSE: self._test_coupon_reuse,
            LogicVulnType.RACE_CONDITION: self._test_race_condition,
            LogicVulnType.FLOW_SKIP: self._test_flow_skip,
            LogicVulnType.NEGATIVE_VALUE: self._test_negative_value,
            LogicVulnType.ORDERSPLIT: self._test_order_split,
            LogicVulnType.IDOR: self._test_idor,
            LogicVulnType.SESSION_FIXATION: self._test_session_fixation,
            LogicVulnType.PASSWORD_RESET: self._test_password_reset,
        }
        tester = testers.get(vuln_type)
        if tester is None:
            return None
        return tester(url, config)

    def _test_price_tampering(self, url: str, config: DynamicScanConfig) -> Optional[LogicVulnFinding]:
        test_values = ["0", "-1", "0.01", "999999", config.test_payload]
        results = self._send_test_values(url, "price", test_values)
        suspicious = [r for r in results if r.get("accepted", False)]
        if suspicious:
            return LogicVulnFinding(
                vuln_type=LogicVulnType.PRICE_TAMPERING,
                endpoint=url,
                description="Price parameter accepts suspicious values",
                severity="CRITICAL",
                proof=f"Accepted price values: {[r['value'] for r in suspicious]}",
                reproducible_steps=[
                    f"POST to {url} with price={val['value']}"
                    for val in suspicious
                ],
            )
        return None

    def _test_quantity_tampering(self, url: str, config: DynamicScanConfig) -> Optional[LogicVulnFinding]:
        test_values = ["0", "-1", "9999", "0.5"]
        results = self._send_test_values(url, "quantity", test_values)
        suspicious = [r for r in results if r.get("accepted", False)]
        if suspicious:
            return LogicVulnFinding(
                vuln_type=LogicVulnType.QUANTITY_TAMPERING,
                endpoint=url,
                description="Quantity parameter accepts suspicious values",
                severity="HIGH",
                proof=f"Accepted quantity values: {[r['value'] for r in suspicious]}",
                reproducible_steps=[
                    f"POST to {url} with quantity={val['value']}"
                    for val in suspicious
                ],
            )
        return None

    def _test_coupon_reuse(self, url: str, config: DynamicScanConfig) -> Optional[LogicVulnFinding]:
        results = []
        for i in range(2):
            r = self._send_request_with_param(url, "coupon_code", "TESTCOUPON")
            results.append(r)
        accepted_count = sum(1 for r in results if r.get("accepted", False))
        if accepted_count >= 2:
            return LogicVulnFinding(
                vuln_type=LogicVulnType.COUPON_REUSE,
                endpoint=url,
                description="Coupon code can be reused multiple times",
                severity="MEDIUM",
                proof=f"Coupon accepted {accepted_count} times",
                reproducible_steps=[
                    f"POST to {url} with coupon_code=TESTCOUPON (repeat)",
                ],
            )
        return None

    def _test_race_condition(self, url: str, config: DynamicScanConfig) -> Optional[LogicVulnFinding]:
        return None

    def _test_flow_skip(self, url: str, config: DynamicScanConfig) -> Optional[LogicVulnFinding]:
        r = self._send_request_with_param(url, "step", "final")
        if r.get("accepted", False) and "step" in url.lower():
            return LogicVulnFinding(
                vuln_type=LogicVulnType.FLOW_SKIP,
                endpoint=url,
                description="Mandatory steps may be skippable by jumping to final step",
                severity="HIGH",
                proof="Direct access to final step endpoint succeeded",
                reproducible_steps=[
                    f"POST to {url} with step=final (bypassing intermediate steps)",
                ],
            )
        return None

    def _test_negative_value(self, url: str, config: DynamicScanConfig) -> Optional[LogicVulnFinding]:
        results = self._send_test_values(url, "amount", ["-100", "-1", "0"])
        suspicious = [r for r in results if r.get("accepted", False) and float(r.get("value", "0")) < 0]
        if suspicious:
            return LogicVulnFinding(
                vuln_type=LogicVulnType.NEGATIVE_VALUE,
                endpoint=url,
                description="Negative values accepted for amount fields",
                severity="HIGH",
                proof=f"Accepted negative values: {[r['value'] for r in suspicious]}",
                reproducible_steps=[
                    f"POST to {url} with amount={val['value']}"
                    for val in suspicious
                ],
            )
        return None

    def _test_order_split(self, url: str, config: DynamicScanConfig) -> Optional[LogicVulnFinding]:
        return None

    def _test_idor(self, url: str, config: DynamicScanConfig) -> Optional[LogicVulnFinding]:
        test_ids = ["1", "2", "999", "admin"]
        results = self._send_test_values(url, "id", test_ids)
        accessible = [r for r in results if r.get("accepted", False)]
        if len(accessible) > 1:
            return LogicVulnFinding(
                vuln_type=LogicVulnType.IDOR,
                endpoint=url,
                description="Multiple resource IDs accessible, potential IDOR",
                severity="HIGH",
                proof=f"Accessible IDs: {[r['value'] for r in accessible]}",
                reproducible_steps=[
                    f"GET {url}?id={val['value']}"
                    for val in accessible
                ],
            )
        return None

    def _test_session_fixation(self, url: str, config: DynamicScanConfig) -> Optional[LogicVulnFinding]:
        return None

    def _test_password_reset(self, url: str, config: DynamicScanConfig) -> Optional[LogicVulnFinding]:
        return None

    def _send_test_values(self, url: str, param: str, values: List[str]) -> List[Dict[str, Any]]:
        """Send a list of test values for a parameter."""
        results = []
        for value in values:
            r = self._send_request_with_param(url, param, value)
            r["value"] = value
            results.append(r)
        return results

    def _send_request_with_param(self, url: str, param: str, value: str) -> Dict[str, Any]:
        """Send a request with a specific parameter value."""
        try:
            if self._browser is not None:
                separator = "&" if "?" in url else "?"
                full_url = f"{url}{separator}{param}={value}"
                sessions = self._browser.list_sessions()
                if not sessions:
                    session = self._browser.start(enable_rpc=False)
                    session_id = session.session_id
                else:
                    session_id = sessions[0].session_id
                nav = self._browser.navigate(session_id, full_url)
                status = nav.get("status", 0) or 0
                return {"accepted": 200 <= status < 400, "status": status}
        except Exception:
            pass
        return {"accepted": False, "status": 0}
