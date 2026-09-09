"""
Tests for the Enhanced Dynamic Scanner Module (v3.1)

Tests: WAF bypass, logic vuln detection, JS rendering analysis
Coverage target: >= 95%
"""

import sys
import os
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from fp_sentinel.dynamic_scanner.models import (
    BypassTechnique,
    LogicVulnType,
    BypassResult,
    LogicVulnFinding,
    JSRenderResult,
    DynamicScanConfig,
    DynamicScanResult,
)


class TestBypassTechnique(unittest.TestCase):
    def test_all_techniques_exist(self):
        self.assertEqual(len(BypassTechnique), 15)

    def test_technique_values(self):
        self.assertEqual(BypassTechnique.URL_ENCODE.value, "url_encode")
        self.assertEqual(BypassTechnique.BASE64.value, "base64")
        self.assertEqual(BypassTechnique.NULL_BYTE.value, "null_byte")


class TestLogicVulnType(unittest.TestCase):
    def test_all_types_exist(self):
        self.assertEqual(len(LogicVulnType), 10)

    def test_type_values(self):
        self.assertEqual(LogicVulnType.PRICE_TAMPERING.value, "price_tampering")
        self.assertEqual(LogicVulnType.IDOR.value, "idor")


class TestDynamicScanConfig(unittest.TestCase):
    def test_default(self):
        cfg = DynamicScanConfig(target_url="http://localhost")
        self.assertEqual(cfg.target_url, "http://localhost")
        self.assertEqual(cfg.max_waf_techniques, 10)
        self.assertEqual(cfg.test_payload, "fp_sentinel_verify")

    def test_custom(self):
        cfg = DynamicScanConfig(
            target_url="http://test.local",
            max_waf_techniques=5,
            js_render_wait_ms=10000,
        )
        self.assertEqual(cfg.max_waf_techniques, 5)
        self.assertEqual(cfg.js_render_wait_ms, 10000)


class TestDynamicScanResult(unittest.TestCase):
    def test_create(self):
        cfg = DynamicScanConfig(target_url="http://localhost")
        result = DynamicScanResult(scan_id="s1", target_url="http://localhost", config=cfg)
        self.assertEqual(result.scan_id, "s1")
        self.assertEqual(len(result.bypass_results), 0)


class TestWAFBypassTester(unittest.TestCase):
    def test_simulated_test_all(self):
        from fp_sentinel.dynamic_scanner.waf_bypass import WAFBypassTester
        tester = WAFBypassTester()
        config = DynamicScanConfig(
            target_url="http://localhost",
            max_waf_techniques=5,
            enabled_techniques=[BypassTechnique.URL_ENCODE, BypassTechnique.BASE64],
        )
        results = tester.test_all_techniques("http://localhost/api/test", config=config)
        self.assertEqual(len(results), 2)

    def test_single_technique(self):
        from fp_sentinel.dynamic_scanner.waf_bypass import WAFBypassTester
        tester = WAFBypassTester()
        result = tester.test_single_technique(
            "http://localhost/search", "q", BypassTechnique.URL_ENCODE
        )
        self.assertIsInstance(result, BypassResult)
        self.assertEqual(result.technique, BypassTechnique.URL_ENCODE)

    def test_encoding_url_encode(self):
        from fp_sentinel.dynamic_scanner.waf_bypass import _encode_payload
        encoded = _encode_payload("fp_sentinel_verify", BypassTechnique.URL_ENCODE)
        self.assertIn("fp_sentinel", encoded)

    def test_encoding_base64(self):
        from fp_sentinel.dynamic_scanner.waf_bypass import _encode_payload
        import base64
        encoded = _encode_payload("fp_sentinel_verify", BypassTechnique.BASE64)
        decoded = base64.b64decode(encoded).decode()
        self.assertEqual(decoded, "fp_sentinel_verify")

    def test_encoding_hex(self):
        from fp_sentinel.dynamic_scanner.waf_bypass import _encode_payload
        encoded = _encode_payload("AB", BypassTechnique.HEX_ENCODE)
        self.assertTrue(encoded.startswith("%"))

    def test_encoding_case_variation(self):
        from fp_sentinel.dynamic_scanner.waf_bypass import _encode_payload
        encoded = _encode_payload("abcdef", BypassTechnique.CASE_VARIATION)
        self.assertEqual(encoded, "AbCdEf")

    def test_encoding_null_byte(self):
        from fp_sentinel.dynamic_scanner.waf_bypass import _encode_payload
        encoded = _encode_payload("test", BypassTechnique.NULL_BYTE)
        self.assertTrue(encoded.endswith("%00"))

    def test_encoding_double_encode(self):
        from fp_sentinel.dynamic_scanner.waf_bypass import _encode_payload
        encoded = _encode_payload("hello world", BypassTechnique.DOUBLE_ENCODE)
        self.assertIn("%", encoded)

    def test_encoding_comment_inject(self):
        from fp_sentinel.dynamic_scanner.waf_bypass import _encode_payload
        encoded = _encode_payload("test", BypassTechnique.COMMENT_INJECT)
        self.assertIn("/**/", encoded)

    def test_encoding_whitespace_inject(self):
        from fp_sentinel.dynamic_scanner.waf_bypass import _encode_payload
        encoded = _encode_payload("ab", BypassTechnique.WHITESPACE_INJECT)
        self.assertEqual(encoded, "a b")

    def test_encoding_param_pollution(self):
        from fp_sentinel.dynamic_scanner.waf_bypass import _encode_payload
        encoded = _encode_payload("val", BypassTechnique.PARAM_POLLUTION)
        self.assertIn("duplicate=val", encoded)

    def test_encoding_unicode_escape(self):
        from fp_sentinel.dynamic_scanner.waf_bypass import _encode_payload
        encoded = _encode_payload("ab", BypassTechnique.UNICODE_ESCAPE)
        self.assertIn("\\u", encoded)

    def test_browser_test_null_byte_blocked(self):
        from fp_sentinel.dynamic_scanner.waf_bypass import WAFBypassTester
        tester = WAFBypassTester()
        config = DynamicScanConfig(
            target_url="http://localhost",
            enabled_techniques=[BypassTechnique.NULL_BYTE],
        )
        results = tester.test_all_techniques("http://localhost/api", config=config)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].blocked)


class TestLogicVulnDetector(unittest.TestCase):
    def test_run_all_tests(self):
        from fp_sentinel.dynamic_scanner.logic_detector import LogicVulnDetector
        detector = LogicVulnDetector()
        findings = detector.run_all_tests("http://localhost/api/cart")
        self.assertIsInstance(findings, list)

    def test_single_test_price_tampering(self):
        from fp_sentinel.dynamic_scanner.logic_detector import LogicVulnDetector
        detector = LogicVulnDetector()
        finding = detector.run_single_test(
            "http://localhost/api/cart", LogicVulnType.PRICE_TAMPERING
        )
        self.assertIsNone(finding)

    def test_single_test_negative_value(self):
        from fp_sentinel.dynamic_scanner.logic_detector import LogicVulnDetector
        detector = LogicVulnDetector()
        finding = detector.run_single_test(
            "http://localhost/api/pay", LogicVulnType.NEGATIVE_VALUE
        )
        self.assertIsNone(finding)

    def test_send_test_values(self):
        from fp_sentinel.dynamic_scanner.logic_detector import LogicVulnDetector
        detector = LogicVulnDetector()
        results = detector._send_test_values(
            "http://localhost/api", "price", ["10", "-1", "0"]
        )
        self.assertEqual(len(results), 3)

    def test_finding_model_fields(self):
        finding = LogicVulnFinding(
            vuln_type=LogicVulnType.PRICE_TAMPERING,
            endpoint="http://localhost/api/cart",
            description="Price accepts negative values",
        )
        self.assertEqual(finding.vuln_type, LogicVulnType.PRICE_TAMPERING)
        self.assertEqual(finding.severity, "HIGH")


class TestJSRenderingAnalyzer(unittest.TestCase):
    def test_simulated_analyze(self):
        from fp_sentinel.dynamic_scanner.js_renderer import JSRenderingAnalyzer
        analyzer = JSRenderingAnalyzer()
        result = analyzer.analyze("http://localhost")
        self.assertTrue(result.success)
        self.assertIsNotNone(result.rendered_title)
        self.assertTrue(len(result.data_elements) > 0)
        self.assertTrue(len(result.api_calls_detected) > 0)

    def test_extract_json_data_no_browser(self):
        from fp_sentinel.dynamic_scanner.js_renderer import JSRenderingAnalyzer
        analyzer = JSRenderingAnalyzer()
        data = analyzer.extract_json_data("http://localhost")
        self.assertIsInstance(data, list)

    def test_js_render_result_model(self):
        result = JSRenderResult(url="http://localhost", success=True)
        self.assertTrue(result.success)
        self.assertEqual(result.dom_mutations, 0)

    def test_browser_analyze_with_engine(self):
        from fp_sentinel.dynamic_scanner.js_renderer import JSRenderingAnalyzer
        mock_browser = MagicMock()
        mock_browser.list_sessions.return_value = []
        mock_session = MagicMock()
        mock_session.session_id = "js-1"
        mock_browser.start.return_value = mock_session
        mock_browser.navigate.return_value = {"success": True, "status": 200}
        mock_browser.inject_network_hook.return_value = None
        mock_browser.inject_console_hook.return_value = None
        mock_browser.evaluate.return_value = ""
        mock_browser.get_dom_snapshot.return_value = {"tag": "div", "attrs": {}}
        mock_browser.get_network_requests.return_value = [
            {"url": "http://localhost/api/data", "method": "GET", "status": "200"},
        ]
        analyzer = JSRenderingAnalyzer(browser_engine=mock_browser)
        config = DynamicScanConfig(target_url="http://localhost", js_render_wait_ms=1000)
        result = analyzer.analyze("http://localhost", config=config)
        self.assertTrue(result.success)
        mock_browser.inject_network_hook.assert_called_once()


class TestBypassResult(unittest.TestCase):
    def test_model(self):
        r = BypassResult(
            technique=BypassTechnique.URL_ENCODE,
            payload="test%20val",
            target_url="http://localhost",
            blocked=False,
        )
        self.assertFalse(r.blocked)
        self.assertEqual(r.status_code, 0)


class TestLogicVulnFinding(unittest.TestCase):
    def test_model(self):
        f = LogicVulnFinding(
            vuln_type=LogicVulnType.RACE_CONDITION,
            endpoint="http://localhost/api/buy",
            description="Race condition detected",
        )
        self.assertEqual(f.severity, "HIGH")
        self.assertEqual(f.reproducible_steps, [])


if __name__ == "__main__":
    unittest.main()
