"""
XuanJian v2.3.0 JS/TS Enhanced Rules Unit Tests

Coverage:
- D1: All v2.3.0 enhanced JS rules regex compile guard
- D2: Enhanced rule hit testing (XSS/proto-pollution/injection/secrets/DOM/TS)
- D3: Enhanced guard groups compile
- D4: JSScanner integration with v2.3.0 rules
"""

import asyncio
import os
import tempfile
from pathlib import Path

import pytest

from fp_sentinel.rules.js import (
    JS_SECURITY_RULES,
    JS_SECURITY_GUARD_PATTERNS,
    XSS_ENHANCED_RULES_V230,
    PROTO_POLLUTION_ENHANCED_V230,
    INJECTION_ENHANCED_V230,
    SECRETS_ENHANCED_V230,
    UNSAFE_DOM_ENHANCED_V230,
    TYPESCRIPT_RULES_V230,
)
from fp_sentinel.rules.js.rules import CustomRule, JS_RULES_INDEX
from fp_sentinel.scanners.js_scanner import JSScanner


def _run_scan(target, **kwargs):
    scanner = JSScanner(config={"check_dependencies": False, **kwargs})
    return asyncio.run(scanner.scan(str(target)))


class TestEnhancedJSRulesCompile:
    """Guard test: all v2.3.0 enhanced JS rules regex must compile"""

    def test_all_v230_enhanced_rules_compile(self):
        import re
        v230_rules = (
            XSS_ENHANCED_RULES_V230
            + PROTO_POLLUTION_ENHANCED_V230
            + INJECTION_ENHANCED_V230
            + SECRETS_ENHANCED_V230
            + UNSAFE_DOM_ENHANCED_V230
            + TYPESCRIPT_RULES_V230
        )
        for rule in v230_rules:
            if rule.code_pattern:
                try:
                    re.compile(rule.code_pattern, re.IGNORECASE)
                except re.error as e:
                    pytest.fail(f"{rule.rule_id} regex invalid: {rule.code_pattern!r} ({e})")

    def test_all_enhanced_guard_groups_compile(self):
        import re
        enhanced_groups = ["xss_enhanced", "prototype_pollution_enhanced", "template_injection", "worker_ssrf", "ts_typing"]
        for group in enhanced_groups:
            patterns = JS_SECURITY_GUARD_PATTERNS.get(group, [])
            for p in patterns:
                try:
                    re.compile(p)
                except re.error as e:
                    pytest.fail(f"guard group {group} invalid regex: {p!r} ({e})")

    def test_v230_rule_counts(self):
        """Verify v2.3.0 new rule counts"""
        assert len(XSS_ENHANCED_RULES_V230) >= 5
        assert len(INJECTION_ENHANCED_V230) >= 4
        assert len(PROTO_POLLUTION_ENHANCED_V230) >= 4
        assert len(SECRETS_ENHANCED_V230) >= 5
        assert len(UNSAFE_DOM_ENHANCED_V230) >= 5
        assert len(TYPESCRIPT_RULES_V230) >= 3

    def test_total_rules_increased(self):
        """Confirm total rule count increased due to v2.3.0 enhancements"""
        assert len(JS_SECURITY_RULES) >= 70


class TestEnhancedRuleMatching:
    """v2.3.0 enhanced rule hit testing"""

    def _match_rule(self, code, rule_id):
        rule = JS_RULES_INDEX.get(rule_id)
        if not rule or not rule.code_pattern:
            return False
        import re
        return bool(re.search(rule.code_pattern, code, re.IGNORECASE))

    @pytest.mark.parametrize(
        ("code", "expected_rule"),
        [
            ('<svg onload="alert(1)">', "js.xss.svg-onload"),
            ('<svg onerror="alert(1)">', "js.xss.svg-onload"),
            ('el.innerHTML = `${location.hash}`', "js.xss.template-literal-xss"),
            ('div.outerHTML = `${document.cookie}`', "js.xss.template-literal-xss"),
        ],
    )
    def test_xss_enhanced_match(self, code, expected_rule):
        assert self._match_rule(code, expected_rule), f"Expected {expected_rule} to match: {code}"

    @pytest.mark.parametrize(
        ("code", "expected_rule"),
        [
            ('obj["__proto__"] = malicious', "js.proto.proto-access"),
            ('obj["constructor"]["prototype"]["isAdmin"] = true', "js.proto.constructor-prototype"),
            ('JSON.parse(req.body)["__proto__"]', "js.proto.json-parse-unsafe"),
            ('Array.prototype.find = function() {}', "js.proto.array-prototype-pollution"),
        ],
    )
    def test_prototype_pollution_match(self, code, expected_rule):
        assert self._match_rule(code, expected_rule), f"Expected {expected_rule} to match: {code}"

    @pytest.mark.parametrize(
        ("code", "expected_rule"),
        [
            ('globalThis.eval(userCode)', "js.injection.indirect-eval"),
            ('window.eval(untrusted)', "js.injection.indirect-eval"),
            ('document.createElement("script")', "js.injection.createElement-script"),
            ('location = "javascript:alert(1)"', "js.injection.win-location-js"),
        ],
    )
    def test_injection_enhanced_match(self, code, expected_rule):
        assert self._match_rule(code, expected_rule), f"Expected {expected_rule} to match: {code}"

    @pytest.mark.parametrize(
        ("code", "expected_rule"),
        [
            ('console.log("token: " + userToken)', "js.secrets.console-sensitive"),
            ('res.send(err.stack)', "js.secrets.error-stack-leak"),
            ('https://user:pass123@example.com/path', "js.secrets.url-credential-leak"),
            ('localStorage.setItem("token", jwt)', "js.secrets.jwt-in-localstorage"),
        ],
    )
    def test_secrets_enhanced_match(self, code, expected_rule):
        assert self._match_rule(code, expected_rule), f"Expected {expected_rule} to match: {code}"


class TestJSScannerWithEnhancedRules:
    """JSScanner integration with v2.3.0 rules"""

    def test_scan_detects_indirect_eval(self, tmp_path):
        """Detect indirect eval"""
        js_file = tmp_path / "app.js"
        js_file.write_text(
            'function run(userCode) {\n    return window.eval(userCode);\n}\n',
            encoding="utf-8",
        )
        results = _run_scan(js_file)
        rule_ids = {r.rule_id for r in results}
        assert "js.injection.indirect-eval" in rule_ids

    def test_scan_detects_proto_pollution(self, tmp_path):
        """Detect prototype pollution"""
        js_file = tmp_path / "merge.js"
        js_file.write_text(
            'function merge(target, source) {\n    target["__proto__"] = source;\n}\n',
            encoding="utf-8",
        )
        results = _run_scan(js_file)
        rule_ids = {r.rule_id for r in results}
        assert "js.proto.proto-access" in rule_ids

    def test_original_rules_still_work(self, tmp_path):
        """Original rules still work (no regression)"""
        js_file = tmp_path / "original.js"
        js_file.write_text('eval(userInput);\n', encoding="utf-8")
        results = _run_scan(js_file)
        rule_ids = {r.rule_id for r in results}
        assert "js.injection.eval" in rule_ids
