"""
数据模型单元测试
"""

import pytest
from fp_sentinel.models import (
    Severity, ScanTool, Verdict, Language,
    Finding, ScanResult, FilterResult, FilterReason,
    BrowserConfig, RPCConfig, HookConfig, HookType,
    BrowserSession, JSRPCResult,
    scan_result_to_finding,
)
from datetime import datetime


class TestEnums:
    """枚举测试"""

    def test_severity_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"

    def test_scan_tool_values(self):
        assert ScanTool.SEMGREP.value == "semgrep"
        assert ScanTool.JS_SCANNER.value == "js_scanner"

    def test_verdict_values(self):
        assert Verdict.TRUE_POSITIVE.value == "true_positive"
        assert Verdict.FALSE_POSITIVE.value == "false_positive"

    def test_language_values(self):
        assert Language.JAVASCRIPT.value == "javascript"
        assert Language.TYPESCRIPT.value == "typescript"
        assert Language.PYTHON.value == "python"


class TestScanResult:
    """扫描结果测试"""

    def test_create_scan_result(self):
        result = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="app.js",
            line=10,
            code="element.innerHTML = userInput",
            severity=Severity.HIGH,
            message="XSS vulnerability",
        )
        assert result.tool == ScanTool.JS_SCANNER
        assert result.rule_id == "js.xss.innerhtml"
        assert result.severity == Severity.HIGH

    def test_scan_result_with_metadata(self):
        result = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="test",
            file="app.js",
            line=10,
            code="test",
            severity=Severity.MEDIUM,
            message="test",
            metadata={"confidence": 0.8, "category": "XSS"},
        )
        assert result.metadata["confidence"] == 0.8


class TestFinding:
    """发现测试"""

    def test_create_finding(self):
        finding = Finding(
            scanner="js_scanner",
            rule_id="js.xss.innerhtml",
            severity=Severity.HIGH,
            file_path="app.js",
            line_start=10,
            message="XSS",
        )
        assert finding.scanner == "js_scanner"


class TestFilterResult:
    """过滤结果测试"""

    def test_is_false_positive(self):
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="test",
            file="app.js",
            line=10,
            code="test",
            severity=Severity.HIGH,
            message="test",
        )
        result = FilterResult(
            original=scan,
            verdict=Verdict.FALSE_POSITIVE,
            confidence=0.9,
            filter_reasons=[],
            risk_score=0,
            recommendation="ignore",
        )
        assert result.is_false_positive is True

    def test_is_not_false_positive(self):
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="test",
            file="app.js",
            line=10,
            code="test",
            severity=Severity.HIGH,
            message="test",
        )
        result = FilterResult(
            original=scan,
            verdict=Verdict.TRUE_POSITIVE,
            confidence=0.9,
            filter_reasons=[],
            risk_score=5,
            recommendation="fix",
        )
        assert result.is_false_positive is False


class TestScanResultToFinding:
    """转换测试"""

    def test_conversion(self):
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="app.js",
            line=10,
            code="element.innerHTML = userInput",
            severity=Severity.HIGH,
            message="XSS",
            cwe="CWE-79",
            owasp="A03:2021",
            metadata={"confidence": 0.8, "category": "XSS", "language": "javascript"},
        )
        finding = scan_result_to_finding(scan)
        assert finding.rule_id == "js.xss.innerhtml"
        assert finding.severity == Severity.HIGH
        assert finding.cwe == "CWE-79"


class TestBrowserModels:
    """浏览器模型测试"""

    def test_browser_config(self):
        config = BrowserConfig()
        assert config.headless is True
        assert config.browser_type == "chromium"

    def test_rpc_config(self):
        config = RPCConfig()
        assert config.port == 18800
        assert config.host == "127.0.0.1"

    def test_hook_config(self):
        config = HookConfig(target="window.encrypt")
        assert config.target == "window.encrypt"
        assert config.hook_type == HookType.TRACE

    def test_browser_session(self):
        session = BrowserSession(session_id="test-001")
        assert session.session_id == "test-001"
        assert session.status == "created"
