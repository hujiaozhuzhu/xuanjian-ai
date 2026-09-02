"""
MCP 服务器完整测试
"""

import pytest
import asyncio
from fp_sentinel.mcp_server import MCPAuditServer, create_mcp_server


class TestMCPServerFull:
    """MCP服务器完整测试"""

    def test_create_server(self):
        server = create_mcp_server()
        assert server is not None

    def test_server_default_config(self):
        server = create_mcp_server()
        assert server.config is not None

    def test_server_custom_config(self):
        config = {
            "rule_filter": {"enabled": False},
            "context_filter": {"enabled": True, "false_positive_threshold": 0.3},
            "ml_filter": {"enabled": False},
            "scanners": {},
        }
        server = create_mcp_server(config)
        assert server.config["rule_filter"]["enabled"] is False

    def test_server_has_mcp(self):
        server = create_mcp_server()
        assert server.mcp is not None

    def test_server_has_filters(self):
        server = create_mcp_server()
        assert server.rule_filter is not None
        assert server.context_filter is not None
        assert server.ml_filter is not None

    def test_server_has_scanner_manager(self):
        server = create_mcp_server()
        assert server.scanner_manager is not None

    def test_server_scans_empty(self):
        server = create_mcp_server()
        assert len(server._scans) == 0

    def test_server_findings_empty(self):
        server = create_mcp_server()
        assert len(server._findings) == 0

    def test_calculate_statistics_empty(self):
        server = create_mcp_server()
        stats = server._calculate_statistics([])
        assert stats.total == 0
        assert stats.false_positives == 0
        assert stats.reduction_rate == "0%"

    def test_default_config(self):
        config = MCPAuditServer._default_config()
        assert config["rule_filter"]["enabled"] is True
        assert config["context_filter"]["enabled"] is True
        assert config["context_filter"]["false_positive_threshold"] == 0.5
        assert config["ml_filter"]["enabled"] is True

    def test_generate_explanation(self):
        from fp_sentinel.mcp_server import _generate_explanation
        from fp_sentinel.models import (
            ScanResult, FilterResult, Verdict, ScanTool,
            Severity, FilterReason,
        )
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="app.js",
            line=10,
            code="element.innerHTML = userInput",
            severity=Severity.HIGH,
            message="XSS vulnerability",
            cwe="CWE-79",
            owasp="A03:2021",
        )
        fr = FilterResult(
            original=scan,
            verdict=Verdict.TRUE_POSITIVE,
            confidence=0.9,
            filter_reasons=[
                FilterReason(
                    filter_level="L1",
                    rule_name="test",
                    description="test reason",
                    confidence=0.8,
                ),
            ],
            risk_score=7.5,
            recommendation="Fix XSS",
        )
        explanation = _generate_explanation(fr)
        assert "js.xss.innerhtml" in explanation
        assert "CWE-79" in explanation
        assert "Fix XSS" in explanation

    @pytest.mark.asyncio
    async def test_apply_filters(self):
        from fp_sentinel.models import ScanResult, ScanTool, Severity
        server = create_mcp_server()
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.injection.eval",
            file="app.js",
            line=10,
            code="eval(userInput)",
            severity=Severity.CRITICAL,
            message="Code injection",
        )
        result = await server._apply_filters(scan)
        assert result is not None
        assert result.original == scan

    @pytest.mark.asyncio
    async def test_apply_filters_with_level(self):
        from fp_sentinel.models import ScanResult, ScanTool, Severity
        server = create_mcp_server()
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="app.js",
            line=10,
            code="element.innerHTML = userInput",
            severity=Severity.HIGH,
            message="XSS",
        )
        result = await server._apply_filters(scan, filter_level="L1")
        assert result is not None
