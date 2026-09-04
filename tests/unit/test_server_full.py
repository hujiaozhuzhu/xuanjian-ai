"""
服务器完整测试
"""

import pytest
import asyncio
from fp_sentinel.server import FPServer


class TestFPServerFull:
    """FPServer 完整测试"""

    def test_create_server(self):
        server = FPServer()
        assert server is not None

    def test_server_has_scanner_manager(self):
        server = FPServer()
        assert server.scanner_manager is not None

    def test_server_has_rule_filter(self):
        server = FPServer()
        assert server.rule_filter is not None

    def test_server_has_context_filter(self):
        server = FPServer()
        assert server.context_filter is not None

    def test_server_has_ml_filter(self):
        server = FPServer()
        assert server.ml_filter is not None

    def test_server_scans_empty(self):
        server = FPServer()
        assert len(server._scans) == 0

    def test_server_findings_empty(self):
        server = FPServer()
        assert len(server._findings) == 0

    def test_calculate_statistics_empty(self):
        server = FPServer()
        stats = server._calculate_statistics([])
        assert stats.total == 0
        assert stats.false_positives == 0
        assert stats.true_positives == 0
        assert stats.needs_review == 0
        assert stats.reduction_rate == "0%"

    @pytest.mark.asyncio
    async def test_scan_project(self, tmp_path):
        """扫描项目"""
        (tmp_path / "app.js").write_text('eval(userInput);')
        server = FPServer()
        result = await server.scan_project(str(tmp_path), language="javascript")
        assert result is not None

    @pytest.mark.asyncio
    async def test_scan_empty_project(self, tmp_path):
        """扫描空项目"""
        server = FPServer()
        result = await server.scan_project(str(tmp_path), language="javascript")
        assert result is not None

    @pytest.mark.asyncio
    async def test_triage_findings(self):
        """分诊发现"""
        from fp_sentinel.models import ScanResult, ScanTool, Severity
        server = FPServer()
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
