"""
MCP 工具测试
"""

import pytest
import asyncio
from fp_sentinel.mcp_server import MCPAuditServer, create_mcp_server
from fp_sentinel.models import ScanResult, ScanTool, Severity, Verdict


class TestMCPTools:
    """MCP工具测试"""

    def setup_method(self):
        self.server = create_mcp_server()

    @pytest.mark.asyncio
    async def test_scan_project_tool(self, tmp_path):
        """scan_project 工具测试"""
        (tmp_path / "app.js").write_text('eval(userInput);')
        # 直接调用内部方法
        result = await self.server.scanner_manager.scan(
            str(tmp_path), language="javascript"
        )
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_triage_findings_empty(self):
        """triage_findings 空结果"""
        stats = self.server._calculate_statistics([])
        assert stats.total == 0

    @pytest.mark.asyncio
    async def test_apply_filters_eval(self):
        """过滤 eval 漏洞"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.injection.eval",
            file="app.js",
            line=10,
            code="eval(userInput)",
            severity=Severity.CRITICAL,
            message="Code injection",
        )
        result = await self.server._apply_filters(scan)
        assert result is not None
        assert result.original == scan

    @pytest.mark.asyncio
    async def test_apply_filters_xss(self):
        """过滤 XSS 漏洞"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="app.js",
            line=10,
            code="element.innerHTML = userInput",
            severity=Severity.HIGH,
            message="XSS",
        )
        result = await self.server._apply_filters(scan)
        assert result is not None

    @pytest.mark.asyncio
    async def test_apply_filters_nosec(self):
        """过滤 nosec 注释"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="app.js",
            line=10,
            code="element.innerHTML = userInput  # nosec",
            severity=Severity.HIGH,
            message="XSS",
        )
        result = await self.server._apply_filters(scan)
        assert result is not None
        # nosec 应该被过滤为误报
        assert result.verdict in (Verdict.FALSE_POSITIVE, Verdict.LIKELY_FALSE_POSITIVE, Verdict.NEEDS_REVIEW)

    @pytest.mark.asyncio
    async def test_apply_filters_test_file(self):
        """过滤测试文件"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="tests/test_app.js",
            line=10,
            code="element.innerHTML = userInput",
            severity=Severity.HIGH,
            message="XSS",
        )
        result = await self.server._apply_filters(scan)
        assert result is not None

    @pytest.mark.asyncio
    async def test_apply_filters_l1_only(self):
        """仅L1过滤"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.injection.eval",
            file="app.js",
            line=10,
            code="eval(userInput)",
            severity=Severity.CRITICAL,
            message="Code injection",
        )
        result = await self.server._apply_filters(scan, filter_level="L1")
        assert result is not None

    @pytest.mark.asyncio
    async def test_apply_filters_l2_only(self):
        """仅L2过滤"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.injection.eval",
            file="app.js",
            line=10,
            code="eval(userInput)",
            severity=Severity.CRITICAL,
            message="Code injection",
        )
        result = await self.server._apply_filters(scan, filter_level="L2")
        assert result is not None

    @pytest.mark.asyncio
    async def test_apply_filters_python(self):
        """过滤Python漏洞"""
        scan = ScanResult(
            tool=ScanTool.SEMGREP,
            rule_id="py.injection.sql",
            file="db.py",
            line=10,
            code='cursor.execute("SELECT * WHERE id=" + user_id)',
            severity=Severity.CRITICAL,
            message="SQL injection",
        )
        result = await self.server._apply_filters(scan)
        assert result is not None

    @pytest.mark.asyncio
    async def test_calculate_statistics(self):
        """统计计算"""
        from fp_sentinel.models import FilterResult, FilterReason
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.injection.eval",
            file="app.js",
            line=10,
            code="eval(userInput)",
            severity=Severity.CRITICAL,
            message="Code injection",
        )
        results = [
            FilterResult(
                original=scan,
                verdict=Verdict.TRUE_POSITIVE,
                confidence=0.9,
                filter_reasons=[],
                risk_score=8.0,
                recommendation="Fix",
            ),
            FilterResult(
                original=scan,
                verdict=Verdict.FALSE_POSITIVE,
                confidence=0.8,
                filter_reasons=[],
                risk_score=0.0,
                recommendation="Ignore",
            ),
        ]
        stats = self.server._calculate_statistics(results)
        assert stats.total == 2
        assert stats.true_positives == 1
        assert stats.false_positives == 1
