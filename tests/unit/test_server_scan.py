"""
服务器扫描测试
"""

import pytest
import asyncio
from fp_sentinel.server import FPServer
from fp_sentinel.models import ScanResult, ScanTool, Severity, Verdict


class TestFPServerScan:
    """FPServer 扫描测试"""

    def setup_method(self):
        self.server = FPServer()

    @pytest.mark.asyncio
    async def test_scan_js_vuln(self, tmp_path):
        """扫描JS漏洞"""
        (tmp_path / "app.js").write_text('eval(userInput);')
        result = await self.server.scan_project(str(tmp_path), language="javascript")
        assert result is not None

    @pytest.mark.asyncio
    async def test_scan_js_xss(self, tmp_path):
        """扫描JS XSS"""
        (tmp_path / "app.js").write_text('element.innerHTML = userInput;')
        result = await self.server.scan_project(str(tmp_path), language="javascript")
        assert result is not None

    @pytest.mark.asyncio
    async def test_scan_js_multiple(self, tmp_path):
        """扫描多个JS文件"""
        (tmp_path / "app.js").write_text('eval(userInput);')
        (tmp_path / "utils.js").write_text('element.innerHTML = x;')
        result = await self.server.scan_project(str(tmp_path), language="javascript")
        assert result is not None

    @pytest.mark.asyncio
    async def test_scan_empty(self, tmp_path):
        """扫描空目录"""
        result = await self.server.scan_project(str(tmp_path), language="javascript")
        assert result is not None

    @pytest.mark.asyncio
    async def test_apply_filters_critical(self):
        """过滤CRITICAL漏洞"""
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
        assert result.risk_score > 0

    @pytest.mark.asyncio
    async def test_apply_filters_high(self):
        """过滤HIGH漏洞"""
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
    async def test_apply_filters_medium(self):
        """过滤MEDIUM漏洞"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.crypto.math-random",
            file="app.js",
            line=10,
            code="const token = Math.random();",
            severity=Severity.LOW,
            message="Weak random",
        )
        result = await self.server._apply_filters(scan)
        assert result is not None

    @pytest.mark.asyncio
    async def test_apply_filters_nosec(self):
        """过滤nosec注释"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.injection.eval",
            file="app.js",
            line=10,
            code="eval(userInput)  # nosec",
            severity=Severity.CRITICAL,
            message="Code injection",
        )
        result = await self.server._apply_filters(scan)
        assert result is not None
        assert result.verdict in (Verdict.FALSE_POSITIVE, Verdict.LIKELY_FALSE_POSITIVE, Verdict.NEEDS_REVIEW)

    @pytest.mark.asyncio
    async def test_apply_filters_test_file(self):
        """过滤测试文件"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.injection.eval",
            file="tests/test_app.js",
            line=10,
            code="eval(userInput)",
            severity=Severity.CRITICAL,
            message="Code injection",
        )
        result = await self.server._apply_filters(scan)
        assert result is not None

    @pytest.mark.asyncio
    async def test_apply_filters_python(self):
        """过滤Python漏洞"""
        scan = ScanResult(
            tool=ScanTool.SEMGREP,
            rule_id="py.injection.command",
            file="cmd.py",
            line=10,
            code='os.system("ls " + user_input)',
            severity=Severity.CRITICAL,
            message="Command injection",
        )
        result = await self.server._apply_filters(scan)
        assert result is not None

    @pytest.mark.asyncio
    async def test_statistics(self):
        """统计测试"""
        from fp_sentinel.models import FilterResult
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
        ]
        stats = self.server._calculate_statistics(results)
        assert stats.total == 1
        assert stats.true_positives == 1
