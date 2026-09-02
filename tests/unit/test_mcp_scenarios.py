"""
MCP 服务器场景测试
"""

import pytest
import asyncio
from fp_sentinel.mcp_server import MCPAuditServer, create_mcp_server, _generate_explanation
from fp_sentinel.models import (
    ScanResult, ScanTool, Severity, Verdict,
    FilterResult, FilterReason,
)


class TestMCPScenarios:
    """MCP服务器场景测试"""

    def setup_method(self):
        self.server = create_mcp_server()

    @pytest.mark.asyncio
    async def test_scan_js_eval(self, tmp_path):
        """扫描JS eval漏洞"""
        (tmp_path / "app.js").write_text('eval(userInput);')
        raw = await self.server.scanner_manager.scan(str(tmp_path), language="javascript")
        for sr in raw:
            fr = await self.server._apply_filters(sr)
            assert fr is not None

    @pytest.mark.asyncio
    async def test_scan_js_xss(self, tmp_path):
        """扫描JS XSS漏洞"""
        (tmp_path / "app.js").write_text('element.innerHTML = userInput;')
        raw = await self.server.scanner_manager.scan(str(tmp_path), language="javascript")
        for sr in raw:
            fr = await self.server._apply_filters(sr)
            assert fr is not None

    @pytest.mark.asyncio
    async def test_scan_js_safe(self, tmp_path):
        """扫描JS安全代码"""
        (tmp_path / "app.js").write_text('element.textContent = userInput;')
        raw = await self.server.scanner_manager.scan(str(tmp_path), language="javascript")
        for sr in raw:
            fr = await self.server._apply_filters(sr)
            assert fr is not None

    @pytest.mark.asyncio
    async def test_scan_python_eval(self, tmp_path):
        """扫描Python eval漏洞"""
        (tmp_path / "app.py").write_text('eval(user_input)')
        raw = await self.server.scanner_manager.scan(str(tmp_path), language="python")
        for sr in raw:
            fr = await self.server._apply_filters(sr)
            assert fr is not None

    @pytest.mark.asyncio
    async def test_scan_mixed(self, tmp_path):
        """扫描混合文件"""
        (tmp_path / "app.js").write_text('eval(userInput);')
        (tmp_path / "utils.js").write_text('element.innerHTML = x;')
        (tmp_path / "safe.js").write_text('element.textContent = x;')
        raw = await self.server.scanner_manager.scan(str(tmp_path), language="javascript")
        for sr in raw:
            fr = await self.server._apply_filters(sr)
            assert fr is not None

    @pytest.mark.asyncio
    async def test_triage_with_all_filters(self, tmp_path):
        """全量过滤"""
        (tmp_path / "app.js").write_text('eval(userInput);')
        raw = await self.server.scanner_manager.scan(str(tmp_path), language="javascript")
        for sr in raw:
            fr = await self.server._apply_filters(
                sr, filter_level="all",
                use_context_filter=True, use_baseline=True
            )
            assert fr is not None

    @pytest.mark.asyncio
    async def test_triage_l1_only(self, tmp_path):
        """仅L1过滤"""
        (tmp_path / "app.js").write_text('eval(userInput);')
        raw = await self.server.scanner_manager.scan(str(tmp_path), language="javascript")
        for sr in raw:
            fr = await self.server._apply_filters(sr, filter_level="L1")
            assert fr is not None

    @pytest.mark.asyncio
    async def test_explain_finding_eval(self):
        """解释eval发现"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.injection.eval",
            file="app.js",
            line=10,
            code="eval(userInput)",
            severity=Severity.CRITICAL,
            message="Code injection via eval",
            cwe="CWE-95",
            owasp="A03:2021",
        )
        fr = FilterResult(
            original=scan,
            verdict=Verdict.TRUE_POSITIVE,
            confidence=0.9,
            filter_reasons=[
                FilterReason(filter_level="L1", rule_name="eval", description="eval detected", confidence=0.9),
            ],
            risk_score=9.0,
            recommendation="Remove eval()",
        )
        explanation = _generate_explanation(fr)
        assert "eval" in explanation
        assert "CWE-95" in explanation

    @pytest.mark.asyncio
    async def test_explain_finding_xss(self):
        """解释XSS发现"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="app.js",
            line=10,
            code="element.innerHTML = userInput",
            severity=Severity.HIGH,
            message="DOM XSS",
            cwe="CWE-79",
        )
        fr = FilterResult(
            original=scan,
            verdict=Verdict.TRUE_POSITIVE,
            confidence=0.8,
            filter_reasons=[],
            risk_score=7.0,
            recommendation="Use textContent",
        )
        explanation = _generate_explanation(fr)
        assert len(explanation) > 0

    @pytest.mark.asyncio
    async def test_statistics_multiple(self, tmp_path):
        """多文件统计"""
        (tmp_path / "app.js").write_text('eval(userInput);')
        (tmp_path / "utils.js").write_text('element.innerHTML = x;')
        raw = await self.server.scanner_manager.scan(str(tmp_path), language="javascript")
        filtered = []
        for sr in raw:
            fr = await self.server._apply_filters(sr)
            filtered.append(fr)
        stats = self.server._calculate_statistics(filtered)
        assert stats.total == len(filtered)

    @pytest.mark.asyncio
    async def test_export_json(self, tmp_path):
        """导出JSON"""
        (tmp_path / "app.js").write_text('eval(userInput);')
        raw = await self.server.scanner_manager.scan(str(tmp_path), language="javascript")
        filtered = []
        for i, sr in enumerate(raw):
            fr = await self.server._apply_filters(sr)
            fr.id = f"scan1:{i}"
            self.server._findings[fr.id] = fr
            filtered.append(fr)
        stats = self.server._calculate_statistics(filtered)
        assert stats is not None
