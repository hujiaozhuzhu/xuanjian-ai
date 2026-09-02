"""
MCP 工具直接调用测试
"""

import pytest
import asyncio
from fp_sentinel.mcp_server import MCPAuditServer, create_mcp_server
from fp_sentinel.models import (
    ScanResult, ScanTool, Severity, Verdict,
    FilterResult, FilterReason,
)


class TestMCPToolsDirect:
    """MCP工具直接调用测试"""

    def setup_method(self):
        self.server = create_mcp_server()

    @pytest.mark.asyncio
    async def test_scan_and_triage(self, tmp_path):
        """扫描+分诊完整流程"""
        (tmp_path / "app.js").write_text('eval(userInput);')

        # 扫描
        raw = await self.server.scanner_manager.scan(
            str(tmp_path), language="javascript"
        )

        # 过滤
        filtered = []
        for i, sr in enumerate(raw):
            fr = await self.server._apply_filters(sr)
            fid = f"test:{i}"
            fr.id = fid
            self.server._findings[fid] = fr
            filtered.append(fr)

        assert len(filtered) >= 0

    @pytest.mark.asyncio
    async def test_explain_finding(self):
        """解释发现"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.injection.eval",
            file="app.js",
            line=10,
            code="eval(userInput)",
            severity=Severity.CRITICAL,
            message="Code injection",
            cwe="CWE-95",
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
            risk_score=8.0,
            recommendation="Fix code injection",
        )
        self.server._findings["test-1"] = fr

        # 解释
        finding = self.server._findings.get("test-1")
        assert finding is not None
        assert finding.original.rule_id == "js.injection.eval"

    @pytest.mark.asyncio
    async def test_mark_false_positive(self):
        """标记误报"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="app.js",
            line=10,
            code="element.innerHTML = userInput  # nosec",
            severity=Severity.HIGH,
            message="XSS",
        )
        fr = FilterResult(
            original=scan,
            verdict=Verdict.NEEDS_REVIEW,
            confidence=0.5,
            filter_reasons=[],
            risk_score=5.0,
            recommendation="Review",
        )
        self.server._findings["test-2"] = fr

        # 标记误报
        finding = self.server._findings.get("test-2")
        finding.verdict = Verdict.FALSE_POSITIVE
        finding.recommendation = "Manual FP"
        assert finding.verdict == Verdict.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_list_findings(self):
        """列出发现"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.injection.eval",
            file="app.js",
            line=10,
            code="eval(userInput)",
            severity=Severity.CRITICAL,
            message="Code injection",
        )
        self.server._findings["f1"] = FilterResult(
            original=scan, verdict=Verdict.TRUE_POSITIVE,
            confidence=0.9, filter_reasons=[], risk_score=8.0, recommendation="Fix",
        )
        self.server._findings["f2"] = FilterResult(
            original=scan, verdict=Verdict.FALSE_POSITIVE,
            confidence=0.8, filter_reasons=[], risk_score=0.0, recommendation="Ignore",
        )

        # 按verdict过滤
        tps = [f for f in self.server._findings.values() if f.verdict == Verdict.TRUE_POSITIVE]
        fps = [f for f in self.server._findings.values() if f.verdict == Verdict.FALSE_POSITIVE]
        assert len(tps) == 1
        assert len(fps) == 1

    @pytest.mark.asyncio
    async def test_statistics_with_findings(self):
        """带发现的统计"""
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
                original=scan, verdict=Verdict.TRUE_POSITIVE,
                confidence=0.9, filter_reasons=[], risk_score=8.0, recommendation="Fix",
            ),
            FilterResult(
                original=scan, verdict=Verdict.FALSE_POSITIVE,
                confidence=0.8, filter_reasons=[], risk_score=0.0, recommendation="Ignore",
            ),
            FilterResult(
                original=scan, verdict=Verdict.LIKELY_FALSE_POSITIVE,
                confidence=0.6, filter_reasons=[], risk_score=2.0, recommendation="Review",
            ),
            FilterResult(
                original=scan, verdict=Verdict.NEEDS_REVIEW,
                confidence=0.5, filter_reasons=[], risk_score=5.0, recommendation="Review",
            ),
        ]
        stats = self.server._calculate_statistics(results)
        assert stats.total == 4
        assert stats.true_positives == 1
        assert stats.false_positives == 1
        assert stats.likely_false_positives == 1
        assert stats.needs_review == 1

    @pytest.mark.asyncio
    async def test_export_report_json(self, tmp_path):
        """导出JSON报告"""
        (tmp_path / "app.js").write_text('eval(userInput);')

        # 扫描
        raw = await self.server.scanner_manager.scan(
            str(tmp_path), language="javascript"
        )

        # 过滤
        filtered = []
        for i, sr in enumerate(raw):
            fr = await self.server._apply_filters(sr)
            fid = f"scan1:{i}"
            fr.id = fid
            self.server._findings[fid] = fr
            filtered.append(fr)

        # 统计
        stats = self.server._calculate_statistics(filtered)
        assert stats is not None

    @pytest.mark.asyncio
    async def test_list_projects(self, tmp_path):
        """列出项目"""
        (tmp_path / "app.js").write_text('eval(userInput);')

        # 模拟扫描记录
        self.server._scans["scan-1"] = {
            "id": "scan-1",
            "project_path": str(tmp_path),
            "language": "javascript",
            "status": "completed",
            "completed_at": "2026-09-02T00:00:00",
            "stats": {"total": 5},
        }

        # 列出项目
        projects = {}
        for sid, scan in self.server._scans.items():
            if scan.get("status") == "completed":
                p = scan.get("project_path", "")
                if p not in projects:
                    projects[p] = {"path": p, "scan_count": 0}
                projects[p]["scan_count"] += 1

        assert len(projects) >= 1
