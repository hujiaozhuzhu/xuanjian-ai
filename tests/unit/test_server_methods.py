"""
服务器方法测试
"""

import pytest
import asyncio
from fp_sentinel.server import FPServer, create_app
from fp_sentinel.models import (
    ScanResult, ScanTool, Severity, Verdict,
    FilterResult, FilterReason,
)


class TestFPServerMethods:
    """FPServer 方法测试"""

    def setup_method(self):
        self.server = FPServer()

    def test_get_finding(self):
        """获取发现"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.injection.eval",
            file="app.js",
            line=10,
            code="eval(userInput)",
            severity=Severity.CRITICAL,
            message="Code injection",
        )
        fr = FilterResult(
            original=scan,
            verdict=Verdict.TRUE_POSITIVE,
            confidence=0.9,
            filter_reasons=[],
            risk_score=8.0,
            recommendation="Fix",
        )
        self.server._findings["f1"] = fr

        result = self.server.get_finding("f1")
        assert result is not None
        assert result.original.rule_id == "js.injection.eval"

    def test_get_finding_not_found(self):
        """获取不存在的发现"""
        result = self.server.get_finding("nonexistent")
        assert result is None

    def test_list_findings(self):
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

        # 列出全部
        all_findings = list(self.server._findings.values())
        assert len(all_findings) == 2

        # 按verdict过滤
        tps = [f for f in all_findings if f.verdict == Verdict.TRUE_POSITIVE]
        assert len(tps) == 1

    def test_list_projects(self):
        """列出项目"""
        self.server._scans["s1"] = {
            "id": "s1",
            "project_path": "/tmp/project1",
            "language": "javascript",
            "status": "completed",
            "completed_at": "2026-09-02T00:00:00",
            "stats": {"total": 5},
        }
        self.server._scans["s2"] = {
            "id": "s2",
            "project_path": "/tmp/project2",
            "language": "python",
            "status": "completed",
            "completed_at": "2026-09-02T00:00:00",
            "stats": {"total": 3},
        }

        projects = {}
        for sid, scan in self.server._scans.items():
            if scan.get("status") == "completed":
                p = scan.get("project_path", "")
                if p not in projects:
                    projects[p] = {"path": p, "scan_count": 0, "total_findings": 0}
                projects[p]["scan_count"] += 1
                projects[p]["total_findings"] += scan.get("stats", {}).get("total", 0)

        assert len(projects) == 2

    def test_get_statistics(self):
        """获取统计"""
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

        all_findings = list(self.server._findings.values())
        total = len(all_findings)
        fps = sum(1 for f in all_findings if f.verdict == Verdict.FALSE_POSITIVE)
        tps = sum(1 for f in all_findings if f.verdict == Verdict.TRUE_POSITIVE)

        assert total == 2
        assert fps == 1
        assert tps == 1

    @pytest.mark.asyncio
    async def test_scan_project_js(self, tmp_path):
        """扫描JS项目"""
        (tmp_path / "app.js").write_text('eval(userInput);')
        result = await self.server.scan_project(str(tmp_path), language="javascript")
        assert result is not None

    @pytest.mark.asyncio
    async def test_scan_project_python(self, tmp_path):
        """扫描Python项目"""
        (tmp_path / "app.py").write_text('eval(user_input)')
        result = await self.server.scan_project(str(tmp_path), language="python")
        assert result is not None

    @pytest.mark.asyncio
    async def test_apply_filters_with_threshold(self):
        """带阈值的过滤"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.injection.eval",
            file="app.js",
            line=10,
            code="eval(userInput)",
            severity=Severity.CRITICAL,
            message="Code injection",
        )
        result = await self.server._apply_filters(scan, confidence_threshold=0.5)
        assert result is not None

    @pytest.mark.asyncio
    async def test_apply_filters_l1(self):
        """L1过滤"""
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
    async def test_apply_filters_l2(self):
        """L2过滤"""
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


class TestCreateApp:
    """创建应用测试"""

    def test_create_app(self):
        """创建FastAPI应用"""
        app = create_app()
        assert app is not None

    def test_create_app_with_server(self):
        """带服务器创建应用"""
        server = FPServer()
        app = create_app(server)
        assert app is not None
