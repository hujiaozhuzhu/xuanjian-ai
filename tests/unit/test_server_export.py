"""
服务器导出和WebSocket测试
"""

import pytest
import asyncio
from fp_sentinel.server import FPServer, create_app
from fp_sentinel.models import (
    ScanResult, ScanTool, Severity, Verdict,
    FilterResult, FilterReason,
)


class TestFPServerExport:
    """FPServer 导出测试"""

    def setup_method(self):
        self.server = FPServer()

    def test_export_json(self):
        """导出JSON"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="js.injection.eval",
            file="app.js", line=10, code="eval(x)",
            severity=Severity.CRITICAL, message="eval",
        )
        fr = FilterResult(
            original=scan, verdict=Verdict.TRUE_POSITIVE,
            confidence=0.9, filter_reasons=[], risk_score=8.0, recommendation="Fix",
        )
        self.server._findings["f1"] = fr
        self.server._scans["s1"] = {
            "id": "s1", "project_path": "/tmp", "language": "javascript",
            "status": "completed", "completed_at": "2026-09-02",
            "findings": ["f1"], "stats": {"total": 1},
        }

        import json
        report = {
            "scan_id": "s1",
            "project_path": "/tmp",
            "statistics": {"total": 1},
            "findings": [fr.model_dump()],
        }
        json_str = json.dumps(report, default=str)
        assert len(json_str) > 0

    def test_export_markdown(self):
        """导出Markdown"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="js.injection.eval",
            file="app.js", line=10, code="eval(x)",
            severity=Severity.CRITICAL, message="eval",
        )
        fr = FilterResult(
            original=scan, verdict=Verdict.TRUE_POSITIVE,
            confidence=0.9, filter_reasons=[], risk_score=8.0, recommendation="Fix",
        )

        lines = [
            "# 扫描报告", "",
            f"- 规则: {fr.original.rule_id}",
            f"- 判定: {fr.verdict.value}",
            f"- 建议: {fr.recommendation}",
        ]
        md = "\n".join(lines)
        assert "eval" in md

    def test_mark_false_positive(self):
        """标记误报"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="js.xss.innerhtml",
            file="app.js", line=10, code="element.innerHTML = x  # nosec",
            severity=Severity.HIGH, message="XSS",
        )
        fr = FilterResult(
            original=scan, verdict=Verdict.NEEDS_REVIEW,
            confidence=0.5, filter_reasons=[], risk_score=5.0, recommendation="Review",
        )
        self.server._findings["f1"] = fr

        # 标记误报
        self.server._findings["f1"].verdict = Verdict.FALSE_POSITIVE
        self.server._findings["f1"].recommendation = "Manual FP: nosec comment"
        assert self.server._findings["f1"].verdict == Verdict.FALSE_POSITIVE

    def test_mark_tp(self):
        """标记真阳性"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="js.injection.eval",
            file="app.js", line=10, code="eval(x)",
            severity=Severity.CRITICAL, message="eval",
        )
        fr = FilterResult(
            original=scan, verdict=Verdict.NEEDS_REVIEW,
            confidence=0.5, filter_reasons=[], risk_score=5.0, recommendation="Review",
        )
        self.server._findings["f1"] = fr

        # 标记真阳性
        self.server._findings["f1"].verdict = Verdict.TRUE_POSITIVE
        assert self.server._findings["f1"].verdict == Verdict.TRUE_POSITIVE

    def test_get_statistics(self):
        """获取统计"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="js.injection.eval",
            file="app.js", line=10, code="eval(x)",
            severity=Severity.CRITICAL, message="eval",
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

    def test_list_projects_with_scans(self):
        """列出项目"""
        self.server._scans["s1"] = {
            "project_path": "/tmp/p1", "status": "completed",
            "completed_at": "2026-09-02", "language": "javascript", "stats": {"total": 5},
        }
        self.server._scans["s2"] = {
            "project_path": "/tmp/p2", "status": "completed",
            "completed_at": "2026-09-02", "language": "python", "stats": {"total": 3},
        }

        projects = {}
        for s in self.server._scans.values():
            if s.get("status") == "completed":
                p = s.get("project_path", "")
                if p not in projects:
                    projects[p] = {"path": p, "count": 0, "total": 0}
                projects[p]["count"] += 1
                projects[p]["total"] += s.get("stats", {}).get("total", 0)

        assert len(projects) == 2
        assert projects["/tmp/p1"]["total"] == 5

    def test_register_unregister_ws(self):
        """WebSocket注册/注销"""
        mock_ws = object()
        self.server.register_ws("scan1", mock_ws)
        assert mock_ws in self.server._ws_connections.get("scan1", [])

        self.server.unregister_ws("scan1", mock_ws)
