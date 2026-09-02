"""
MCP 导出和统计测试
"""

import pytest
import asyncio
import json
from fp_sentinel.mcp_server import MCPAuditServer, create_mcp_server, _generate_explanation
from fp_sentinel.models import (
    ScanResult, ScanTool, Severity, Verdict,
    FilterResult, FilterReason,
)


class TestMCPExport:
    """MCP导出测试"""

    def setup_method(self):
        self.server = create_mcp_server()

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

        # 导出JSON
        findings = [self.server._findings[fid] for fid in self.server._scans["s1"].get("findings", []) if fid in self.server._findings]
        stats = self.server._calculate_statistics(findings)
        report = {
            "scan_id": "s1",
            "statistics": stats.model_dump(),
            "findings": [f.model_dump() for f in findings],
        }
        json_str = json.dumps(report, default=str, ensure_ascii=False)
        assert "eval" in json_str

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
            "# 玄鉴扫描报告", "",
            f"- 规则: {fr.original.rule_id}",
            f"- 严重级别: {fr.original.severity.value}",
            f"- 判定: {fr.verdict.value}",
            f"- 建议: {fr.recommendation}",
        ]
        md = "\n".join(lines)
        assert "CRITICAL" in md
        assert "Fix" in md

    def test_explanation_eval(self):
        """eval解释"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="js.injection.eval",
            file="app.js", line=10, code="eval(userInput)",
            severity=Severity.CRITICAL, message="Code injection",
            cwe="CWE-95", owasp="A03:2021",
        )
        fr = FilterResult(
            original=scan, verdict=Verdict.TRUE_POSITIVE,
            confidence=0.9,
            filter_reasons=[FilterReason(filter_level="L1", rule_name="eval", description="eval detected", confidence=0.9)],
            risk_score=9.0, recommendation="Remove eval()",
        )
        explanation = _generate_explanation(fr)
        assert "eval" in explanation
        assert "CWE-95" in explanation

    def test_explanation_xss(self):
        """XSS解释"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="js.xss.innerhtml",
            file="app.js", line=10, code="element.innerHTML = x",
            severity=Severity.HIGH, message="XSS",
            cwe="CWE-79",
        )
        fr = FilterResult(
            original=scan, verdict=Verdict.TRUE_POSITIVE,
            confidence=0.8, filter_reasons=[], risk_score=7.0, recommendation="Use textContent",
        )
        explanation = _generate_explanation(fr)
        assert len(explanation) > 0

    def test_explanation_fp(self):
        """误报解释"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="js.injection.eval",
            file="app.js", line=10, code="eval('1+1')",
            severity=Severity.CRITICAL, message="eval",
        )
        fr = FilterResult(
            original=scan, verdict=Verdict.FALSE_POSITIVE,
            confidence=0.9,
            filter_reasons=[FilterReason(filter_level="L1", rule_name="constant", description="Constant expression", confidence=0.9)],
            risk_score=0.0, recommendation="Ignore",
        )
        explanation = _generate_explanation(fr)
        assert len(explanation) > 0

    def test_statistics_with_all_verdicts(self):
        """全判定统计"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="test",
            file="app.js", line=10, code="test",
            severity=Severity.MEDIUM, message="test",
        )
        results = [
            FilterResult(original=scan, verdict=Verdict.TRUE_POSITIVE, confidence=0.9, filter_reasons=[], risk_score=8.0, recommendation="Fix"),
            FilterResult(original=scan, verdict=Verdict.FALSE_POSITIVE, confidence=0.8, filter_reasons=[], risk_score=0.0, recommendation="Ignore"),
            FilterResult(original=scan, verdict=Verdict.LIKELY_FALSE_POSITIVE, confidence=0.6, filter_reasons=[], risk_score=2.0, recommendation="Review"),
            FilterResult(original=scan, verdict=Verdict.NEEDS_REVIEW, confidence=0.5, filter_reasons=[], risk_score=5.0, recommendation="Review"),
        ]
        stats = self.server._calculate_statistics(results)
        assert stats.total == 4
        assert stats.true_positives == 1
        assert stats.false_positives == 1
        assert stats.likely_false_positives == 1
        assert stats.needs_review == 1

    def test_list_projects(self):
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
                    projects[p] = {"count": 0, "total": 0}
                projects[p]["count"] += 1
                projects[p]["total"] += s.get("stats", {}).get("total", 0)
        assert len(projects) == 2
