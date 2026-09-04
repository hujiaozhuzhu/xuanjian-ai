"""
服务器场景测试
"""

import pytest
import asyncio
from fp_sentinel.server import FPServer, create_app
from fp_sentinel.models import (
    ScanResult, ScanTool, Severity, Verdict,
    FilterResult, FilterReason,
)


class TestFPServerScenarios:
    """FPServer 场景测试"""

    def setup_method(self):
        self.server = FPServer()

    @pytest.mark.asyncio
    async def test_scan_js_eval(self, tmp_path):
        """扫描JS eval"""
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
    async def test_scan_js_command(self, tmp_path):
        """扫描JS命令注入"""
        (tmp_path / "app.js").write_text('exec("ls " + userInput);')
        result = await self.server.scan_project(str(tmp_path), language="javascript")
        assert result is not None

    @pytest.mark.asyncio
    async def test_scan_js_secrets(self, tmp_path):
        """扫描JS密钥"""
        (tmp_path / "app.js").write_text('const API_KEY = "sk-1234567890abcdef";')
        result = await self.server.scan_project(str(tmp_path), language="javascript")
        assert result is not None

    @pytest.mark.asyncio
    async def test_scan_js_safe(self, tmp_path):
        """扫描JS安全代码"""
        (tmp_path / "app.js").write_text('element.textContent = userInput;')
        result = await self.server.scan_project(str(tmp_path), language="javascript")
        assert result is not None

    @pytest.mark.asyncio
    async def test_scan_multiple_files(self, tmp_path):
        """扫描多文件"""
        (tmp_path / "app.js").write_text('eval(userInput);')
        (tmp_path / "utils.js").write_text('element.innerHTML = x;')
        (tmp_path / "safe.js").write_text('element.textContent = x;')
        result = await self.server.scan_project(str(tmp_path), language="javascript")
        assert result is not None

    @pytest.mark.asyncio
    async def test_apply_filters_critical(self):
        """过滤CRITICAL"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="js.injection.eval",
            file="app.js", line=10, code="eval(userInput)",
            severity=Severity.CRITICAL, message="eval",
        )
        result = await self.server._apply_filters(scan)
        assert result.risk_score > 0

    @pytest.mark.asyncio
    async def test_apply_filters_high(self):
        """过滤HIGH"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="js.xss.innerhtml",
            file="app.js", line=10, code="element.innerHTML = x",
            severity=Severity.HIGH, message="XSS",
        )
        result = await self.server._apply_filters(scan)
        assert result.risk_score > 0

    @pytest.mark.asyncio
    async def test_apply_filters_nosec(self):
        """过滤nosec"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="js.injection.eval",
            file="app.js", line=10, code="eval(x)  # nosec",
            severity=Severity.CRITICAL, message="eval",
        )
        result = await self.server._apply_filters(scan)
        assert result.verdict in (Verdict.FALSE_POSITIVE, Verdict.LIKELY_FALSE_POSITIVE, Verdict.NEEDS_REVIEW)

    @pytest.mark.asyncio
    async def test_apply_filters_test_file(self):
        """过滤测试文件"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="js.injection.eval",
            file="tests/test_app.js", line=10, code="eval(x)",
            severity=Severity.CRITICAL, message="eval",
        )
        result = await self.server._apply_filters(scan)
        assert result is not None

    @pytest.mark.asyncio
    async def test_statistics_with_results(self):
        """带结果的统计"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="js.injection.eval",
            file="app.js", line=10, code="eval(x)",
            severity=Severity.CRITICAL, message="eval",
        )
        results = [
            FilterResult(original=scan, verdict=Verdict.TRUE_POSITIVE, confidence=0.9, filter_reasons=[], risk_score=8.0, recommendation="Fix"),
            FilterResult(original=scan, verdict=Verdict.FALSE_POSITIVE, confidence=0.8, filter_reasons=[], risk_score=0.0, recommendation="Ignore"),
        ]
        stats = self.server._calculate_statistics(results)
        assert stats.total == 2
        assert stats.true_positives == 1
        assert stats.false_positives == 1

    def test_get_finding(self):
        """获取发现"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER, rule_id="js.injection.eval",
            file="app.js", line=10, code="eval(x)",
            severity=Severity.CRITICAL, message="eval",
        )
        fr = FilterResult(original=scan, verdict=Verdict.TRUE_POSITIVE, confidence=0.9, filter_reasons=[], risk_score=8.0, recommendation="Fix")
        self.server._findings["f1"] = fr
        assert self.server.get_finding("f1") is not None
        assert self.server.get_finding("nonexistent") is None

    def test_list_projects(self):
        """列出项目"""
        self.server._scans["s1"] = {"project_path": "/tmp/p1", "status": "completed", "stats": {"total": 5}}
        self.server._scans["s2"] = {"project_path": "/tmp/p2", "status": "completed", "stats": {"total": 3}}
        projects = {}
        for s in self.server._scans.values():
            p = s["project_path"]
            projects[p] = projects.get(p, 0) + 1
        assert len(projects) == 2

    def test_create_app(self):
        """创建应用"""
        app = create_app(self.server)
        assert app is not None
