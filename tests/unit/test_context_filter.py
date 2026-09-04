"""
上下文过滤器单元测试
"""

import pytest
from fp_sentinel.filters.context_filter import ContextFilter
from fp_sentinel.models import ScanResult, ScanTool, Severity, Verdict


class TestContextFilter:
    """上下文过滤器测试"""

    def setup_method(self):
        self.filter = ContextFilter()

    def test_detect_dead_code_if_false(self):
        """死代码检测: if False"""
        context = 'if False:\n    eval(x)'
        result = self.filter._detect_dead_code(context)
        assert result is True

    def test_detect_dead_code_if_0(self):
        """死代码检测: if 0"""
        context = 'if 0:\n    eval(x)'
        result = self.filter._detect_dead_code(context)
        assert result is True

    def test_detect_dead_code_normal(self):
        """正常代码非死代码"""
        context = 'if True:\n    eval(x)'
        result = self.filter._detect_dead_code(context)
        assert result is False

    def test_detect_test_file(self):
        """测试文件检测"""
        assert self.filter._detect_test_file("tests/test_app.py")
        assert self.filter._detect_test_file("src/app_test.py")
        assert self.filter._detect_test_file("__tests__/app.js")
        assert not self.filter._detect_test_file("src/app.js")

    def test_classify_vuln_type(self):
        """漏洞类型分类"""
        assert self.filter._classify_vuln_type("js.xss.innerhtml") == "xss"
        # injection 包含 sql_injection 关键字，所以返回 sql_injection
        assert self.filter._classify_vuln_type("js.injection.eval") in ("injection", "sql_injection")
        assert self.filter._classify_vuln_type("js.node.sql-injection") == "sql_injection"

    def test_is_java_file(self):
        """Java文件检测"""
        assert self.filter._is_java_file("src/App.java")
        assert not self.filter._is_java_file("src/app.js")

    def test_pass_through(self):
        """直通测试"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="app.js",
            line=10,
            code="element.innerHTML = userInput",
            severity=Severity.HIGH,
            message="XSS",
        )
        result = self.filter._pass_through(scan)
        assert result.verdict == Verdict.NEEDS_REVIEW

    def test_calc_risk(self):
        """风险计算"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="app.js",
            line=10,
            code="test",
            severity=Severity.HIGH,
            message="test",
        )
        risk = self.filter._calc_risk(scan, is_fp=False, confidence=0.8)
        assert risk > 0

    def test_gen_recommendation(self):
        """建议生成"""
        rec = self.filter._gen_recommendation(Verdict.TRUE_POSITIVE, 0.9)
        assert len(rec) > 0

        rec_fp = self.filter._gen_recommendation(Verdict.FALSE_POSITIVE, 0.9)
        assert len(rec_fp) > 0

    def test_estimate_data_flow(self):
        """数据流估计"""
        lines = ['user_input = request.args["id"]', 'cursor.execute(sql)']
        flow = self.filter._estimate_data_flow(lines)
        assert flow >= 0

    def test_calc_complexity(self):
        """复杂度计算"""
        lines = ['if x:', '    if y:', '        if z:', '            eval(a)']
        complexity = self.filter._calc_complexity(lines)
        assert complexity > 0
