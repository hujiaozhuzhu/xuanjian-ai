"""
规则过滤器测试
"""

import pytest
from fp_sentinel.filters.rule_filter import RuleFilter
from fp_sentinel.models import ScanResult, ScanTool, Severity, Verdict


class TestRuleFilter:
    """规则过滤器测试"""

    def setup_method(self):
        self.filter = RuleFilter()

    def test_create_filter(self):
        """创建过滤器"""
        assert self.filter is not None

    def test_filter_test_file(self):
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
        import asyncio
        result = asyncio.run(self.filter.filter(scan))
        # 测试文件应该被过滤或降级
        assert result.verdict in (Verdict.FALSE_POSITIVE, Verdict.LIKELY_FALSE_POSITIVE, Verdict.NEEDS_REVIEW)

    def test_filter_nosec_comment(self):
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
        import asyncio
        result = asyncio.run(self.filter.filter(scan))
        assert result.verdict in (Verdict.FALSE_POSITIVE, Verdict.LIKELY_FALSE_POSITIVE, Verdict.NEEDS_REVIEW)

    def test_filter_real_vulnerability(self):
        """真实漏洞不过滤"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.injection.eval",
            file="app.js",
            line=10,
            code="eval(userInput)",
            severity=Severity.CRITICAL,
            message="Code injection",
        )
        import asyncio
        result = asyncio.run(self.filter.filter(scan))
        # 真实漏洞应该保留
        assert result.verdict in (Verdict.TRUE_POSITIVE, Verdict.NEEDS_REVIEW)

    def test_filter_node_modules(self):
        """过滤 node_modules"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="node_modules/dep/lib.js",
            line=10,
            code="element.innerHTML = x",
            severity=Severity.HIGH,
            message="XSS",
        )
        import asyncio
        result = asyncio.run(self.filter.filter(scan))
        assert result.verdict in (Verdict.FALSE_POSITIVE, Verdict.LIKELY_FALSE_POSITIVE, Verdict.NEEDS_REVIEW)
