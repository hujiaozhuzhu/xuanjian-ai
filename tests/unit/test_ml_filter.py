"""
ML 过滤器测试
"""

import pytest
from fp_sentinel.filters.ml_filter import MLFilter
from fp_sentinel.models import ScanResult, ScanTool, Severity, Verdict


class TestMLFilter:
    """ML过滤器测试"""

    def test_create_filter(self):
        filter = MLFilter()
        assert filter is not None

    def test_filter_baseline(self):
        """基线过滤"""
        filter = MLFilter()
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="app.js",
            line=10,
            code="element.innerHTML = userInput",
            severity=Severity.HIGH,
            message="XSS",
        )
        import asyncio
        result = asyncio.run(filter.filter(scan))
        assert result is not None
        assert result.original == scan

    def test_filter_with_config(self):
        """带配置的过滤器"""
        config = {"confidence_threshold": 0.8}
        filter = MLFilter(config)
        assert filter is not None

    def test_filter_multiple(self):
        """多条过滤"""
        filter = MLFilter()
        scans = [
            ScanResult(
                tool=ScanTool.JS_SCANNER,
                rule_id=f"js.test.{i}",
                file="app.js",
                line=i * 10,
                code=f"code {i}",
                severity=Severity.MEDIUM,
                message=f"test {i}",
            )
            for i in range(3)
        ]
        import asyncio
        for scan in scans:
            result = asyncio.run(filter.filter(scan))
            assert result is not None
