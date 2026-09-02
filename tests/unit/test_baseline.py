"""
基线过滤器测试
"""

import pytest
import tempfile
import os
from fp_sentinel.filters.baseline import BaselineFilter
from fp_sentinel.models import ScanResult, ScanTool, Severity, Verdict


class TestBaselineFilter:
    """基线过滤器测试"""

    def setup_method(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "baseline.json")
        self.filter = BaselineFilter({"db_path": self.db_path})

    def teardown_method(self):
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
            os.rmdir(self.tmp_dir)
        except:
            pass

    def test_create_filter(self):
        """创建过滤器"""
        assert self.filter is not None

    def test_add_to_baseline(self):
        """添加到基线"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="app.js",
            line=10,
            code="element.innerHTML = userInput",
            severity=Severity.HIGH,
            message="XSS",
        )
        fp = self.filter.add_to_baseline(scan, verdict="false_positive", confidence=0.9, reason="test")
        assert fp is not None
        assert len(fp) > 0

    def test_get_baseline_count(self):
        """获取基线数量"""
        count = self.filter.get_baseline_count()
        assert count >= 0

    def test_filter_with_baseline(self):
        """基线过滤"""
        scan = ScanResult(
            tool=ScanTool.JS_SCANNER,
            rule_id="js.xss.innerhtml",
            file="app.js",
            line=10,
            code="element.innerHTML = userInput",
            severity=Severity.HIGH,
            message="XSS",
        )
        # 添加到基线
        self.filter.add_to_baseline(scan, verdict="false_positive", confidence=0.9, reason="test")

        # 过滤
        import asyncio
        result = asyncio.run(self.filter.filter(scan))
        assert result.verdict in (Verdict.FALSE_POSITIVE, Verdict.LIKELY_FALSE_POSITIVE, Verdict.NEEDS_REVIEW)
