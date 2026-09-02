"""
FindSecBugs 扫描器测试
"""

import pytest
from fp_sentinel.scanners.findsecbugs_scanner import FindSecBugsScanner
from fp_sentinel.models import ScanTool


class TestFindSecBugsScanner:
    """FindSecBugs扫描器测试"""

    def test_create_scanner(self):
        scanner = FindSecBugsScanner()
        assert scanner is not None

    def test_scanner_type(self):
        scanner = FindSecBugsScanner()
        assert scanner.get_tool_type() == ScanTool.FINDSECBUGS

    def test_scanner_default_config(self):
        scanner = FindSecBugsScanner()
        assert scanner.timeout == 600
