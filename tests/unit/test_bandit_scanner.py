"""
Bandit 扫描器测试
"""

import pytest
from fp_sentinel.scanners.bandit_scanner import BanditScanner
from fp_sentinel.models import ScanTool


class TestBanditScanner:
    """Bandit扫描器测试"""

    def test_create_scanner(self):
        scanner = BanditScanner()
        assert scanner is not None

    def test_scanner_type(self):
        scanner = BanditScanner()
        assert scanner.get_tool_type() == ScanTool.BANDIT

    def test_scanner_default_config(self):
        scanner = BanditScanner()
        assert scanner.timeout == 300
