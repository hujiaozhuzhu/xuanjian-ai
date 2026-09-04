"""
基础扫描器测试
"""

import pytest
from fp_sentinel.scanners.base import BaseScanner
from fp_sentinel.models import ScanTool


class TestBaseScanner:
    """基础扫描器测试"""

    def test_base_scanner_abstract(self):
        """BaseScanner是抽象类"""
        with pytest.raises(TypeError):
            BaseScanner()

    def test_base_scanner_subclass(self):
        """子类必须实现抽象方法"""
        class TestScanner(BaseScanner):
            async def scan(self, target_path, **kwargs):
                return []

            def get_tool_type(self):
                return ScanTool.SEMGREP

        scanner = TestScanner()
        assert scanner is not None
        assert scanner.enabled is True

    def test_base_scanner_config(self):
        """配置传递"""
        class TestScanner(BaseScanner):
            async def scan(self, target_path, **kwargs):
                return []

            def get_tool_type(self):
                return ScanTool.SEMGREP

        config = {"enabled": False, "timeout": 100}
        scanner = TestScanner(config)
        assert scanner.enabled is False

    def test_generate_id(self):
        """ID生成"""
        class TestScanner(BaseScanner):
            async def scan(self, target_path, **kwargs):
                return []

            def get_tool_type(self):
                return ScanTool.SEMGREP

        scanner = TestScanner()
        id1 = scanner._generate_id("semgrep", "rule1", "file1", 10)
        assert isinstance(id1, str)
        assert len(id1) > 0

    def test_generate_id_unique(self):
        """不同输入生成不同ID"""
        class TestScanner(BaseScanner):
            async def scan(self, target_path, **kwargs):
                return []

            def get_tool_type(self):
                return ScanTool.SEMGREP

        scanner = TestScanner()
        id1 = scanner._generate_id("semgrep", "rule1", "file1", 10)
        id2 = scanner._generate_id("semgrep", "rule2", "file2", 20)
        assert id1 != id2
