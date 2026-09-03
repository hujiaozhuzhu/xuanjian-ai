"""
扫描器管理器单元测试
"""

from unittest.mock import patch

import pytest
from fp_sentinel.scanners.manager import ScannerManager
from fp_sentinel.models import ScanTool


class TestScannerManager:
    """扫描器管理器测试"""

    def setup_method(self):
        self.manager = ScannerManager()

    def test_init_scanners(self):
        """初始化扫描器"""
        available = self.manager.get_available_scanners()
        assert len(available) > 0

    def test_reports_missing_semgrep_to_cli(self):
        with patch("fp_sentinel.scanners.semgrep_scanner.shutil.which", return_value=None):
            manager = ScannerManager()

        assert "semgrep" not in manager.get_available_scanners()
        assert any("fp-sentinel[scanners]" in message for message in manager.get_unavailable_scanner_messages())

    def test_detect_language_javascript(self, tmp_path):
        """检测JavaScript项目"""
        (tmp_path / "package.json").write_text("{}")
        lang = self.manager._detect_language(str(tmp_path))
        assert lang == "javascript"

    def test_detect_language_typescript(self, tmp_path):
        """检测TypeScript项目"""
        (tmp_path / "tsconfig.json").write_text("{}")
        lang = self.manager._detect_language(str(tmp_path))
        assert lang == "typescript"

    def test_detect_language_python(self, tmp_path):
        """检测Python项目"""
        (tmp_path / "requirements.txt").write_text("flask")
        lang = self.manager._detect_language(str(tmp_path))
        assert lang == "python"

    def test_detect_language_java(self, tmp_path):
        """检测Java项目"""
        (tmp_path / "pom.xml").write_text("<project/>")
        lang = self.manager._detect_language(str(tmp_path))
        assert lang == "java"

    def test_detect_language_go(self, tmp_path):
        """检测Go项目"""
        (tmp_path / "go.mod").write_text("module test")
        lang = self.manager._detect_language(str(tmp_path))
        assert lang == "go"

    def test_detect_language_by_extension(self, tmp_path):
        """按扩展名检测语言"""
        (tmp_path / "app.js").write_text("const x = 1;")
        (tmp_path / "utils.js").write_text("const y = 2;")
        lang = self.manager._detect_language(str(tmp_path))
        assert lang == "javascript"

    def test_select_scanners_javascript(self):
        """JavaScript扫描器选择"""
        scanners = self.manager._select_scanners("javascript")
        assert ScanTool.SEMGREP in scanners

    def test_select_scanners_python(self):
        """Python扫描器选择"""
        scanners = self.manager._select_scanners("python")
        assert ScanTool.SEMGREP in scanners
        assert ScanTool.BANDIT in scanners

    def test_select_scanners_java(self):
        """Java扫描器选择"""
        scanners = self.manager._select_scanners("java")
        assert ScanTool.SEMGREP in scanners
        assert ScanTool.FINDSECBUGS in scanners

    @pytest.mark.asyncio
    async def test_scan_empty_dir(self, tmp_path):
        """扫描空目录"""
        results = await self.manager.scan(str(tmp_path), language="javascript")
        assert isinstance(results, list)
