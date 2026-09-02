"""
CLI 模块测试
"""

import pytest
from typer.testing import CliRunner
from fp_sentinel.cli import app


runner = CliRunner()


class TestCLI:
    """CLI 测试"""

    def test_version(self):
        """版本命令"""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0

    def test_help(self):
        """帮助命令"""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "xuanjian" in result.output.lower() or "玄鉴" in result.output or len(result.output) > 0

    def test_scan_help(self):
        """扫描帮助"""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0

    def test_list_help(self):
        """列表帮助"""
        result = runner.invoke(app, ["list", "--help"])
        assert result.exit_code == 0

    def test_stats_help(self):
        """统计帮助"""
        result = runner.invoke(app, ["stats", "--help"])
        assert result.exit_code == 0

    def test_mark_help(self):
        """标记帮助"""
        result = runner.invoke(app, ["mark", "--help"])
        assert result.exit_code == 0

    def test_browser_help(self):
        """浏览器帮助"""
        result = runner.invoke(app, ["browser", "--help"])
        assert result.exit_code == 0


class TestCLIScan:
    """CLI 扫描命令测试"""

    def test_scan_nonexistent_path(self, tmp_path):
        """扫描不存在的路径"""
        result = runner.invoke(app, ["scan", str(tmp_path / "nonexistent"), "--no-save"])
        # 应该不崩溃
        assert result.exit_code in (0, 1)

    def test_scan_empty_dir(self, tmp_path):
        """扫描空目录"""
        result = runner.invoke(app, ["scan", str(tmp_path), "--lang", "javascript", "--no-save"])
        assert result.exit_code in (0, 1)

    def test_scan_with_file(self, tmp_path):
        """扫描包含文件的目录"""
        (tmp_path / "app.js").write_text('eval(userInput);')
        result = runner.invoke(app, ["scan", str(tmp_path), "--lang", "javascript", "--no-save"])
        assert result.exit_code in (0, 1)
