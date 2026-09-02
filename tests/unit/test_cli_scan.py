"""
CLI 扫描测试
"""

import pytest
from typer.testing import CliRunner
from fp_sentinel.cli import app


runner = CliRunner()


class TestCLIScan:
    """CLI扫描测试"""

    def test_help(self):
        """帮助"""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0

    def test_version(self):
        """版本"""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0

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

    def test_scan_js(self, tmp_path):
        """扫描JS"""
        (tmp_path / "app.js").write_text('eval(userInput);')
        result = runner.invoke(app, ["scan", str(tmp_path), "--lang", "javascript", "--no-save"])
        assert result.exit_code in (0, 1)

    def test_scan_empty(self, tmp_path):
        """扫描空目录"""
        result = runner.invoke(app, ["scan", str(tmp_path), "--lang", "javascript", "--no-save"])
        assert result.exit_code in (0, 1)

    def test_scan_nonexistent(self):
        """扫描不存在的路径"""
        result = runner.invoke(app, ["scan", "/nonexistent", "--no-save"])
        assert result.exit_code in (0, 1)


class TestCLIBrowser:
    """CLI浏览器命令测试"""

    def test_browser_start_help(self):
        """启动帮助"""
        from fp_sentinel.cli.browser_commands import app as browser_app
        result = runner.invoke(browser_app, ["start", "--help"])
        assert result.exit_code == 0

    def test_browser_call_help(self):
        """调用帮助"""
        from fp_sentinel.cli.browser_commands import app as browser_app
        result = runner.invoke(browser_app, ["call", "--help"])
        assert result.exit_code == 0

    def test_browser_hook_help(self):
        """Hook帮助"""
        from fp_sentinel.cli.browser_commands import app as browser_app
        result = runner.invoke(browser_app, ["hook", "--help"])
        assert result.exit_code == 0

    def test_browser_navigate_help(self):
        """导航帮助"""
        from fp_sentinel.cli.browser_commands import app as browser_app
        result = runner.invoke(browser_app, ["navigate", "--help"])
        assert result.exit_code == 0

    def test_browser_script_help(self):
        """脚本帮助"""
        from fp_sentinel.cli.browser_commands import app as browser_app
        result = runner.invoke(browser_app, ["script", "--help"])
        assert result.exit_code == 0

    def test_browser_status_help(self):
        """状态帮助"""
        from fp_sentinel.cli.browser_commands import app as browser_app
        result = runner.invoke(browser_app, ["status", "--help"])
        assert result.exit_code == 0

    def test_browser_keys_help(self):
        """密钥帮助"""
        from fp_sentinel.cli.browser_commands import app as browser_app
        result = runner.invoke(browser_app, ["keys", "--help"])
        assert result.exit_code == 0
