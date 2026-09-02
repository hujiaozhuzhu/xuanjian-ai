"""
CLI 浏览器命令测试
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from typer.testing import CliRunner
from fp_sentinel.cli.browser_commands import app as browser_app


runner = CliRunner()


class TestCLIBrowserCommands:
    """CLI浏览器命令测试"""

    def test_help(self):
        """帮助"""
        result = runner.invoke(browser_app, ["--help"])
        assert result.exit_code == 0

    def test_start_help(self):
        """启动帮助"""
        result = runner.invoke(browser_app, ["start", "--help"])
        assert result.exit_code == 0

    def test_call_help(self):
        """调用帮助"""
        result = runner.invoke(browser_app, ["call", "--help"])
        assert result.exit_code == 0

    def test_hook_help(self):
        """Hook帮助"""
        result = runner.invoke(browser_app, ["hook", "--help"])
        assert result.exit_code == 0

    def test_navigate_help(self):
        """导航帮助"""
        result = runner.invoke(browser_app, ["navigate", "--help"])
        assert result.exit_code == 0

    def test_script_help(self):
        """脚本帮助"""
        result = runner.invoke(browser_app, ["script", "--help"])
        assert result.exit_code == 0

    def test_status_help(self):
        """状态帮助"""
        result = runner.invoke(browser_app, ["status", "--help"])
        assert result.exit_code == 0

    def test_keys_help(self):
        """密钥帮助"""
        result = runner.invoke(browser_app, ["keys", "--help"])
        assert result.exit_code == 0

    def test_start_with_url_help(self):
        """带URL的启动帮助"""
        result = runner.invoke(browser_app, ["start", "--help"])
        assert result.exit_code == 0
        assert "--url" in result.output or "--headless" in result.output

    def test_call_with_func_help(self):
        """带函数的调用帮助"""
        result = runner.invoke(browser_app, ["call", "--help"])
        assert result.exit_code == 0
        assert "--args" in result.output

    def test_hook_with_type_help(self):
        """带类型的Hook帮助"""
        result = runner.invoke(browser_app, ["hook", "--help"])
        assert result.exit_code == 0
        assert "--type" in result.output
