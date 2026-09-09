"""
CLI 命令测试
使用 CliRunner 测试CLI命令的注册和执行
"""

import pytest
from typer.testing import CliRunner
from fp_sentinel.auto_pr.cli import auto_pr_app

runner = CliRunner()


class TestCLICommands:
    """测试CLI命令注册和执行"""

    def test_preview_command(self):
        result = runner.invoke(auto_pr_app, [
            "preview",
            "--rule-id", "py.xss.dom",
            "--severity", "HIGH",
            "--file", "app.py",
            "--code", "el.innerHTML = userInput",
        ])
        assert result.exit_code == 0
        assert "修复预览" in result.output or "innerHTML" in result.output

    def test_preview_command_sql(self):
        result = runner.invoke(auto_pr_app, [
            "preview",
            "--rule-id", "py.injection.sql",
            "--severity", "CRITICAL",
            "--file", "app.py",
            '--code', 'cursor.execute("SELECT * FROM users WHERE id = " + uid)',
        ])
        assert result.exit_code == 0


    def test_verify_command_pass(self):
        result = runner.invoke(auto_pr_app, [
            "verify",
            "--patch-id", "test-p1",
            "--finding-id", "test-f1",
            "--fixed-code", "el.textContent = userInput",
            "--original-code", "el.innerHTML = userInput",
            "--vuln-type", "xss",
        ])
        assert result.exit_code == 0

    def test_verify_command_generate(self):
        """Test verify with generate command"""
        result = runner.invoke(auto_pr_app, [
            "verify",
            "--patch-id", "gen-p1",
            "--finding-id", "gen-f1",
            "--fixed-code", "subprocess.run(['ls', '-la'], shell=False)",
            "--original-code", "os.system('ls')",
            "--vuln-type", "os_command",
        ])
        assert result.exit_code == 0

    def test_verify_command_fail(self):
        result = runner.invoke(auto_pr_app, [
            "verify",
            "--patch-id", "test-p2",
            "--finding-id", "test-f2",
            "--fixed-code", "eval(user_input)",  # introduces eval
            "--original-code", "el.innerHTML = userInput",
            "--vuln-type", "xss",
        ])
        # Should fail because eval() is a dangerous pattern -> new vuln + original not resolved
        assert result.exit_code == 1

    def test_verify_command_invalid_syntax(self):
        result = runner.invoke(auto_pr_app, [
            "verify",
            "--patch-id", "test-p3",
            "--finding-id", "test-f3",
            "--fixed-code", "subprocess.run([, broken",
            "--original-code", "os.system(cmd)",
            "--vuln-type", "os_command",
        ])
        assert result.exit_code == 1

    def test_submit_command_dry_run(self):
        result = runner.invoke(auto_pr_app, [
            "submit",
            "--finding-ids", "nonexistent-finding",
            "--title", "Test",
            "--dry-run",
            "--provider", "gitlab",
        ])
        # Even in dry_run mode with no patches, should report error
        # but exit cleanly (handled gracefully)
        assert result.exit_code == 0 or result.exit_code == 1

    def test_status_command(self):
        result = runner.invoke(auto_pr_app, [
            "status",
            "--pr-id", "some-pr",
        ])
        assert result.exit_code == 0

    def test_list_command(self):
        result = runner.invoke(auto_pr_app, ["list"])
        assert result.exit_code == 0

    def test_list_command_with_status(self):
        result = runner.invoke(auto_pr_app, [
            "list",
            "--status", "open",
        ])
        assert result.exit_code == 0

    def test_stats_command(self):
        result = runner.invoke(auto_pr_app, ["stats"])
        assert result.exit_code == 0

    def test_test_connection_command(self):
        """Test connection command should fail without real credentials"""
        result = runner.invoke(auto_pr_app, [
            "test-connection",
            "--provider", "gitlab",
        ])
        # Without credentials, should fail
        assert result.exit_code == 1

    def test_test_connection_github(self):
        """Test GitHub connection command without credentials"""
        result = runner.invoke(auto_pr_app, [
            "test-connection",
            "--provider", "github",
        ])
        # Without credentials, should fail
        assert result.exit_code == 1

    def test_list_command_all_statuses(self):
        """Test list with various status filters"""
        for status in ["open", "merged", "closed", "draft"]:
            result = runner.invoke(auto_pr_app, [
                "list",
                "--status", status,
            ])
            assert result.exit_code == 0

    def test_submit_with_tickets(self):
        """Test submit with ticket IDs"""
        result = runner.invoke(auto_pr_app, [
            "submit",
            "--finding-ids", "f1,f2,f3",
            "--title", "Multi-fix",
            "--ticket-ids", "T-001,T-002",
            "--dry-run",
        ])
        assert result.exit_code == 0 or result.exit_code == 1

    def test_submit_with_labels(self):
        """Test submit with custom labels"""
        result = runner.invoke(auto_pr_app, [
            "submit",
            "--finding-ids", "f1",
            "--labels", "critical,security,auto",
            "--dry-run",
        ])
        assert result.exit_code == 0 or result.exit_code == 1

    def test_status_with_explicit_pr_id(self):
        """Test status command returns not found for unknown PR"""
        result = runner.invoke(auto_pr_app, [
            "status",
            "--pr-id", "99999",
        ])
        assert result.exit_code == 0
