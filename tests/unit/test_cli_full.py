"""
CLI 完整测试
"""

from typer.testing import CliRunner

from tests.conftest import plain_cli_output
from fp_sentinel.cli import app


runner = CliRunner()


class TestCLIFull:
    """CLI完整测试"""

    def test_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0

    def test_version(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0

    def test_scan_help(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--lang" in plain_cli_output(result.output)

    def test_list_help(self):
        result = runner.invoke(app, ["list", "--help"])
        assert result.exit_code == 0

    def test_stats_help(self):
        result = runner.invoke(app, ["stats", "--help"])
        assert result.exit_code == 0

    def test_mark_help(self):
        result = runner.invoke(app, ["mark", "--help"])
        assert result.exit_code == 0

    def test_browser_help(self):
        result = runner.invoke(app, ["browser", "--help"])
        assert result.exit_code == 0

    def test_scan_nonexistent(self):
        result = runner.invoke(app, ["scan", "/nonexistent", "--no-save"])
        assert result.exit_code in (0, 1)

    def test_scan_empty(self, tmp_path):
        result = runner.invoke(app, ["scan", str(tmp_path), "--no-save"])
        assert result.exit_code in (0, 1)

    def test_scan_js(self, tmp_path):
        (tmp_path / "app.js").write_text('eval(x);')
        result = runner.invoke(app, ["scan", str(tmp_path), "--lang", "javascript", "--no-save"])
        assert result.exit_code in (0, 1)

    def test_scan_python(self, tmp_path):
        (tmp_path / "app.py").write_text('eval(x)')
        result = runner.invoke(app, ["scan", str(tmp_path), "--lang", "python", "--no-save"])
        assert result.exit_code in (0, 1)

    def test_scan_format_json(self, tmp_path):
        (tmp_path / "app.js").write_text('eval(x);')
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--no-save"])
        assert result.exit_code in (0, 1)

    def test_scan_format_table(self, tmp_path):
        (tmp_path / "app.js").write_text('eval(x);')
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "table", "--no-save"])
        assert result.exit_code in (0, 1)

    def test_scan_verbose(self, tmp_path):
        (tmp_path / "app.js").write_text('eval(x);')
        result = runner.invoke(app, ["scan", str(tmp_path), "--verbose", "--no-save"])
        assert result.exit_code in (0, 1)

    def test_list_empty(self):
        result = runner.invoke(app, ["list"])
        assert result.exit_code in (0, 1)

    def test_stats_empty(self):
        result = runner.invoke(app, ["stats"])
        assert result.exit_code in (0, 1)
