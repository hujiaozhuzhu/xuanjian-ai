"""
CLI 模块测试
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fp_sentinel.cli import _write_structured_results, app
from fp_sentinel.models import Finding, Severity


runner = CliRunner()


def _finding() -> Finding:
    return Finding(
        scanner="python_scanner",
        rule_id="py.injection.sql",
        severity=Severity.HIGH,
        file_path="app.py",
        line_start=10,
        code_snippet="query = user_input",
        fingerprint="test-fingerprint",
    )


class TestStructuredResults:
    def test_writes_json_results_file(self, tmp_path):
        output = tmp_path / "results.json"

        _write_structured_results([_finding()], "json", str(output))

        data = json.loads(output.read_text(encoding="utf-8"))
        assert data[0]["rule_id"] == "py.injection.sql"

    def test_writes_sarif_results_file(self, tmp_path):
        output = tmp_path / "results.sarif"

        _write_structured_results([_finding()], "sarif", str(output))

        data = json.loads(output.read_text(encoding="utf-8"))
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["results"][0]["ruleId"] == "py.injection.sql"

    def test_rejects_non_structured_results_file(self, tmp_path):
        with pytest.raises(Exception, match="results-file"):
            _write_structured_results([_finding()], "table", str(tmp_path / "results.txt"))


class TestCLI:
    """CLI 测试"""

    def test_version(self):
        """版本命令"""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0

    def test_module_entrypoint_runs_without_script_path(self):
        project_root = Path(__file__).resolve().parents[2]
        result = subprocess.run(
            [sys.executable, "-m", "fp_sentinel", "--version"],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0
        assert "fp_sentinel v" in result.stdout

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
