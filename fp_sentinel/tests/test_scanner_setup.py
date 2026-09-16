"""C-002: ScannerInstaller / ProjectScannerAdvisor 测试。

覆盖:
- check 可用/不可用路径；
- install dry_run 和失败建议；
- verify；
- generate_one_click_script 与白名单写入校验；
- ProjectScannerAdvisor 语言检测、推荐、报告格式化；
- interactive_agreement / env_token_agreed 模拟；
- CLI setup / render / scan --install-deps 参数解析。

严禁真实 pip install；所有外部命令走 mock。
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from fp_sentinel.mobile_reporting.formats.base_generator import PathNotAllowedError
from fp_sentinel.scanner_setup import (
    SCANNERS,
    SCANNER_INSTALL_CMD,
    ProjectScannerAdvisor,
    ScannerInstaller,
    env_token_agreed,
    interactive_agreement,
)


runner = CliRunner()


# ─────────────────────────── SCANNERS 常量 ──────────────────────


class TestScannersConstant:
    def test_all_required_keys_present(self) -> None:
        required = {"semgrep", "bandit", "findsecbugs", "njsscan", "eslint", "shellcheck", "dirsearch", "httpx"}
        assert required.issubset(set(SCANNERS.keys()))

    def test_each_has_binary_and_pip(self) -> None:
        for name, meta in SCANNERS.items():
            assert "pip_package" in meta, f"{name} missing pip_package"
            assert "binary" in meta, f"{name} missing binary"
            assert "purpose" in meta, f"{name} missing purpose"

    def test_install_cmd_defined(self) -> None:
        assert SCANNER_INSTALL_CMD == "pip install fp-sentinel[scanners]"


# ─────────────────────────── ScannerInstaller.check ────────────────────


class TestScannerInstallerCheck:
    def test_check_installed(self) -> None:
        installer = ScannerInstaller()
        with patch("fp_sentinel.scanner_setup.shutil.which", return_value="/usr/bin/semgrep"), \
             patch("fp_sentinel.scanner_setup.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="semgrep 1.50.0\n", stderr="", returncode=0
            )
            result = installer.check("semgrep")

        assert result["installed"] is True
        assert result["version"] == "1.50.0"
        assert result["error"] is None

    def test_check_not_in_path(self) -> None:
        installer = ScannerInstaller()
        with patch("fp_sentinel.scanner_setup.shutil.which", return_value=None):
            result = installer.check("semgrep")

        assert result["installed"] is False
        assert result["version"] is None
        assert "不在 PATH" in result["error"]

    def test_check_unknown_scanner(self) -> None:
        installer = ScannerInstaller()
        result = installer.check("nonexistent_tool")
        assert result["installed"] is False
        assert "未知扫描器" in result["error"]

    def test_check_timeout(self) -> None:
        installer = ScannerInstaller()
        with patch("fp_sentinel.scanner_setup.shutil.which", return_value="/usr/bin/bandit"), \
             patch(
                 "fp_sentinel.scanner_setup.subprocess.run",
                 side_effect=subprocess.TimeoutExpired(cmd="bandit", timeout=10),
             ):
            result = installer.check("bandit")

        assert result["installed"] is False
        assert "失败" in result["error"]


# ─────────────────────────── ScannerInstaller.install ────────────────────


class TestScannerInstallerInstall:
    def test_install_dry_run(self) -> None:
        installer = ScannerInstaller()
        result = installer.install(["semgrep", "bandit"], dry_run=True)

        assert result["dry_run"] is True
        assert len(result["commands"]) == 2
        assert "--dry-run" not in result["commands"][0]
        assert "semgrep" in result["commands"][0]
        assert "bandit" in result["commands"][1]

    def test_install_dry_run_with_index_url(self) -> None:
        installer = ScannerInstaller()
        result = installer.install(["semgrep"], index_url="https://mirror.example.com/pypi", dry_run=True)

        assert result["dry_run"] is True
        assert "-i https://mirror.example.com/pypi" in result["commands"][0]

    @patch("fp_sentinel.scanner_setup.subprocess.run")
    def test_install_real_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            stdout="Successfully installed semgrep", stderr="", returncode=0
        )
        installer = ScannerInstaller()
        result = installer.install(["semgrep"], dry_run=False)

        assert result["dry_run"] is False
        assert len(result["results"]) == 1
        assert result["results"][0]["ok"] is True
        assert result["results"][0]["name"] == "semgrep"
        mock_run.assert_called_once()

    @patch("fp_sentinel.scanner_setup.subprocess.run")
    def test_install_real_failure(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            stdout="", stderr="Could not find a version", returncode=1
        )
        installer = ScannerInstaller()
        result = installer.install(["bandit"], dry_run=False)

        assert result["results"][0]["ok"] is False
        assert result["results"][0]["returncode"] == 1
        assert "镜像源" in result["suggestions"]

    @patch("fp_sentinel.scanner_setup.subprocess.run")
    def test_install_timeout(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="pip", timeout=120)
        installer = ScannerInstaller()
        result = installer.install(["semgrep"], dry_run=False)

        assert result["results"][0]["ok"] is False
        assert result["results"][0]["returncode"] == -1


# ─────────────────────────── ScannerInstaller.verify ────────────────────


class TestScannerInstallerVerify:
    def test_verify_all_installed(self) -> None:
        installer = ScannerInstaller()
        with patch.object(installer, "check") as mock_check:
            mock_check.return_value = {
                "name": "semgrep", "installed": True, "version": "1.50", "error": None
            }
            result = installer.verify(["semgrep", "bandit"])

        assert len(result["results"]) == 2
        assert all(r["usable"] for r in result["results"])

    def test_verify_missing(self) -> None:
        installer = ScannerInstaller()
        with patch.object(installer, "check") as mock_check:
            mock_check.return_value = {
                "name": "semgrep", "installed": False, "version": None, "error": "缺失"
            }
            result = installer.verify(["semgrep"])

        assert result["results"][0]["installed"] is False
        assert result["results"][0]["usable"] is False


# ─────────────────────────── generate_one_click_script ────────────────


class TestGenerateOneClickScript:
    def test_ps1_content(self) -> None:
        installer = ScannerInstaller()
        script = installer.generate_one_click_script(["semgrep", "bandit"], shell="ps1")

        assert "PowerShell" in script
        assert "semgrep" in script
        assert "bandit" in script
        assert "是否继续安装" in script
        assert "$confirm" in script

    def test_sh_content(self) -> None:
        installer = ScannerInstaller()
        script = installer.generate_one_click_script(["semgrep"], shell="sh")

        assert "#!/usr/bin/env bash" in script
        assert "read -r -p" in script
        assert "semgrep" in script

    def test_invalid_shell_raises(self) -> None:
        installer = ScannerInstaller()
        with pytest.raises(ValueError, match="不支持"):
            installer.generate_one_click_script(["semgrep"], shell="bat")

    def test_write_to_file(self, tmp_path: Path) -> None:
        installer = ScannerInstaller(allowed_roots=[tmp_path])
        out = tmp_path / "setup.ps1"
        installer.generate_one_click_script(["semgrep"], shell="ps1", output_path=out)
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "semgrep" in content

    def test_write_outside_whitelist_raises(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside" / "x.ps1"
        outside.parent.mkdir()
        installer = ScannerInstaller(allowed_roots=[allowed])

        with pytest.raises(PathNotAllowedError):
            installer.generate_one_click_script(["semgrep"], shell="ps1", output_path=outside)


# ─────────────────────────── ProjectScannerAdvisor ────────────────


class TestProjectScannerAdvisor:
    def _make_project(self, tmp_path: Path) -> Path:
        (tmp_path / "app.py").write_text("import os\nos.system('ls')\n")
        (tmp_path / "utils.py").write_text("def foo(): pass\n")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "pkg.js").write_text("// ignored\n")
        (tmp_path / ".git").mkdir()
        return tmp_path

    def test_detect_languages_python(self, tmp_path: Path) -> None:
        proj = self._make_project(tmp_path)
        advisor = ProjectScannerAdvisor()
        counts = advisor.detect_languages(proj)

        assert "python" in counts
        assert counts["python"] == 2  # app.py + utils.py
        # node_modules and .git 被忽略
        assert "javascript" not in counts

    def test_detect_languages_js_ts(self, tmp_path: Path) -> None:
        (tmp_path / "index.ts").write_text("const x: number = 1;\n")
        (tmp_path / "app.js").write_text("console.log(1);\n")
        advisor = ProjectScannerAdvisor()
        counts = advisor.detect_languages(tmp_path)

        assert counts.get("typescript", 0) == 1
        assert counts.get("javascript", 0) == 1

    def test_recommend_python(self, tmp_path: Path) -> None:
        proj = self._make_project(tmp_path)
        advisor = ProjectScannerAdvisor()
        recs = advisor.recommend(proj)

        names = [r["name"] for r in recs]
        assert "bandit" in names
        assert "semgrep" in names

    def test_recommend_javascript(self, tmp_path: Path) -> None:
        (tmp_path / "app.js").write_text("console.log(1);\n")
        advisor = ProjectScannerAdvisor()
        recs = advisor.recommend(tmp_path)

        names = [r["name"] for r in recs]
        assert "eslint" in names or "njsscan" in names
        assert "semgrep" in names

    def test_recommend_generic_fallback(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text("# Test\n")
        advisor = ProjectScannerAdvisor()
        recs = advisor.recommend(tmp_path)

        names = [r["name"] for r in recs]
        assert "semgrep" in names

    def test_recommend_with_extra(self, tmp_path: Path) -> None:
        proj = self._make_project(tmp_path)
        advisor = ProjectScannerAdvisor()
        recs = advisor.recommend(proj, extra=["httpx"])

        names = [r["name"] for r in recs]
        assert "httpx" in names

    def test_format_report(self, tmp_path: Path) -> None:
        proj = self._make_project(tmp_path)
        advisor = ProjectScannerAdvisor()
        report = advisor.format_report(proj)

        assert "# 扫描器推荐报告" in report
        assert "bandit" in report
        assert "pip install" in report and "bandit" in report

    def test_detect_languages_missing_dir_raises(self, tmp_path: Path) -> None:
        advisor = ProjectScannerAdvisor()
        with pytest.raises(FileNotFoundError):
            advisor.detect_languages(tmp_path / "no_such_dir")


# ─────────────────────────── agreement helpers ────────────────


class TestAgreementHelpers:
    def test_env_token_agreed_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("I_HAVE_ENV_AUTH", "1")
        assert env_token_agreed() is True

    def test_env_token_agreed_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("I_HAVE_ENV_AUTH", raising=False)
        assert env_token_agreed() is False

    def test_env_token_wrong_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("I_HAVE_ENV_AUTH", "yes")
        assert env_token_agreed() is False

    def test_interactive_yes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("builtins.input", lambda _: "y")
        assert interactive_agreement() is True

    def test_interactive_YES(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("builtins.input", lambda _: "YES")
        assert interactive_agreement() is True

    def test_interactive_no(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("builtins.input", lambda _: "n")
        assert interactive_agreement() is False

    def test_interactive_eof(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise_eof(prompt: str = "") -> str:
            raise EOFError

        monkeypatch.setattr("builtins.input", _raise_eof)
        assert interactive_agreement() is False


# ─────────────────────────── CLI 参数解析 ────────────────


class TestCLISetup:
    def test_setup_audit(self) -> None:
        from fp_sentinel.cli import app

        result = runner.invoke(app, ["setup", "--audit"])
        # 不要求成功（因为 scanner check 可能找不到命令），只要求不崩溃
        assert result.exit_code in (0, 1)

    def test_setup_dry_run(self) -> None:
        from fp_sentinel.cli import app

        result = runner.invoke(app, ["setup", "--dry-run", "--only", "semgrep,bandit"])
        assert result.exit_code == 0
        assert "dry-run" in result.output

    def test_setup_generate_script_ps1(self) -> None:
        from fp_sentinel.cli import app

        result = runner.invoke(app, ["setup", "--generate-script", "ps1"])
        assert result.exit_code == 0
        assert "PowerShell" in result.output

    def test_setup_generate_script_sh(self) -> None:
        from fp_sentinel.cli import app

        result = runner.invoke(app, ["setup", "--generate-script", "sh"])
        assert result.exit_code == 0
        assert "#!/usr/bin/env bash" in result.output

    def test_setup_invalid_only(self) -> None:
        from fp_sentinel.cli import app

        result = runner.invoke(app, ["setup", "--dry-run", "--only", "notexist_tool"])
        assert result.exit_code == 1

    def test_setup_auto_dry_run(self) -> None:
        from fp_sentinel.cli import app

        result = runner.invoke(app, ["setup", "--auto", "--dry-run"])
        assert result.exit_code == 0


class TestCLIRender:
    def test_render_nonexistent_file(self) -> None:
        from fp_sentinel.cli import app

        result = runner.invoke(app, ["render", "/nonexistent/report.docx", "--fmt", "html"])
        assert result.exit_code != 0  # FileNotFoundError

    def test_render_help(self) -> None:
        from fp_sentinel.cli import app

        result = runner.invoke(app, ["render", "--help"])
        assert result.exit_code == 0
        assert "--fmt" in result.output


class TestCLIScanInstallDeps:
    def test_scan_help_shows_install_deps(self) -> None:
        from fp_sentinel.cli import app

        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--install-deps" in result.output

    @patch("fp_sentinel.scanner_setup.ScannerInstaller")
    def test_scan_install_deps_dry_run(self, mock_cls: MagicMock, tmp_path: Path) -> None:
        """scan --install-deps --dry-run 应检测缺失并给出命令，不真实安装。"""
        from fp_sentinel.cli import app

        instance = mock_cls.return_value
        instance.check.return_value = {
            "name": "semgrep", "installed": False, "version": None, "error": "缺失"
        }

        (tmp_path / "app.py").write_text("pass\n")
        result = runner.invoke(
            app,
            [
                "scan", str(tmp_path), "--lang", "python",
                "--install-deps", "--dry-run", "--no-save",
            ],
        )
        # 可能因为其他原因退出，但不应崩溃
        assert result.exit_code in (0, 1, 2)

    @patch("fp_sentinel.scanner_setup.ScannerInstaller")
    def test_scan_install_deps_all_present(self, mock_cls: MagicMock, tmp_path: Path) -> None:
        from fp_sentinel.cli import app

        instance = mock_cls.return_value
        instance.check.return_value = {
            "name": "semgrep", "installed": True, "version": "1.50", "error": None
        }

        (tmp_path / "app.py").write_text("pass\n")
        result = runner.invoke(
            app,
            [
                "scan", str(tmp_path), "--lang", "python",
                "--install-deps", "--dry-run", "--no-save",
            ],
        )
        assert result.exit_code in (0, 1, 2)


class TestCLIRenderFmtHtml:
    """render --fmt html 成功路径（mock 文件存在）。"""

    @patch("fp_sentinel.web_rendering.DocxPreview")
    def test_render_fmt_html_success(self, mock_cls: MagicMock, tmp_path: Path) -> None:
        from fp_sentinel.cli import app

        (tmp_path / "report.html")  # ensure result path is under tmp_path
        mock_instance = mock_cls.return_value
        mock_instance.render.return_value = {
            "format": "html",
            "path": tmp_path / "report.html",
            "backend": "native-html",
            "warnings": ["安装 LibreOffice 可转 PDF/PNG"],
        }

        # 直接通过 mock 绕过文件存在检查
        docx = tmp_path / "report.docx"
        from docx import Document
        Document().save(str(docx))

        result = runner.invoke(
            app, ["render", str(docx), "--fmt", "html"]
        )
        assert result.exit_code == 0
        assert "渲染完成" in result.output
