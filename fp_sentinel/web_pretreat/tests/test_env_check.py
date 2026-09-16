"""env_check 模块的单元测试。

通过 mock subprocess / shutil.which 的方式模拟命令可用/不可用，
检测 ScannerChecker / LibreOfficeChecker / NodeJSExtendedChecker 各项逻辑路径。
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fp_sentinel.mobile_common import env_check
from fp_sentinel.mobile_common.env_check import (
    LibreOfficeChecker,
    NodeJSExtendedChecker,
    ScannerChecker,
    ScannerResult,
    _extract_version,
    run_env_audit,
)


# ──────────────────────────────────────────────────────
# ScannerChecker —— subprocess mock
# ──────────────────────────────────────────────────────


class _FakeProc:
    """subprocess.run 的伪返回值。"""

    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch_env(which_map: dict, run_map: dict) -> tuple:
    """统一 patch shutil.which 和 subprocess.run。

    Parameters
    ----------
    which_map:
        {name: path_or_None} 映射给 shutil.which。
    run_map:
        {(cmd_name, args): FakeProc} 映射给 subprocess.run。

    Returns
    -------
    tuple
        两个 mock 对象 (which_mock, run_mock)。
    """
    def _which_side_effect(name: str, *a, **kw):
        return which_map.get(name)

    def _run_side_effect(cmd_and_args, *a, **kw):
        key = tuple(cmd_and_args)
        if key in run_map:
            return run_map[key]
        raise FileNotFoundError("not found: " + str(key))

    which_mock = patch.object(env_check.shutil, "which", side_effect=_which_side_effect)
    run_mock = patch.object(
        env_check.subprocess, "run", side_effect=_run_side_effect
    )
    return which_mock, run_mock


class TestScannerChecker:
    """ScannerChecker 测试集。"""

    def test_check_available_scanner(self) -> None:
        """命令存在 + 返回版本号 —— 应识别为可用并解析版本。"""
        which_mock, run_mock = _patch_env(
            which_map={"semgrep": "/usr/bin/semgrep"},
            run_map={
                ("semgrep", "--version"): _FakeProc(0, "semgrep 1.55.2"),
            },
        )
        with which_mock, run_mock:
            checker = ScannerChecker()
            result = checker.check("semgrep")

        assert result.available is True
        assert result.version == "1.55.2"
        assert result.install_hint == "已就绪"
        assert "SAST" in result.reason

    def test_check_missing_scanner(self) -> None:
        """命令不在 PATH —— 应给出安装指引。"""
        which_mock, run_mock = _patch_env(
            which_map={"semgrep": None},
            run_map={},
        )
        with which_mock, run_mock:
            checker = ScannerChecker()
            result = checker.check("semgrep")

        assert result.available is False
        assert result.version == ""
        ok = (
            "pip install semgrep" in result.install_hint
            or "fp-sentinel[scanners]" in result.install_hint
        )
        assert ok

    def test_check_unknown_scanner(self) -> None:
        """未录入 catalog 的工具名 —— 给默认安装建议。"""
        which_mock, run_mock = _patch_env(which_map={}, run_map={})
        with which_mock, run_mock:
            checker = ScannerChecker()
            result = checker.check("nonexistent_xyz")

        assert result.available is False
        assert "fp-sentinel[scanners]" in result.install_hint

    def test_check_all_returns_full_list(self) -> None:
        """check_all 应返回 catalog 全部工具的结果，顺序一致。"""
        catalog = {
            "fake1": {
                "version_args": ["--version"],
                "pip_package": "fake1",
                "install_hints": {"generic": "pip install fake1"},
                "reason": "测试用",
            },
            "fake2": {
                "version_args": ["--version"],
                "pip_package": "fake2",
                "install_hints": {"generic": "pip install fake2"},
                "reason": "测试用",
            },
        }
        which_mock, run_mock = _patch_env(which_map={}, run_map={})
        with which_mock, run_mock:
            checker = ScannerChecker(catalog=catalog)
            results = checker.check_all()

        assert len(results) == 2
        assert results[0].name == "fake1"
        assert results[1].name == "fake2"

    def test_print_table_contains_headers(self) -> None:
        """print_table 应产出包含表头字符串。"""
        results = [
            ScannerResult(
                name="tool_a", available=True, version="1.0",
                install_hint="已就绪", reason="测试",
            ),
            ScannerResult(
                name="tool_b", available=False, version="",
                install_hint="pip install tool_b", reason="测试",
            ),
        ]
        checker = ScannerChecker(catalog={})
        out = checker.print_table(results)

        assert "扫描器" in out
        assert "tool_a" in out
        assert "tool_b" in out
        assert "可用" in out
        assert "缺失" in out


# ──────────────────────────────────────────────────────
# 版本提取辅助
# ──────────────────────────────────────────────────────


class TestExtractVersion:
    """_extract_version 的边界测试。"""

    def test_simple_semver(self) -> None:
        assert _extract_version("1.55.2") == "1.55.2"

    def test_prefixed_v(self) -> None:
        assert _extract_version("v1.2.3") == "1.2.3"

    def test_with_text_around(self) -> None:
        assert _extract_version("semgrep version 1.99.0 (build abc)") == "1.99.0"

    def test_empty_string_returns_empty(self) -> None:
        assert _extract_version("") == ""

    def test_none_returns_empty(self) -> None:
        assert _extract_version(None) == ""


# ──────────────────────────────────────────────────────
# LibreOfficeChecker
# ──────────────────────────────────────────────────────


class TestLibreOfficeChecker:
    """LibreOfficeChecker 的 mock 测试。"""

    def test_not_available(self) -> None:
        with patch.object(env_check.shutil, "which", return_value=None):
            checker = LibreOfficeChecker()
            result = checker.check()

        assert result["available"] == "False"
        assert "LibreOffice" in result["name"]
        assert "DOCX" in result["reason"] or "文档" in result["reason"]

    def test_available_returns_version(self) -> None:
        with patch.object(
            env_check.shutil, "which", return_value="/usr/bin/soffice"
        ), patch.object(
            env_check, "_run_version_cmd", return_value="LibreOffice 7.5.2"
        ):
            checker = LibreOfficeChecker()
            result = checker.check()

        assert result["available"] == "True"
        assert result["version"] == "7.5.2"
        assert result["install_hint"] == "已就绪"

    def test_install_hint_contains_reason(self) -> None:
        checker = LibreOfficeChecker()
        hint = checker.get_install_hint()
        assert "原因" in hint or "DOCX" in hint


# ──────────────────────────────────────────────────────
# NodeJSExtendedChecker
# ──────────────────────────────────────────────────────


class TestNodeJSExtendedChecker:
    """NodeJSExtendedChecker mock 测试。"""

    def test_not_available(self) -> None:
        with patch.object(env_check.shutil, "which", return_value=None):
            checker = NodeJSExtendedChecker()
            result = checker.check()

        assert result["available"] == "False"
        assert "Node.js" in result["name"]
        # 缺省时给出 winget 或通用提示
        assert "node" in result["install_hint"].lower()

    def test_available(self) -> None:
        with patch.object(
            env_check.shutil, "which", return_value="/usr/bin/node"
        ), patch.object(
            env_check, "_run_version_cmd", return_value="Node.js v20.11.0"
        ):
            checker = NodeJSExtendedChecker()
            result = checker.check()

        assert result["available"] == "True"
        assert result["version"] == "20.11.0"


# ──────────────────────────────────────────────────────
# run_env_audit 集成
# ──────────────────────────────────────────────────────


class TestRunEnvAudit:
    """run_env_audit 集成测试。"""

    def test_run_with_defaults_returns_markdown(self) -> None:
        """未传 output_path —— 应返回字符串且包含必要章节标题。"""
        with patch.object(
            env_check, "ScannerChecker"
        ) as mock_checker_cls, patch.object(
            env_check, "LibreOfficeChecker"
        ) as mock_lo_cls, patch.object(
            env_check, "NodeJSExtendedChecker"
        ) as mock_node_cls:

            mock_checker = MagicMock()
            mock_checker.check_all.return_value = [
                ScannerResult(
                    name="semgrep", available=True, version="1.55",
                    install_hint="已就绪", reason="SAST",
                ),
            ]
            mock_checker_cls.return_value = mock_checker

            mock_lo = MagicMock()
            mock_lo.check.return_value = {
                "name": "LibreOffice", "available": "False",
                "version": "", "install_hint": "winget install ...",
                "reason": "DOCX 渲染",
            }
            mock_lo_cls.return_value = mock_lo

            mock_node = MagicMock()
            mock_node.check.return_value = {
                "name": "Node.js", "available": "True",
                "version": "20.0", "install_hint": "已就绪",
                "reason": "JS 解析",
            }
            mock_node_cls.return_value = mock_node

            md = run_env_audit(output_path=None)

        assert "# 玄鉴AI" in md or "## 1." in md
        assert "常用扫描器" in md or "LibreOffice" in md
        assert "fp-sentinel[scanners]" in md

    def test_run_with_output_path_writes_file(self, tmp_path) -> None:
        """传了 output_path —— 应写入文件。"""
        out = tmp_path / "report.md"
        with patch.object(
            env_check, "ScannerChecker"
        ) as mock_checker_cls, patch.object(
            env_check, "LibreOfficeChecker"
        ) as mock_lo_cls, patch.object(
            env_check, "NodeJSExtendedChecker"
        ) as mock_node_cls:

            mock_checker = MagicMock()
            mock_checker.check_all.return_value = []
            mock_checker_cls.return_value = mock_checker

            mock_lo = MagicMock()
            mock_lo.check.return_value = {
                "name": "LibreOffice", "available": "False",
                "version": "", "install_hint": "winget ...",
                "reason": "渲染",
            }
            mock_lo_cls.return_value = mock_lo

            mock_node = MagicMock()
            mock_node.check.return_value = {
                "name": "Node.js", "available": "True",
                "version": "20", "install_hint": "已就绪",
                "reason": "JS",
            }
            mock_node_cls.return_value = mock_node

            run_env_audit(output_path=str(out))

        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "依赖" in content or "报告" in content
