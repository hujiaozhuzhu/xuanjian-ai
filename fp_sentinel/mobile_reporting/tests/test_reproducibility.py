"""core.reproducibility 单元测试：环境采集与双平台复现脚本生成。"""

from __future__ import annotations

import hashlib
import sys
import types
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _ensure_reporting_importable() -> None:
    """formats.excel_generator 由并行开发提供，缺失时注入最小存根保证可导入。"""
    try:
        import fp_sentinel.mobile_reporting  # noqa: F401
    except ModuleNotFoundError:
        for name in [
            k for k in sys.modules if k.startswith("fp_sentinel.mobile_reporting")
        ]:
            del sys.modules[name]
        stub = types.ModuleType(
            "fp_sentinel.mobile_reporting.formats.excel_generator"
        )
        stub.OPENPYXL_AVAILABLE = False  # type: ignore[attr-defined]
        stub.ExcelReportGenerator = type(  # type: ignore[attr-defined]
            "ExcelReportGenerator", (), {}
        )
        sys.modules[stub.__name__] = stub
        import fp_sentinel.mobile_reporting  # noqa: F401


_ensure_reporting_importable()

from fp_sentinel.mobile_reporting.core.reproducibility import (  # noqa: E402
    ReproducibilityManager,
)
from fp_sentinel.mobile_reporting.formats.base_generator import (  # noqa: E402
    PathNotAllowedError,
)
from fp_sentinel.mobile_reporting.models import (  # noqa: E402
    EnvironmentInfo,
    FindingReport,
    MobileSecurityReport,
    ReportMetadata,
    ReproStep,
    TargetAppInfo,
)

SCAN_COMMAND = "fp_sentinel insight scan demo.apk --sensitive"


def _target_file(tmp_path: Path) -> Path:
    """构造带确定内容的目标 APK 假文件。"""
    target = tmp_path / "demo.apk"
    target.write_bytes(b"PK\x03\x04fake-apk-content")
    return target


def _sample_report(target: TargetAppInfo) -> MobileSecurityReport:
    """构造带环境与复现步骤的示例报告。"""
    finding = FindingReport(
        id="VUL-001",
        title="硬编码凭据",
        severity="HIGH",
        description="d",
        repro_steps=[
            ReproStep(
                step_no=1,
                action="反编译并搜索关键字",
                expected_result="命中硬编码口令",
                command="apktool d demo.apk -o out && grep -rn password out/",
            )
        ],
    )
    return MobileSecurityReport(
        metadata=ReportMetadata(title="演示报告", version="V1.0"),
        environment=EnvironmentInfo(
            os="Windows", python_version="3.12.1", target_app=target,
            scan_command=SCAN_COMMAND,
        ),
        findings=[finding],
    )


class TestCaptureEnvironment:
    """环境采集测试。"""

    def test_capture_with_target(self, tmp_path: Path) -> None:
        """目标文件 SHA256 与大小正确采集。"""
        target = _target_file(tmp_path)
        env = ReproducibilityManager().capture_environment(
            target, scan_command=SCAN_COMMAND
        )
        expected = hashlib.sha256(target.read_bytes()).hexdigest()
        assert env.target_app is not None
        assert env.target_app.name == "demo"
        assert env.target_app.sha256 == expected
        assert env.target_app.file_size == target.stat().st_size
        assert env.os
        assert "3." in env.python_version
        assert env.scan_command == SCAN_COMMAND
        assert env.scan_time
        assert "fp_sentinel" in env.tool_versions

    def test_capture_missing_target(self, tmp_path: Path) -> None:
        """目标缺失时降级为空哈希而不抛异常。"""
        env = ReproducibilityManager().capture_environment(
            tmp_path / "ghost.apk", scan_command=""
        )
        assert env.target_app is not None
        assert env.target_app.sha256 == ""
        assert env.target_app.file_size == 0


class TestBuildReproScript:
    """复现脚本生成测试。"""

    def test_generates_bash_and_powershell(self, tmp_path: Path) -> None:
        """bash 与 PowerShell 双版本脚本均生成且内容完整。"""
        target = TargetAppInfo(
            name="demo.apk", sha256="a" * 64, file_size=1234
        )
        report = _sample_report(target)
        out = tmp_path / "repro.sh"
        result = ReproducibilityManager(allowed_roots=[tmp_path]).build_repro_script(
            report, out
        )
        assert result == str(out)
        bash = Path(result).read_text(encoding="utf-8")
        ps1 = Path(tmp_path / "repro.ps1").read_text(encoding="utf-8")
        # 环境校验步骤
        assert "python3 --version" in bash
        assert "a" * 64 in bash
        assert "sha256sum" in bash
        assert "Get-FileHash" in ps1
        assert "a" * 64 in ps1
        # 逐步命令（DRY-RUN 保护）
        assert "apktool d demo.apk" in bash
        assert "DRY-RUN" in bash
        assert "RUN_SCAN" in bash
        assert "Invoke-Expression" in ps1
        # 预期输出校验点
        assert "[CHECK] 预期: 命中硬编码口令" in bash
        assert "命中硬编码口令" in ps1
        # 扫描命令回放
        assert SCAN_COMMAND in bash
        assert SCAN_COMMAND in ps1

    def test_report_without_environment(self, tmp_path: Path) -> None:
        """无环境信息的报告也能生成脚本。"""
        report = MobileSecurityReport(findings=[])
        out = ReproducibilityManager(allowed_roots=[tmp_path]).build_repro_script(
            report, tmp_path / "bare.sh"
        )
        assert Path(out).is_file()
        assert Path(tmp_path / "bare.ps1").is_file()

    def test_output_outside_whitelist_rejected(self, tmp_path: Path) -> None:
        """输出路径逃逸白名单时抛出 PathNotAllowedError（S7 红线）。"""
        manager = ReproducibilityManager(allowed_roots=[tmp_path / "allowed"])
        (tmp_path / "allowed").mkdir()
        report = MobileSecurityReport(findings=[])
        with pytest.raises(PathNotAllowedError):
            manager.build_repro_script(report, tmp_path / "outside.sh")

    def test_bad_suffix_rejected(self, tmp_path: Path) -> None:
        """非脚本后缀被拒绝（S7 红线）。"""
        manager = ReproducibilityManager(allowed_roots=[tmp_path])
        report = MobileSecurityReport(findings=[])
        with pytest.raises(PathNotAllowedError):
            manager.build_repro_script(report, tmp_path / "report.exe")


class TestScriptInjectionSafety:
    """复现脚本对外部可控字符串的转义回归（不执行脚本）。"""

    EVIL_COMMAND = 'fp_sentinel scan $(id) `whoami` demo.apk "; rm -rf /; "'
    EVIL_TITLE = '标题"; rm -rf /; "'

    def _evil_report(self) -> MobileSecurityReport:
        """构造携带注入 payload 的示例报告。"""
        target = TargetAppInfo(name='de"mo$(id).apk', sha256="a" * 64)
        finding = FindingReport(
            id='VUL-1"; rm -rf /; "',
            title=self.EVIL_TITLE,
            severity="HIGH",
            description="d",
            repro_steps=[
                ReproStep(
                    step_no=1,
                    action="a",
                    expected_result='预期"; rm -rf /; "$(id)',
                    command=self.EVIL_COMMAND,
                )
            ],
        )
        return MobileSecurityReport(
            metadata=ReportMetadata(title="注入回归", version="V1.0"),
            environment=EnvironmentInfo(
                os="Windows", python_version="3.12", target_app=target,
                scan_command=self.EVIL_COMMAND,
            ),
            findings=[finding],
        )

    def test_bash_dry_run_escapes_injection(self, tmp_path: Path) -> None:
        """危险命令触发安全红线：禁用自动执行，仅留转义预览与人工审核提示。"""
        out = ReproducibilityManager(allowed_roots=[tmp_path]).build_repro_script(
            self._evil_report(), tmp_path / "repro.sh"
        )
        bash = Path(out).read_text(encoding="utf-8")
        # 危险命令（scan_command 与 step.command 均含元字符）禁用自动执行：
        # 不存在任何 RUN_SCAN 可执行分支，仅保留审核提示
        assert "[SKIP-DANGER]" in bash
        assert "[DRY-RUN]" not in bash
        assert 'if [ "${RUN_SCAN:-0}" = "1" ]; then' not in bash
        # 原始（未转义）注入命令不得出现在脚本任何可执行位置
        for line in bash.splitlines():
            if line.strip().startswith("#") or "SKIP-DANGER" in line:
                continue
            assert self.EVIL_COMMAND not in line
            assert line.count('\\"') >= 0  # 占位：转义引号允许出现
        # 所有双引号 echo 行内引号必须成对闭合（防止提前终止字符串）
        for line in bash.splitlines():
            if line.startswith('echo "'):
                assert line.count('"') % 2 == 0, f"引号未闭合: {line}"
        # 危险 payload 以转义字面量形式保留在注释预览中
        assert "\\$(id)" in bash
        assert "\\`whoami\\`" in bash

    def test_bash_safe_command_still_executable(self, tmp_path: Path) -> None:
        """不含元字符的干净命令保留 RUN_SCAN 自动执行分支。"""
        target = TargetAppInfo(name="demo.apk", sha256="a" * 64)
        finding = FindingReport(
            id="VUL-1", title="t", severity="HIGH", description="d",
            repro_steps=[ReproStep(
                step_no=1, action="a",
                command="fp_sentinel insight scan demo.apk --sensitive",
            )],
        )
        report = MobileSecurityReport(
            metadata=ReportMetadata(title="正常", version="V1.0"),
            environment=EnvironmentInfo(
                os="Windows", python_version="3.12", target_app=target,
                scan_command="fp_sentinel insight scan demo.apk",
            ),
            findings=[finding],
        )
        out = ReproducibilityManager(allowed_roots=[tmp_path]).build_repro_script(
            report, tmp_path / "repro.sh"
        )
        bash = Path(out).read_text(encoding="utf-8")
        assert 'if [ "${RUN_SCAN:-0}" = "1" ]; then' in bash
        assert "fp_sentinel insight scan demo.apk --sensitive" in bash
        assert "[DRY-RUN]" in bash

    def test_bash_target_and_sha_escaped(self, tmp_path: Path) -> None:
        """bash 侧 target.name 与 expected_sha 嵌入前经过 dq 转义。"""
        out = ReproducibilityManager(allowed_roots=[tmp_path]).build_repro_script(
            self._evil_report(), tmp_path / "repro.sh"
        )
        bash = Path(out).read_text(encoding="utf-8")
        # target.name 的双引号与命令替换在双引号内被转义
        assert 'TARGET_FILE="${TARGET_FILE:-de\\"mo\\$(id).apk}"' in bash
        assert f'EXPECTED_SHA256="{"a" * 64}"' in bash

    def test_ps1_escapes_injection(self, tmp_path: Path) -> None:
        """PowerShell 侧：危险命令禁用 Invoke-Expression，嵌入字符串经 sq 转义。"""
        out = ReproducibilityManager(allowed_roots=[tmp_path]).build_repro_script(
            self._evil_report(), tmp_path / "repro.ps1"
        )
        ps1 = Path(out).read_text(encoding="utf-8")
        # 危险命令不进入 Invoke-Expression 执行分支
        assert "[SKIP-DANGER]" in ps1
        assert "Invoke-Expression" not in ps1
        # finding 标题/ID 与 target.name / expected_sha 嵌入均经 sq 转义
        header_lines = [
            line for line in ps1.splitlines()
            if line.startswith("Write-Host '---")
        ]
        assert header_lines
        for line in header_lines:
            assert line.count("'") % 2 == 0
        for line in ps1.splitlines():
            if "$expectedSha256 = " in line or "$targetFile = '" in line:
                assert line.count("'") % 2 == 0
