"""可复现性保障管理器。

ReproducibilityManager 负责：

1. capture_environment: 自动采集扫描环境（操作系统 / Python / 依赖版本 /
   目标 APK 的 SHA256 与文件大小），生成 :class:`EnvironmentInfo`；
2. build_repro_script: 生成 bash + PowerShell 双版本复现脚本
   （含环境校验步骤、逐步命令、预期输出校验点），
   输出路径严格遵循 S7 白名单（复用 formats/base_generator.py 的
   PathNotAllowedError 校验逻辑）。
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import logging
import platform
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Union

from ..formats.base_generator import BaseReportGenerator, PathNotAllowedError
from ..models.report_models import EnvironmentInfo, MobileSecurityReport, TargetAppInfo

__all__ = ["ReproducibilityManager", "PathNotAllowedError"]

logger = logging.getLogger(__name__)

#: 复现脚本允许的输出后缀
SCRIPT_SUFFIXES = (".sh", ".ps1")

#: 需要采集版本号的关键依赖（缺失时静默跳过）
KNOWN_DEPENDENCIES = (
    "frida",
    "frida-tools",
    "androguard",
    "click",
    "rich",
)

#: 依赖采集失败时的占位版本号
_VERSION_UNKNOWN = "unavailable"


class _ScriptPathGuard(BaseReportGenerator):
    """复用 S7 白名单校验的路径守卫（仅用于复现脚本输出路径校验）。"""

    def __init__(self, allowed_roots: Optional[Iterable[Union[str, Path]]]) -> None:
        super().__init__(
            allowed_roots=allowed_roots, allowed_suffixes=list(SCRIPT_SUFFIXES)
        )

    def generate(self, report: MobileSecurityReport, output_path: Path) -> Path:  # noqa: ARG002
        """占位实现：本守卫只负责路径校验，不生成报告。"""
        return Path(output_path)

    def get_format_name(self) -> str:
        """返回格式名称。"""
        return "ReproScript"


class ReproducibilityManager:
    """可复现性保障管理器。

    Args:
        allowed_roots: 复现脚本输出路径的白名单根目录集合；
            为空时默认仅允许当前工作目录。
    """

    def __init__(
        self, allowed_roots: Optional[Iterable[Union[str, Path]]] = None
    ) -> None:
        self._guard = _ScriptPathGuard(allowed_roots)

    # ─────────────────────────── 环境采集 ────────────────────────

    def capture_environment(
        self,
        target_path: Union[str, Path],
        scan_command: str = "",
    ) -> EnvironmentInfo:
        """采集当前扫描环境与目标文件信息。

        Args:
            target_path: 目标 APK/IPA 文件路径。
            scan_command: 本次评估使用的扫描命令（原样记录，不执行）。

        Returns:
            EnvironmentInfo: 环境信息（目标文件缺失时 sha256/大小为 0 值并告警）。
        """
        path = Path(target_path)
        sha256 = ""
        file_size = 0
        if path.is_file():
            sha256 = self._file_sha256(path)
            file_size = path.stat().st_size
        else:
            logger.warning("目标文件不存在，环境信息中缺少其哈希: %s", path)
        target_app = TargetAppInfo(
            name=path.stem,
            package="",
            version="",
            sha256=sha256,
            file_size=file_size,
        )
        env = EnvironmentInfo(
            os=platform.platform(),
            python_version=f"{sys.version.split()[0]} ({platform.python_implementation()})",
            tool_versions=self._collect_tool_versions(),
            target_app=target_app,
            scan_time=datetime.now().isoformat(timespec="seconds"),
            scan_command=scan_command,
        )
        logger.info("环境信息采集完成: 目标=%s sha256=%s", path.name, sha256[:16])
        return env

    # ─────────────────────────── 复现脚本 ────────────────────────

    def build_repro_script(
        self,
        report: MobileSecurityReport,
        output_path: Union[str, Path],
    ) -> str:
        """生成 bash + PowerShell 双版本复现脚本。

        脚本内容包含：环境校验步骤（Python 版本 / 目标文件 SHA256 比对）、
        每个 finding 的逐步复现命令、预期输出校验点。
        默认以 DRY-RUN 模式仅打印命令，设置 ``RUN_SCAN=1`` 后才实际执行，
        避免误触发扫描。

        Args:
            report: 移动安全报告（复现命令来自 finding.repro_steps）。
            output_path: bash 脚本输出路径（``.sh``，须通过 S7 白名单校验；
                同名 ``.ps1`` PowerShell 版本写入同目录）。

        Returns:
            str: bash 脚本的实际输出路径。

        Raises:
            PathNotAllowedError: 输出路径逃逸出白名单或后缀不被允许。
        """
        bash_path = self._guard.validate_output_path(output_path)
        ps1_path = self._guard.validate_output_path(
            bash_path.with_suffix(".ps1")
        )
        target = report.environment.target_app if report.environment else None
        scan_command = (
            report.environment.scan_command if report.environment else ""
        )
        expected_sha = target.sha256 if target else ""

        bash_lines = self._build_bash_lines(
            report, target, scan_command, expected_sha
        )
        ps1_lines = self._build_ps1_lines(
            report, target, scan_command, expected_sha
        )
        bash_path.write_text("\n".join(bash_lines) + "\n", encoding="utf-8")
        ps1_path.write_text("\n".join(ps1_lines) + "\n", encoding="utf-8")
        logger.info("复现脚本已生成: %s 与 %s", bash_path, ps1_path)
        return str(bash_path)

    # ─────────────────────────── 内部工具 ────────────────────────

    @staticmethod
    def _file_sha256(path: Path) -> str:
        """流式计算文件 SHA256。"""
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _collect_tool_versions() -> "dict[str, str]":
        """采集关键依赖版本（缺失时标记 unavailable）。"""
        versions = {"fp_sentinel": _probe_fp_sentinel_version()}
        for name in KNOWN_DEPENDENCIES:
            try:
                versions[name] = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                versions[name] = _VERSION_UNKNOWN
        return versions

    def _build_bash_lines(
        self,
        report: MobileSecurityReport,
        target: Optional[TargetAppInfo],
        scan_command: str,
        expected_sha: str,
    ) -> List[str]:
        """构建 bash 复现脚本行。"""
        lines: List[str] = [
            "#!/usr/bin/env bash",
            "# 玄鉴AI (fp_sentinel) 移动安全评估复现脚本（自动生成）",
            f"# 报告: {report.metadata.title} {report.metadata.version}",
            "# 用法: RUN_SCAN=1 bash repro.sh  （默认 DRY-RUN 仅打印命令）",
            "set -euo pipefail",
            "",
            'echo "[1/3] 环境校验"',
            "python3 --version",
            'TARGET_FILE="${TARGET_FILE:-'
            + self._escape_dq(target.name if target else "target.apk")
            + '}"',
        ]
        if expected_sha:
            lines += [
                'EXPECTED_SHA256="' + self._escape_dq(expected_sha) + '"',
                'ACTUAL_SHA256="$(sha256sum "${TARGET_FILE}" | awk \'{print $1}\')"',
                'if [ "${ACTUAL_SHA256}" != "${EXPECTED_SHA256}" ]; then',
                '  echo "[FAIL] 目标文件 SHA256 不匹配: ${ACTUAL_SHA256}" && exit 2',
                "fi",
                'echo "[OK] 目标文件 SHA256 校验通过"',
            ]
        lines += ["", 'echo "[2/3] 复现扫描"']
        if scan_command:
            lines.extend(self._bash_cmd(scan_command))
        for finding in report.findings:
            header = self._escape_dq(
                f"--- {finding.id}: {finding.title} [{finding.severity}] ---"
            )
            lines.append(f'echo "{header}"')
            for step in finding.repro_steps:
                if step.command:
                    lines.extend(self._bash_cmd(step.command))
                if step.expected_result:
                    lines.append(
                        f'echo "[CHECK] 预期: {self._escape_dq(step.expected_result)}"'
                    )
        lines += ["", 'echo "[3/3] 复现完成，请人工核对上述 [CHECK] 校验点"']
        return lines

    def _build_ps1_lines(
        self,
        report: MobileSecurityReport,
        target: Optional[TargetAppInfo],
        scan_command: str,
        expected_sha: str,
    ) -> List[str]:
        """构建 PowerShell 复现脚本行。"""
        lines: List[str] = [
            "# 玄鉴AI (fp_sentinel) 移动安全评估复现脚本（自动生成）",
            f"# 报告: {report.metadata.title} {report.metadata.version}",
            "# 用法: $env:RUN_SCAN = '1'; .\\repro.ps1  （默认 DRY-RUN 仅打印命令）",
            "",
            'Write-Host "[1/3] 环境校验"',
            "python --version",
            "$targetFile = $env:TARGET_FILE",
            "if (-not $targetFile) { $targetFile = '"
            + self._escape_sq(target.name if target else "target.apk")
            + "' }",
        ]
        if expected_sha:
            lines += [
                f"$expectedSha256 = '{self._escape_sq(expected_sha)}'",
                "$actualSha256 = (Get-FileHash -Algorithm SHA256 $targetFile).Hash.ToLower()",
                "if ($actualSha256 -ne $expectedSha256) {",
                '  Write-Host "[FAIL] 目标文件 SHA256 不匹配: $actualSha256"; exit 2',
                "}",
                'Write-Host "[OK] 目标文件 SHA256 校验通过"',
            ]
        lines += ["", 'Write-Host "[2/3] 复现扫描"']
        if scan_command:
            lines.append(self._ps1_cmd(scan_command))
        for finding in report.findings:
            header = self._escape_sq(
                f"--- {finding.id}: {finding.title} [{finding.severity}] ---"
            )
            lines.append(f"Write-Host '{header}'")
            for step in finding.repro_steps:
                if step.command:
                    lines.append(self._ps1_cmd(step.command))
                if step.expected_result:
                    expected = self._escape_sq(step.expected_result)
                    lines.append(f"Write-Host '[CHECK] 预期: {expected}'")
        lines += ["", 'Write-Host "[3/3] 复现完成，请人工核对上述 [CHECK] 校验点"']
        return lines

    #: shell 元字符/危险特征：命中即禁用自动执行（安全红线，与 POC 模块一致）
    _DANGEROUS_CMD_RE = re.compile(
        r"[;&|`]|\$\(|\$\{|\$\w|\brm\s+-rf\b|\n|\r",
        re.IGNORECASE,
    )

    @staticmethod
    def _bash_cmd(command: str) -> List[str]:
        """把扫描命令包装为 DRY-RUN 安全的 bash 行（多行 if/else 块）。

        安全红线：命令来自扫描产物（外部可控）。含 shell 元字符或危险
        特征（命令替换、管道、分号、``rm -rf`` 等）的命令一律禁用
        自动执行，仅输出转义预览与人工审核提示；只有不含任何元字符
        的干净命令才允许在 ``RUN_SCAN=1`` 时原样执行。
        """
        safe = ReproducibilityManager._escape_dq(command)
        if ReproducibilityManager._DANGEROUS_CMD_RE.search(command):
            return [
                "# [安全红线] 命令含危险特征（shell 元字符/rm -rf 等），",
                "# 已禁用自动执行，请人工审核后手动运行：",
                f"#   {safe}",
                'echo "[SKIP-DANGER] 该命令未自动执行，请人工审核"',
            ]
        return [
            'if [ "${RUN_SCAN:-0}" = "1" ]; then',
            command,
            "else",
            f'  echo "[DRY-RUN] {safe}"',
            "fi",
        ]

    @staticmethod
    def _ps1_cmd(command: str) -> str:
        """把扫描命令包装为 DRY-RUN 安全的 PowerShell 行。

        与 bash 侧一致：含危险特征的命令禁用 ``Invoke-Expression``，
        仅输出预览与人工审核提示。
        """
        safe = command.replace("'", "''")
        if ReproducibilityManager._DANGEROUS_CMD_RE.search(command):
            return (
                "# [安全红线] 命令含危险特征，已禁用自动执行，请人工审核： "
                + safe
                + " ; Write-Host '[SKIP-DANGER] 该命令未自动执行，请人工审核'"
            )
        return (
            "if ($env:RUN_SCAN -eq '1') { Invoke-Expression '" + safe + "' } "
            "else { Write-Host '[DRY-RUN] " + safe + "' }"
        )

    @staticmethod
    def _escape_dq(text: str) -> str:
        """转义 bash 双引号字符串中的特殊字符。

        先转义反斜杠，再处理反引号 / ``$`` / 双引号，换行与回车
        改写为字面量，防止命令替换、变量展开与引号逃逸。
        """
        return (
            text.replace("\\", "\\\\")
            .replace("`", "\\`")
            .replace("$", "\\$")
            .replace('"', '\\"')
            .replace("\r", "\\r")
            .replace("\n", "\\n")
        )

    @staticmethod
    def _escape_sq(text: str) -> str:
        """转义 PowerShell 单引号字符串。"""
        return text.replace("'", "''")


def _probe_fp_sentinel_version() -> str:
    """探测 fp_sentinel 版本号，失败时返回未知标记。"""
    try:
        import fp_sentinel

        return str(getattr(fp_sentinel, "__version__", _VERSION_UNKNOWN))
    except Exception:  # noqa: BLE001 - 版本探测失败不应影响主流程
        return _VERSION_UNKNOWN
