"""
BlackDex CLI 封装

工具地址: https://github.com/CodingGay/BlackDex
BlackDex 是免 root 的 Android 脱壳 App；桌面端封装形态：
通过 adb 触发 BlackDex 的脱壳任务，再从设备拉取脱出的 dex。

调用形态（全部本地 subprocess，shell=False）::

    adb [-s <device>] shell am start -n top.niunaijun.blackdexa64/.MainActivity
    adb [-s <device>] pull <remote_dir> <local_dir>

安全红线：
- S1: adb 连接仅允许本地 adb server；远程地址必须经 assert_local 守卫
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from fp_sentinel.mobile_shell.core.base import assert_local

logger = logging.getLogger(__name__)


class BlackDexNotAvailable(RuntimeError):
    """BlackDex 依赖不可用（adb 不在 PATH 或设备未连接）。"""


class BlackDex:
    """BlackDex 脱壳封装（免 root，adb 触发）。"""

    ADB_NAME = "adb"
    #: BlackDex 常见包名（32/64 位双 App）
    BLACKDEX_PACKAGES = (
        "top.niunaijun.blackdexa64",
        "top.niunaijun.blackdexa32",
    )

    @property
    def available(self) -> bool:
        """adb 是否在 PATH 中。"""
        return shutil.which(self.ADB_NAME) is not None

    def build_dump_command(
        self,
        package: str,
        device_id: Optional[str] = None,
        remote_host: Optional[str] = None,
    ) -> List[str]:
        """构建触发 BlackDex 脱壳的 adb 命令。

        Raises:
            UnsafeTargetError: remote_host 非 localhost（S1）
        """
        cmd: List[str] = [self.ADB_NAME]
        if remote_host:
            assert_local(remote_host)  # S1 红线
            cmd += ["-H", remote_host]
        elif device_id:
            cmd += ["-s", device_id]
        cmd += ["shell", "am", "start", "-a", "android.intent.action.VIEW", "-p", package]
        return cmd

    def build_pull_command(
        self,
        remote_dir: str,
        local_dir: str,
        device_id: Optional[str] = None,
        remote_host: Optional[str] = None,
    ) -> List[str]:
        """构建拉取脱出文件的 adb 命令。

        Raises:
            UnsafeTargetError: remote_host 非 localhost（S1）
        """
        cmd: List[str] = [self.ADB_NAME]
        if remote_host:
            assert_local(remote_host)  # S1 红线
            cmd += ["-H", remote_host]
        elif device_id:
            cmd += ["-s", device_id]
        cmd += ["pull", remote_dir, local_dir]
        return cmd

    def dump(
        self,
        package: str,
        output_dir: str,
        device_id: Optional[str] = None,
        remote_host: Optional[str] = None,
        remote_dir: str = "/sdcard/BlackDex/",
        timeout_sec: int = 120,
    ) -> Path:
        """触发 BlackDex 脱壳并拉取结果。

        Args:
            package:     目标包名
            output_dir:  本地输出目录
            device_id:   USB 设备 ID
            remote_host: adb 远程地址（仅 localhost）
            remote_dir:  设备端 BlackDex 输出目录
            timeout_sec: 单命令超时

        Returns:
            Path: 本地产出目录

        Raises:
            BlackDexNotAvailable: adb 不可用或设备未连接
            UnsafeTargetError: remote_host 非 localhost（S1）
        """
        if not self.available:
            raise BlackDexNotAvailable("adb 未安装或不在 PATH")
        out = Path(output_dir) / package / "blackdex"
        out.mkdir(parents=True, exist_ok=True)

        trigger = self.build_dump_command(package, device_id, remote_host)
        logger.info("触发 BlackDex: %s", " ".join(trigger))
        proc = subprocess.run(  # noqa: S603 - adb + shell=False
            trigger, capture_output=True, text=True,
            timeout=timeout_sec, shell=False, check=False,
        )
        if proc.returncode != 0:
            raise BlackDexNotAvailable(
                f"BlackDex 触发失败: {(proc.stderr or proc.stdout or '').strip()[:300]}"
            )

        pull = self.build_pull_command(remote_dir, str(out), device_id, remote_host)
        logger.info("拉取结果: %s", " ".join(pull))
        proc = subprocess.run(  # noqa: S603 - adb + shell=False
            pull, capture_output=True, text=True,
            timeout=timeout_sec, shell=False, check=False,
        )
        if proc.returncode != 0:
            logger.warning("adb pull 失败: %s", (proc.stderr or "").strip()[:300])
        return out

    @staticmethod
    def list_dumped_dex(dump_dir: str | Path) -> List[Path]:
        """列出拉取结果中的 dex 文件。"""
        p = Path(dump_dir)
        if not p.is_dir():
            return []
        return sorted(p.glob("**/*.dex"), key=lambda f: f.name)
