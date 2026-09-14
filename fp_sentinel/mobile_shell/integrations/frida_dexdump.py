"""
frida-dexdump CLI 封装

工具地址: https://github.com/hluwa/FRIDA-DEXDump
调用形态（全部本地 subprocess，shell=False）::

    frida-dexdump -U -f <package> -o <output_dir>
    frida-dexdump -H 127.0.0.1:27042 -f <package> -o <output_dir>

安全红线：
- S1: remote_host 必须为 127.0.0.1/localhost（assert_local 守卫）
- subprocess 一律 shell=False 且带超时
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from fp_sentinel.mobile_shell.core.base import UnsafeTargetError, assert_local

logger = logging.getLogger(__name__)


class FridaDexDumpNotAvailable(RuntimeError):
    """frida-dexdump CLI 不可用（未安装或不在 PATH）。"""


class FridaDexDump:
    """frida-dexdump CLI 封装（Android 动态脱壳）。"""

    CLI_NAME = "frida-dexdump"

    @property
    def available(self) -> bool:
        """frida-dexdump 是否在 PATH 中。"""
        return shutil.which(self.CLI_NAME) is not None

    def build_command(
        self,
        package: str,
        output_dir: str,
        device_id: Optional[str] = None,
        remote_host: Optional[str] = None,
        deep_search: bool = True,
        extra_args: Optional[List[str]] = None,
    ) -> List[str]:
        """构建 frida-dexdump 命令行（不执行）。

        Args:
            package:     目标包名
            output_dir:  输出目录
            device_id:   USB 设备 ID（frida-dexdump -D <id>）
            remote_host: frida 远程地址（S1 仅允许 localhost）
            deep_search: 深度搜索模式（-d）
            extra_args:  额外参数

        Returns:
            参数列表（shell=False 直接使用）

        Raises:
            UnsafeTargetError: remote_host 非 localhost（S1）
        """
        cmd: List[str] = [self.CLI_NAME]
        if remote_host:
            assert_local(remote_host)  # S1 红线
            cmd += ["-H", remote_host]
        elif device_id:
            cmd += ["-D", device_id]
        else:
            cmd += ["-U"]
        if deep_search:
            cmd += ["-d"]
        cmd += ["-f", package, "-o", output_dir]
        if extra_args:
            cmd += extra_args
        return cmd

    def dump(
        self,
        package: str,
        output_dir: str,
        device_id: Optional[str] = None,
        remote_host: Optional[str] = None,
        timeout_sec: int = 300,
        deep_search: bool = True,
        extra_args: Optional[List[str]] = None,
    ) -> Path:
        """执行 frida-dexdump 脱壳。

        Args:
            package:     目标包名
            output_dir:  输出目录
            device_id:   USB 设备 ID
            remote_host: frida 远程地址（仅 localhost）
            timeout_sec: 超时（秒）
            deep_search: 深度搜索
            extra_args:  额外参数

        Returns:
            Path: 脱出的 dex 所在目录

        Raises:
            FridaDexDumpNotAvailable: CLI 不可用
            subprocess.SubprocessError: 执行失败或超时
            UnsafeTargetError: remote_host 非 localhost（S1）
        """
        if not self.available:
            raise FridaDexDumpNotAvailable(
                f"{self.CLI_NAME} 未安装（pip install frida-dexdump）"
            )
        out = Path(output_dir) / package / "frida-dexdump"
        out.mkdir(parents=True, exist_ok=True)
        cmd = self.build_command(
            package=package,
            output_dir=str(out),
            device_id=device_id,
            remote_host=remote_host,
            deep_search=deep_search,
            extra_args=extra_args,
        )
        logger.info("执行: %s", " ".join(cmd))
        proc = subprocess.run(  # noqa: S603 - 白名单 CLI + shell=False
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            shell=False,
            check=False,
        )
        if proc.returncode != 0:
            raise subprocess.SubprocessError(
                f"frida-dexdump 退出码 {proc.returncode}: "
                f"{(proc.stderr or proc.stdout or '').strip()[:500]}"
            )
        return out

    @staticmethod
    def list_dumped_dex(dump_dir: str | Path) -> List[Path]:
        """列出脱出目录中的 dex 文件（按名称排序）。"""
        p = Path(dump_dir)
        if not p.is_dir():
            return []
        return sorted(p.glob("**/*.dex"), key=lambda f: f.name)
