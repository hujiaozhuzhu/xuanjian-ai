"""
脱壳结果数据模型 —— DumpResult / DumpTarget / DumpConfig

对齐《v4.0.0-mobile-reverse-engineering-plan.md》2.1.3 核心接口：
- DumpTarget : 脱壳目标（本地文件路径 + 可选包名/设备）
- DumpConfig : 脱壳配置（输出目录 / 设备 / 超时 / 模式）
- DumpResult : 脱壳结果（成功标记 / 哈希 / 加固类型 / 日志）

安全红线：所有字段均为本地路径或枚举，不携带任何远程地址。
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional


class Platform(str, Enum):
    """目标平台。"""

    ANDROID = "android"
    IOS = "ios"


class FileFormat(str, Enum):
    """脱壳输入/输出文件格式。"""

    APK = "apk"
    IPA = "ipa"
    DEX = "dex"
    MACHO = "macho"


class DumpMode(str, Enum):
    """脱壳执行模式。

    - FRIDA   : 通过 frida-dexdump / frida-ios-dump 动态脱壳（需设备）
    - STATIC  : 基于 androguard 的静态检测/提取降级模式（无设备）
    - DETECT  : 仅检测模式（iOS 无越狱设备时的降级）
    """

    FRIDA = "frida"
    STATIC = "static"
    DETECT = "detect"


def sha256_file(path: str) -> str:
    """计算文件 SHA256（分块读取，支持大文件）。

    Args:
        path: 本地文件路径

    Returns:
        64 位十六进制 SHA256 字符串；文件不存在时返回空字符串。
    """
    p = Path(path)
    if not p.is_file():
        return ""
    digest = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class DumpTarget:
    """脱壳目标。

    Attributes:
        path:         本地文件路径（APK/IPA/DEX/Mach-O）；仅设备目标时可为包名占位
        package:      可选包名（如 com.target.app），iOS 按包名 dump 时使用
        device_id:    可选本地设备标识（frida device id / udid）
        remote_host:  可选 frida 远程地址；S1 红线仅允许 127.0.0.1/localhost
        platform_hint: 可选平台覆盖（仅设备目标时用于 ios 包名模式）
    """

    path: str
    package: Optional[str] = None
    device_id: Optional[str] = None
    remote_host: Optional[str] = None
    platform_hint: Optional[Platform] = None

    def __post_init__(self) -> None:
        p = Path(self.path)
        if not p.is_file():
            if self.package and not p.exists():
                # 仅设备目标（如 iOS 按包名 dump），路径无文件语义，放行
                return
            raise FileNotFoundError(f"脱壳目标不存在: {self.path}")
        suffix = p.suffix.lower().lstrip(".")
        if suffix not in {"apk", "ipa", "dex", ""}:
            raise ValueError(f"不支持的文件格式: {p.suffix!r} (支持 apk/ipa/dex)")

    @property
    def is_device_only(self) -> bool:
        """是否为仅设备目标（无本地文件，按包名 dump）。"""
        return not Path(self.path).is_file()

    @property
    def suffix(self) -> str:
        """文件后缀（小写，无点）。"""
        return Path(self.path).suffix.lower().lstrip(".")

    @property
    def platform(self) -> Platform:
        """根据后缀推断平台（platform_hint 优先）。"""
        if self.platform_hint is not None:
            return self.platform_hint
        if self.suffix == "ipa":
            return Platform.IOS
        return Platform.ANDROID

    @property
    def file_format(self) -> FileFormat:
        """根据后缀推断文件格式。"""
        mapping = {
            "apk": FileFormat.APK,
            "ipa": FileFormat.IPA,
            "dex": FileFormat.DEX,
        }
        if self.platform_hint == Platform.IOS and self.suffix not in mapping:
            return FileFormat.MACHO
        return mapping.get(self.suffix, FileFormat.APK)


@dataclass
class DumpConfig:
    """脱壳配置。

    Attributes:
        output_dir:    输出目录（默认 ./reports/mobile_shell/）
        timeout_sec:   单次脱壳超时（秒）
        mode:          执行模式；默认 STATIC = 静态降级，FRIDA = 动态脱壳
        keep_dex_only: 仅保留脱出的 dex 文件
        max_dex_count: 最多保留的 dex 数量（防止磁盘膨胀）
        extra_args:    传给底层 CLI 的额外参数
    """

    output_dir: str = "./reports/mobile_shell/"
    timeout_sec: int = 300
    mode: DumpMode = DumpMode.STATIC
    keep_dex_only: bool = True
    max_dex_count: int = 64
    extra_args: List[str] = field(default_factory=list)


@dataclass
class DumpResult:
    """脱壳结果。"""

    success: bool
    original_path: str
    dumped_path: Optional[str] = None
    protection_type: str = "unknown"
    platform: Platform = Platform.ANDROID
    file_format: FileFormat = FileFormat.APK
    mode: DumpMode = DumpMode.STATIC
    sha256_before: str = ""
    sha256_after: str = ""
    duration_sec: float = 0.0
    dex_count: int = 0
    logs: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def log(self, message: str) -> None:
        """追加一条日志。"""
        self.logs.append(message)

    def warn(self, message: str) -> None:
        """追加一条警告。"""
        self.warnings.append(message)

    @classmethod
    def from_target(
        cls,
        target: DumpTarget,
        protection_type: str = "unknown",
        mode: DumpMode = DumpMode.STATIC,
    ) -> "DumpResult":
        """从目标构建初始结果（自动计算原始哈希）。"""
        return cls(
            success=False,
            original_path=target.path,
            protection_type=protection_type,
            platform=target.platform,
            file_format=target.file_format,
            mode=mode,
            sha256_before=sha256_file(target.path),
        )

    def finalize(self, started_at: float) -> "DumpResult":
        """结束计时并固化耗时。"""
        self.duration_sec = round(time.time() - started_at, 3)
        return self
