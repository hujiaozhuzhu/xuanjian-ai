"""
ShellEngine 抽象基类 + S1 本地目标守卫

对齐《v4.0.0-mobile-reverse-engineering-plan.md》2.1.3 核心接口：

    class ShellEngine(ABC):
        detect_protection(target_path) -> ProtectionInfo
        dump(target: DumpTarget, config: DumpConfig) -> DumpResult
        get_supported_formats() -> List[str]

安全红线（v3.3.0 迭代计划）：
- S1: 禁止向非 localhost 发起任何网络请求。所有涉及远程设备/端点的入口
      必须经 :func:`assert_local` 守卫，否则抛 :class:`UnsafeTargetError`。
"""

from __future__ import annotations

import ipaddress
from abc import ABC, abstractmethod
from urllib.parse import urlparse
from typing import List

from fp_sentinel.mobile_shell.models.dump_result import (
    DumpConfig,
    DumpResult,
    DumpTarget,
    FileFormat,
)
from fp_sentinel.mobile_shell.models.protection_info import ProtectionInfo

#: S1 白名单：仅允许本地回环地址
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0", "host.docker.internal"}


class UnsafeTargetError(Exception):
    """目标不是本地地址，拒绝执行（S1 红线守卫）。"""

    def __init__(self, target: object):
        self.target = target
        super().__init__(
            f"[S1 安全红线] 拒绝非本地目标: {target!r}。"
            f"仅允许 127.0.0.1 / localhost / ::1"
        )


def assert_local(target: str) -> str:
    """S1 守卫：校验目标 host 是否为本地回环地址。

    Args:
        target: 形如 ``127.0.0.1:27042``、``http://localhost:8080``、``usb`` 的目标

    Returns:
        原样返回 target（合法时）

    Raises:
        UnsafeTargetError: 目标 host 不在本地白名单内
    """
    if not target or not isinstance(target, str):
        raise UnsafeTargetError(target)
    value = target.strip()
    lowered = value.lower()
    # 特殊形态：USB 设备 / 纯设备 ID（无网络语义）
    if lowered in {"usb", "local", "local-device"}:
        return value
    # 整体是一个 IP 地址（含 IPv6 如 "::1"、"[::1]"）
    try:
        if ipaddress.ip_address(lowered.strip("[]")).is_loopback:
            return value
    except ValueError:
        pass
    if "://" in value:
        host = (urlparse(value).hostname or "").lower()
    else:
        # host:port 形态
        host = value.rsplit(":", 1)[0].strip("/[]").lower()
    if host in LOCAL_HOSTS:
        return value
    # host 部分可能是回环 IP（如 127.0.0.2:27042）
    try:
        if ipaddress.ip_address(host).is_loopback:
            return value
    except ValueError:
        pass
    raise UnsafeTargetError(target)


class ShellEngine(ABC):
    """脱壳引擎抽象基类。

    子类必须实现：
    - :meth:`detect_protection` : 自动识别加固类型
    - :meth:`dump`              : 执行脱壳
    - :meth:`get_supported_formats` : 返回支持的文件格式
    """

    #: 引擎名称（子类覆盖）
    name: str = "shell-engine"
    #: 默认支持的平台（子类覆盖）
    platform: str = "unknown"

    @abstractmethod
    def detect_protection(self, target_path: str) -> ProtectionInfo:
        """自动识别加固类型。

        Args:
            target_path: 本地 APK/IPA 文件路径

        Returns:
            ProtectionInfo: 识别结果（含置信度与命中特征）
        """

    @abstractmethod
    def dump(self, target: DumpTarget, config: DumpConfig) -> DumpResult:
        """执行脱壳。

        Args:
            target: 脱壳目标
            config: 脱壳配置

        Returns:
            DumpResult: 脱壳结果（降级模式下 success 可能为 False，
            但会附带完整的静态检测信息）
        """

    @abstractmethod
    def get_supported_formats(self) -> List[FileFormat]:
        """返回支持的文件格式。"""

    # ── 公共工具 ──

    def validate_target(self, target: DumpTarget) -> None:
        """校验目标平台与格式是否被当前引擎支持。

        Raises:
            ValueError: 平台或格式不受支持
        """
        if target.platform.value != self.platform:
            raise ValueError(
                f"{self.name} 仅支持 {self.platform} 目标, "
                f"收到 {target.platform.value}"
            )
        supported = {fmt.value for fmt in self.get_supported_formats()}
        if target.file_format.value not in supported:
            raise ValueError(
                f"{self.name} 不支持格式 {target.file_format.value}, "
                f"支持: {sorted(supported)}"
            )

    @staticmethod
    def guard_remote(target: DumpTarget) -> None:
        """S1 守卫入口：若目标携带 remote_host，则校验为本地地址。"""
        if target.remote_host:
            assert_local(target.remote_host)
