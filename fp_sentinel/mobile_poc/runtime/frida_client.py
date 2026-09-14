"""Frida 客户端封装(RPC 模式)。

安全红线对齐:
- M1: 注入前必须校验设备在授权列表内;
- M6: 只能 attach 授权的 app 包名;
- 默认实现为 :class:`MockFridaClient`, 全程不与真实设备通信, 用于
  流水线自检/CI/演示。真实注入仅在显式提供 frida 环境并传入
  ``authorized_serials`` 后由 :class:`RealFridaClient` 承接(本模块不默认启用)。
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

__all__ = ["FridaClient", "MockFridaClient", "RealFridaClient", "create_client"]


class FridaClient(ABC):
    """Frida 客户端抽象接口。"""

    @abstractmethod
    def connect(self) -> bool:
        """建立与设备的会话。"""

    @abstractmethod
    def attach(self, package_name: str) -> Any:
        """附着到目标进程(M6: 必须在授权包名列表内)。"""

    @abstractmethod
    def load_script(self, source: str) -> Any:
        """加载脚本并注册消息回调。"""

    @abstractmethod
    def on_message(self, callback: Callable[[Dict[str, Any], Any], None]) -> None:
        """注册消息回调。"""

    @abstractmethod
    def detach(self) -> None:
        """脱离会话。"""


class MockFridaClient(FridaClient):
    """Mock Frida 客户端 —— 不连接任何真实设备。

    行为: 记录全部调用序列, 按需回放合成消息, 供执行器/CLI/CI 自检。
    """

    def __init__(
        self,
        device_serial: str = "mock-device-0000",
        authorized_serials: Optional[List[str]] = None,
        authorized_packages: Optional[List[str]] = None,
        synthesize_messages: bool = True,
    ) -> None:
        self.device_serial = device_serial
        self.authorized_serials = authorized_serials or ["*"]
        self.authorized_packages = authorized_packages or ["*"]
        self.synthesize_messages = synthesize_messages
        self.calls: List[Dict[str, Any]] = []
        self.messages: List[Dict[str, Any]] = []
        self._callback: Optional[Callable[[Dict[str, Any], Any], None]] = None
        self._script: Optional[Dict[str, Any]] = None
        self._session: Optional[str] = None
        self.connected = False

    # ------------------------------------------------------------------ log
    def _log(self, op: str, **kw: Any) -> None:
        self.calls.append({"op": op, "ts": time.time(), **kw})

    def _authorized(self, value: str, allowed: List[str]) -> bool:
        return "*" in allowed or value in allowed

    # -------------------------------------------------------------- lifecycle
    def connect(self) -> bool:
        if not self._authorized(self.device_serial, self.authorized_serials):
            raise PermissionError(
                f"device {self.device_serial!r} not in authorized list (红线 M1)"
            )
        self.connected = True
        self._log("connect", device=self.device_serial)
        return True

    def attach(self, package_name: str) -> Any:
        if not self.connected:
            raise RuntimeError("client not connected; call connect() first")
        if not self._authorized(package_name, self.authorized_packages):
            raise PermissionError(
                f"package {package_name!r} not authorized for hooking (红线 M6)"
            )
        self._session = f"mock-session:{package_name}"
        self._log("attach", package=package_name)
        return self._session

    def load_script(self, source: str) -> Any:
        if not self._session:
            raise RuntimeError("no active session; call attach() first")
        self._script = {"source": source, "length": len(source)}
        self._log("load_script", length=len(source))
        if self.synthesize_messages and self._callback:
            self._callback(
                {"type": "send", "payload": {"tag": "[fp-sentinel][mock]",
                                             "event": "script-loaded"}},
                None,
            )
        return self._script

    def on_message(self, callback: Callable[[Dict[str, Any], Any], None]) -> None:
        self._callback = callback
        self._log("on_message")

    def emit(self, payload: Dict[str, Any]) -> None:
        """测试/演示用: 主动向回调注入一条合成消息。"""
        self.messages.append(payload)
        if self._callback:
            self._callback({"type": "send", "payload": payload}, None)

    def detach(self) -> None:
        self._log("detach")
        self._script = None
        self._session = None
        self.connected = False

    # ----------------------------------------------------------------- extra
    def get_call_log(self) -> List[Dict[str, Any]]:
        return list(self.calls)


class RealFridaClient(FridaClient):
    """真实 Frida 客户端(惰性导入 frida, 仅在授权场景手工启用)。

    本项目默认不构造该实例; 仅当调用方显式传入授权设备列表时使用。
    """

    def __init__(
        self,
        device_serial: str,
        authorized_serials: List[str],
        authorized_packages: List[str],
    ) -> None:
        if device_serial not in authorized_serials:
            raise PermissionError(f"device {device_serial!r} not authorized (红线 M1)")
        self.device_serial = device_serial
        self.authorized_packages = authorized_packages
        self._callback: Optional[Callable[[Dict[str, Any], Any], None]] = None
        self._session: Any = None
        self._script: Any = None
        try:
            import frida  # noqa: PLC0415  延迟导入, 未安装不阻塞其余功能
        except ImportError as exc:
            raise RuntimeError("frida 未安装, 无法启用真实客户端") from exc
        self._frida = frida

    def connect(self) -> bool:
        device = self._frida.get_device(self.device_serial, timeout=5)
        self._session_device = device
        return True

    def attach(self, package_name: str) -> Any:
        if package_name not in self.authorized_packages:
            raise PermissionError(f"package {package_name!r} not authorized (红线 M6)")
        self._session = self._session_device.attach(package_name)
        return self._session

    def load_script(self, source: str) -> Any:
        self._script = self._session.create_script(source)
        if self._callback:
            self._script.on("message", self._callback)
        self._script.load()
        return self._script

    def on_message(self, callback: Callable[[Dict[str, Any], Any], None]) -> None:
        self._callback = callback

    def detach(self) -> None:
        if self._session:
            self._session.detach()
            self._session = None


def create_client(
    mock: bool = True,
    **kwargs: Any,
) -> FridaClient:
    """客户端工厂: 默认 mock。"""
    if mock:
        return MockFridaClient(**kwargs)
    required = ("device_serial", "authorized_serials", "authorized_packages")
    missing = [k for k in required if k not in kwargs]
    if missing:
        raise ValueError(f"real client requires: {', '.join(missing)}")
    return RealFridaClient(
        kwargs["device_serial"], kwargs["authorized_serials"], kwargs["authorized_packages"]
    )
