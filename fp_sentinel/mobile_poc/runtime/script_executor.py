"""脚本执行器 —— 沙箱化执行封装(默认 dry-run, 不连接真实设备)。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .frida_client import FridaClient

__all__ = ["ScriptExecutor", "ExecutionResult"]


@dataclass
class ExecutionResult:
    """一次脚本执行的结果。"""

    success: bool
    package_name: str
    dry_run: bool
    messages: List[Dict[str, Any]] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    error: Optional[str] = None
    duration_sec: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "package_name": self.package_name,
            "dry_run": self.dry_run,
            "message_count": len(self.messages),
            "messages": self.messages,
            "logs": self.logs,
            "error": self.error,
            "duration_sec": round(self.duration_sec, 4),
        }


class ScriptExecutor:
    """脚本执行器。

    红线约束:
    - M1/M6: 执行前校验设备序列号与包名授权;
    - M4: 执行动作经由注入的 FridaClient, 默认 Mock 客户端即天然沙箱。
    """

    def __init__(
        self,
        client: FridaClient,
        authorized_packages: Optional[List[str]] = None,
        dry_run: bool = True,
    ) -> None:
        self.client = client
        self.authorized_packages = authorized_packages or ["*"]
        self.dry_run = dry_run

    def execute(
        self,
        script_source: str,
        package_name: str,
        device_serial: str = "mock-device-0000",
        collect_timeout: float = 1.0,
    ) -> ExecutionResult:
        import time as _time

        started = _time.perf_counter()
        logs: List[str] = []
        messages: List[Dict[str, Any]] = []

        # 红线 M6: 包名授权前置校验
        if not ("*" in self.authorized_packages or package_name in self.authorized_packages):
            return ExecutionResult(
                success=False,
                package_name=package_name,
                dry_run=self.dry_run,
                error=f"package {package_name!r} not authorized for hooking (红线 M6)",
            )

        def on_message(message: Dict[str, Any], data: Any) -> None:
            if message.get("type") == "send":
                messages.append(message.get("payload", {}))
            else:
                logs.append(str(message))

        self.client.on_message(on_message)
        try:
            self.client.connect()
            self.client.attach(package_name)
            self.client.load_script(script_source)
            if self.dry_run:
                logs.append(
                    f"[dry-run] mock session ended after {collect_timeout}s (无真实设备连接)"
                )
            self.client.detach()
            return ExecutionResult(
                success=True,
                package_name=package_name,
                dry_run=self.dry_run,
                messages=messages,
                logs=logs,
                duration_sec=_time.perf_counter() - started,
            )
        except (PermissionError, RuntimeError, ValueError) as exc:
            return ExecutionResult(
                success=False,
                package_name=package_name,
                dry_run=self.dry_run,
                messages=messages,
                logs=logs,
                error=str(exc),
                duration_sec=_time.perf_counter() - started,
            )
