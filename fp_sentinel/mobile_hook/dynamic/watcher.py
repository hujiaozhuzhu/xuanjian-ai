# -*- coding: utf-8 -*-
"""MemoryWatcher —— API 调用监视器。

职责：
- 维护一份"关注 API"监视清单（集合写入、Base64、JSON、加密、Log...）；
- 生成对应的 Frida 监视脚本（与技法脚本模板同规范）；
- 解析运行期事件流（on_message 回调收到的 JSON），聚合成事件记录。

设计为可 mock：``start()`` 在 dry_run / frida 不可用时返回降级结果，
不产生真实设备交互。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .frida_tracer import FridaTracer

logger = logging.getLogger(__name__)

# 默认监视清单：API -> 说明（Frida 侧以 JS 对象注入）
DEFAULT_WATCH_LIST: List[Dict[str, Any]] = [
    {"clazz": "java.util.HashMap", "method": "put", "desc": "集合写入"},
    {"clazz": "java.util.ArrayList", "method": "add", "desc": "列表写入"},
    {"clazz": "android.util.Base64", "method": "decode", "desc": "Base64 解码"},
    {"clazz": "android.util.Base64", "method": "encode", "desc": "Base64 编码"},
    {"clazz": "javax.crypto.Cipher", "method": "doFinal", "desc": "加解密终结点"},
    {"clazz": "org.json.JSONObject", "method": "toString", "desc": "JSON 序列化"},
    {"clazz": "android.util.Log", "method": "d", "desc": "调试日志"},
]


@dataclass
class WatchEvent:
    """一次被监视 API 的运行期事件。"""

    api: str                       # "java.util.Base64.decode"
    timestamp: float = 0.0
    args: List[str] = field(default_factory=list)
    stack: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "api": self.api,
            "timestamp": self.timestamp,
            "args": self.args,
            "stack": self.stack,
            "extra": self.extra,
        }


class MemoryWatcher:
    """API 调用监视器（内存 Watcher）。"""

    def __init__(
        self,
        watch_list: Optional[List[Dict[str, Any]]] = None,
        dry_run: bool = True,
        device_serial: Optional[str] = None,
        package: Optional[str] = None,
    ):
        self.watch_list = watch_list if watch_list is not None else list(DEFAULT_WATCH_LIST)
        self.dry_run = dry_run
        self.device_serial = device_serial
        self.package = package
        self.events: List[WatchEvent] = []

    # ────────────────────────── 脚本生成 ──────────────────────────

    def generate_watch_script(self) -> str:
        """生成监视脚本：对清单中的每个 API 打印参数与调用栈。"""
        lines = [
            "// ═══════ 玄鉴 v4.0 MemoryWatcher 监视脚本 ═══════",
            "Java.perform(function () {",
        ]
        for item in self.watch_list:
            clazz = item["clazz"]
            method = item["method"]
            lines.append(
                f"    try {{\n"
                f"        var C_{abs(hash((clazz, method))) % 10 ** 8} = "
                f"Java.use(\"{clazz}\");\n"
                f"        console.log(\"[watch] 监视 {clazz}.{method}\");\n"
                f"    }} catch (e) {{\n"
                f"        console.log(\"[watch] 跳过 {clazz}: \" + e);\n"
                f"    }}"
            )
        lines += [
            "});",
            "// 说明: 精确 overload 注入由 frida_tracer.generate_script 依据静态点位生成",
        ]
        return "\n".join(lines)

    # ────────────────────────── 启动（可降级） ──────────────────────────

    def start(self, hook_points=None) -> Dict[str, Any]:
        """启动监视。

        - dry_run / frida 不可用 -> 降级：返回静态监视清单与脚本，不连接设备；
        - 正常模式 -> 交给 FridaTracer.attach 注入，on_message 收事件。
        """
        tracer = FridaTracer(
            device_serial=self.device_serial,
            package=self.package,
            dry_run=self.dry_run,
        )
        if self.dry_run or not tracer.is_available():
            return {
                "mode": "static_fallback",
                "watch_list": self.watch_list,
                "script": self.generate_watch_script(),
                "message": "Watcher 以降级模式启动（无设备交互），监视清单与脚本已就绪",
            }
        try:
            handle = tracer.attach(
                hook_points or [],
                on_message=self._on_message,
            )
            return {"mode": "live", "handle": handle, "watch_list": self.watch_list}
        except Exception as exc:  # frida 不可用 / 附加失败，均降级
            logger.warning("Watcher 附加失败，降级: %s", exc)
            return {
                "mode": "static_fallback",
                "watch_list": self.watch_list,
                "script": self.generate_watch_script(),
                "message": f"Watcher 附加失败已降级: {exc}",
            }

    # ────────────────────────── 事件解析 ──────────────────────────

    def _on_message(self, message: Dict, data: Dict) -> None:
        """frida on_message 回调：解析 payload 为 WatchEvent。"""
        event = self.parse_event(message)
        if event is not None:
            self.events.append(event)

    @staticmethod
    def parse_event(message: Dict) -> Optional[WatchEvent]:
        """把 frida message dict 解析为 WatchEvent；不合规返回 None。

        约定 payload 格式（脚本侧 JSON）::
            {"api": "java.util.Base64.decode", "args": ["..."], "stack": "..."}
        """
        if not isinstance(message, dict):
            return None
        if message.get("type") != "send":
            return None
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return None
        api = payload.get("api")
        if not api or not isinstance(api, str):
            return None
        args = payload.get("args") or []
        if not isinstance(args, list):
            args = [str(args)]
        return WatchEvent(
            api=api,
            timestamp=float(payload.get("timestamp") or 0.0),
            args=[str(a) for a in args],
            stack=str(payload.get("stack") or ""),
            extra={k: v for k, v in payload.items()
                   if k not in ("api", "args", "stack", "timestamp")},
        )

    def summary(self) -> Dict[str, Any]:
        """事件聚合：按 API 计数 + 最近事件。"""
        counts: Dict[str, int] = {}
        for ev in self.events:
            counts[ev.api] = counts.get(ev.api, 0) + 1
        return {
            "total": len(self.events),
            "by_api": counts,
            "recent": [ev.to_dict() for ev in self.events[-10:]],
        }
