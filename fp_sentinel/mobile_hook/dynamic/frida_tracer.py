# -*- coding: utf-8 -*-
"""FridaTracer —— frida-trace 封装。

职责：
- 依据 HookPoint 列表生成 Frida 注入脚本（复用技法层脚本模板）；
- 封装设备附加 / 脚本注入 / 消息回调的生命周期；
- **降级策略**：frida 库不可用或无设备时，``is_available()`` 返回 False，
  ``attach()`` 抛出 :class:`FridaUnavailableError`，上层
  （HookLocator / CLI）捕获后自动回退为纯静态分析结果。

本模块自身绝不直接连接设备，除非调用方显式传入已就绪的 device serial
并调用 ``run()``；``dry_run`` 模式（默认）只生成与校验脚本。
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Dict, List, Optional

from ..models import HookPoint
from ..techniques.base import build_technique

logger = logging.getLogger(__name__)


class FridaUnavailableError(RuntimeError):
    """frida 运行时不可用（未安装 / 无 USB 设备 / server 未启动）。"""


class FridaTracer:
    """frida-trace 封装：脚本生成 + 附加执行（可降级）。"""

    def __init__(
        self,
        device_serial: Optional[str] = None,
        package: Optional[str] = None,
        dry_run: bool = True,
    ):
        self.device_serial = device_serial
        self.package = package
        self.dry_run = dry_run
        self._frida = None  # 惰性导入

    # ────────────────────────── 可用性 ──────────────────────────

    def is_available(self) -> bool:
        """frida Python 绑定是否可导入（不探测设备，探测放 attach）。"""
        try:
            self._import_frida()
            return True
        except FridaUnavailableError:
            return False

    def _import_frida(self):
        if self._frida is not None:
            return self._frida
        try:
            import frida  # noqa: PLC0415

            self._frida = frida
            return frida
        except ImportError as exc:
            raise FridaUnavailableError(
                "frida 未安装，动态追踪不可用，已降级为静态分析。"
                "安装: pip install frida frida-tools"
            ) from exc

    # ────────────────────────── 脚本生成 ──────────────────────────

    def generate_script(self, hook_points: List[HookPoint]) -> str:
        """按技法分组生成合并脚本（每个技法一段模板 + 预置系统 Hook）。"""
        if not hook_points:
            return "// 无 Hook 点位"
        by_technique: Dict[str, List[HookPoint]] = {}
        for hp in hook_points:
            by_technique.setdefault(hp.technique, []).append(hp)
        parts = [
            "// ═══════ 玄鉴 v4.0 mobile_hook 自动生成脚本 ═══════",
            f"// 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"// 点位总数: {len(hook_points)}，技法数: {len(by_technique)}",
        ]
        for technique_name, points in by_technique.items():
            try:
                technique = build_technique(technique_name)
                parts.append(f"\n// ───── 技法 {technique_name}（{len(points)} 点位） ─────")
                parts.append(technique.generate_frida_script(points))
            except KeyError:
                logger.warning("未知技法 %s，跳过其脚本生成", technique_name)
                parts.append(f"// !! 未知技法 {technique_name}，未生成脚本")
        return "\n".join(parts)

    # ────────────────────────── 附加执行 ──────────────────────────

    def attach(
        self,
        hook_points: List[HookPoint],
        on_message: Optional[Callable[[Dict, Dict], None]] = None,
    ):
        """附加到目标进程并注入脚本。

        - ``dry_run=True``（默认）：只生成并返回脚本，不连接任何设备；
        - ``dry_run=False``：真实附加（需要 frida 环境 + USB 设备）。
        """
        script_src = self.generate_script(hook_points)
        if self.dry_run:
            logger.info("dry_run 模式：仅生成脚本（%d 字符），未连接设备", len(script_src))
            return {"mode": "dry_run", "script": script_src}

        frida = self._import_frida()  # frida 不可用则抛 FridaUnavailableError
        if not self.package:
            raise FridaUnavailableError("真实附加需要指定目标包名 --package")
        try:
            device = (
                frida.get_device(self.device_serial)
                if self.device_serial
                else frida.get_usb_device(timeout=5)
            )
            session = device.attach(self.package)
            script = session.create_script(script_src)
            if on_message is not None:
                script.on("message", on_message)
            script.load()
            return {"mode": "live", "session": session, "script": script}
        except Exception as exc:
            raise FridaUnavailableError(f"Frida 附加失败: {exc}") from exc

    # ────────────────────────── 降级静态 ──────────────────────────

    @staticmethod
    def static_fallback(hook_points: List[HookPoint]) -> Dict:
        """Frida 不可用时的降级输出：静态点位 + 脚本仍可生成备用。"""
        tracer = FridaTracer(dry_run=True)
        return {
            "mode": "static_fallback",
            "reason": "frida 不可用或未连接设备，返回静态分析结果",
            "hook_points": [hp.to_dict() for hp in hook_points],
            "script_ready": bool(hook_points),
            "script": tracer.generate_script(hook_points) if hook_points else "",
        }
