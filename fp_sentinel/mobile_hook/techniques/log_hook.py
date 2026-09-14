# -*- coding: utf-8 -*-
"""技法 4：Log 日志定位。

原理：开发调试埋点（Log.d/e/i/v/w）常泄露明文中间值（Token、加密前
数据包、URL）；Hook android.util.Log 系列方法即可旁路收集开发埋点。

自动化方式：静态找出调用 Log.* 的应用方法（含字符串证据）；脚本模板
对 Log.d/e/i/v/w 全量注入参数打印。
"""

from __future__ import annotations

from typing import List

from ..core.apk_context import ApkContext
from ..models import HookPoint, TechniqueResult
from .base import Technique, register_technique

LOG_TARGETS = {
    ("android.util.Log", "d"),
    ("android.util.Log", "e"),
    ("android.util.Log", "i"),
    ("android.util.Log", "v"),
    ("android.util.Log", "w"),
}


@register_technique
class LogHookTechnique(Technique):
    name = "log"
    description = "Log 日志定位：Hook android.util.Log 收集开发埋点泄露的中间值"

    def analyze(self, context: ApkContext, **kwargs) -> TechniqueResult:
        result = self._new_result()
        limit = kwargs.get("limit", 50)
        hook_points: List[HookPoint] = []

        for cls in context.app_classes().values():
            if len(hook_points) >= limit:
                break
            for m in cls.methods:
                targets = sorted(set(t for t in m.invokes if t in LOG_TARGETS))
                if not targets:
                    continue
                # 日志内容含敏感字符串常量的点位价值更高
                sensitive = [
                    s for s in m.strings
                    if any(k in s.lower() for k in
                           ("token", "password", "passwd", "key", "encrypt",
                            "decrypt", "url", "http", "session", "login"))
                ]
                confidence = 0.5 + (0.15 if sensitive else 0.0)
                hook_points.append(
                    self.make_hook_point(
                        class_name=m.class_name,
                        method_name=m.name,
                        param_signature=m.descriptor,
                        confidence=round(confidence, 4),
                        strings_matched=(sensitive or m.strings)[:10],
                        reason=f"调用日志 API {targets}",
                        log_targets=targets,
                        sensitive_strings=sensitive,
                    )
                )
                if len(hook_points) >= limit:
                    break

        hook_points.sort(key=lambda p: p.confidence, reverse=True)
        return self._finish(result, hook_points)

    def system_hook_points(self) -> List[dict]:
        return [
            {"clazz": "android.util.Log", "method": lvl,
             "sig": ["java.lang.String", "java.lang.String"], "stack": False}
            for lvl in ("d", "e", "i", "v", "w")
        ]

    def generate_frida_script(self, hook_points: List[HookPoint]) -> str:
        script = super().generate_frida_script(hook_points)
        script += """
// ───── 技法4 预置：Log 输出监控（开发埋点旁路收集） ─────
Java.perform(function () {
    var Log = Java.use("android.util.Log");
    ["d", "e", "i", "v", "w"].forEach(function (level) {
        Log[level].overload("java.lang.String", "java.lang.String")
            .implementation = function (tag, msg) {
                console.log("[log] Log." + level + " [" + tag + "] " + msg);
                return this[level](tag, msg);
            };
    });
});
"""
        return script
