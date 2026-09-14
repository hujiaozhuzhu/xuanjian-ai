# -*- coding: utf-8 -*-
"""技法 3：Toast 调用栈 Hook。

原理：UI 反馈（如"登录成功"、"解密失败"）由 Toast 展示；Hook Toast
显示方法并打印调用栈，可以逆推触发 UI 提示的业务功能代码位置。

自动化方式：静态找出调用了 android.widget.Toast.makeText/show 的应用
方法；脚本模板对 Toast.show 注入调用栈打印。
"""

from __future__ import annotations

from typing import List

from ..core.apk_context import ApkContext
from ..models import HookPoint, TechniqueResult
from .base import Technique, register_technique

TOAST_TARGETS = {
    ("android.widget.Toast", "makeText"),
    ("android.widget.Toast", "show"),
}


@register_technique
class ToastHookTechnique(Technique):
    name = "toast"
    description = "Toast 调用栈回溯：Hook Toast.show 定位 UI 反馈的业务代码"

    def analyze(self, context: ApkContext, **kwargs) -> TechniqueResult:
        result = self._new_result()
        limit = kwargs.get("limit", 50)
        hook_points: List[HookPoint] = []

        for cls in context.app_classes().values():
            if len(hook_points) >= limit:
                break
            for m in cls.methods:
                if not any(t in TOAST_TARGETS for t in m.invokes):
                    continue
                # show 比 makeText 更靠近"展示"动作
                confidence = 0.6
                strings = m.strings[:10]
                # Toast 前后常见状态字符串（成功/失败提示），有字符串证据加分
                if strings:
                    confidence = min(0.85, confidence + 0.1)
                hook_points.append(
                    self.make_hook_point(
                        class_name=m.class_name,
                        method_name=m.name,
                        param_signature=m.descriptor,
                        confidence=confidence,
                        strings_matched=strings,
                        reason=f"调用 Toast API {sorted(set(t for t in m.invokes if t in TOAST_TARGETS))}",
                        toast_strings=strings,
                    )
                )
                if len(hook_points) >= limit:
                    break

        hook_points.sort(key=lambda p: p.confidence, reverse=True)
        return self._finish(result, hook_points)

    def system_hook_points(self) -> List[dict]:
        return [
            {"clazz": "android.widget.Toast", "method": "show", "sig": [], "stack": True},
        ]

    def generate_frida_script(self, hook_points: List[HookPoint]) -> str:
        script = super().generate_frida_script(hook_points)
        script += """
// ───── 技法3 预置：Toast 显示监控（打印文本 + 调用栈回溯业务代码） ─────
Java.perform(function () {
    var Toast = Java.use("android.widget.Toast");
    Toast.show.overload().implementation = function () {
        console.log("[toast] Toast.show() 文本: " + this.mText ? this.mText.value : "(未知)");
        console.log(Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Throwable").$new()));
        return this.show();
    };
    // 兼容 makeText 链式调用场景：同时打印 makeText 的第二个参数
    Toast.makeText.overload("android.content.Context", "java.lang.CharSequence", "int")
        .implementation = function (ctx, text, dur) {
            console.log("[toast] Toast.makeText: " + text);
            return this.makeText(ctx, text, dur);
        };
});
"""
        return script
