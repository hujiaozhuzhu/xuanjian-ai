# -*- coding: utf-8 -*-
"""技法 7：Base64 编码定位。

原理：Base64.encode/decode 是明文与密文的显式边界（传输编码、密钥
封装、简单混淆）；Hook Base64 全部重载并追踪解码结果，即可定位
明文/密文边界与携带加密数据的业务方法。

自动化方式：静态找出调用 android.util.Base64 / java.util.Base64 的应用
方法；脚本模板对 android.util.Base64.encode/decode 全重载注入打印。
"""

from __future__ import annotations

from typing import List

from ..core.apk_context import ApkContext
from ..models import HookPoint, TechniqueResult
from .base import Technique, register_technique

BASE64_TARGETS = {
    ("android.util.Base64", "encode"),
    ("android.util.Base64", "decode"),
    ("android.util.Base64", "encodeToString"),
    ("java.util.Base64$Encoder", "encode"),
    ("java.util.Base64$Decoder", "decode"),
}


@register_technique
class Base64HookTechnique(Technique):
    name = "base64"
    description = "Base64编码定位：Hook Base64.encode/decode（明文/密文边界定位）"

    def analyze(self, context: ApkContext, **kwargs) -> TechniqueResult:
        result = self._new_result()
        limit = kwargs.get("limit", 50)
        hook_points: List[HookPoint] = []

        for cls in context.app_classes().values():
            if len(hook_points) >= limit:
                break
            for m in cls.methods:
                targets = sorted(set(t for t in m.invokes if t in BASE64_TARGETS))
                if not targets:
                    continue
                decode = any(t[1] == "decode" for t in targets)
                confidence = 0.65 if decode else 0.55
                # decode 直接产生明文，边界价值更高；含 Base64 特征串再加权
                b64_evidence = [
                    s for s in m.strings
                    if any(k in s.lower() for k in ("base64", "a-zaz-09", "abcdefghijklmnopqrstuvwxyz"))
                ]
                if b64_evidence:
                    confidence = min(0.9, confidence + 0.1)
                hook_points.append(
                    self.make_hook_point(
                        class_name=m.class_name,
                        method_name=m.name,
                        param_signature=m.descriptor,
                        confidence=round(confidence, 4),
                        strings_matched=(b64_evidence or m.strings)[:10],
                        reason=f"Base64 编解码调用 {targets}",
                        base64_targets=targets,
                        has_decode=decode,
                    )
                )
                if len(hook_points) >= limit:
                    break

        hook_points.sort(key=lambda p: p.confidence, reverse=True)
        return self._finish(result, hook_points)

    def system_hook_points(self) -> List[dict]:
        return [
            {"clazz": "android.util.Base64", "method": "decode",
             "sig": ["java.lang.String", "int"], "stack": True},
            {"clazz": "android.util.Base64", "method": "encode",
             "sig": ["byte[]", "int"], "stack": True},
            {"clazz": "android.util.Base64", "method": "encodeToString",
             "sig": ["byte[]", "int"], "stack": True},
        ]

    def generate_frida_script(self, hook_points: List[HookPoint]) -> str:
        script = super().generate_frida_script(hook_points)
        script += """
// ───── 技法7 预置：Base64 编解码边界监控（解码即明文） ─────
Java.perform(function () {
    var B64 = Java.use("android.util.Base64");
    B64.decode.overload("java.lang.String", "int").implementation = function (s, flags) {
        var out = this.decode(s, flags);
        console.log("[base64] decode in=" + s.substring(0, 512));
        console.log("[base64] decode out(hex)=" + bytesToHex(out));
        console.log("[base64] decode out(utf8)=" + bytesToString(out));
        console.log(Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Throwable").$new()));
        return out;
    };
    B64.encode.overload("[B", "int").implementation = function (input, flags) {
        var out = this.encode(input, flags);
        console.log("[base64] encode in(hex)=" + bytesToHex(input));
        console.log("[base64] encode out=" + bytesToString(out));
        return out;
    };
    B64.encodeToString.overload("[B", "int").implementation = function (input, flags) {
        var out = this.encodeToString(input, flags);
        console.log("[base64] encodeToString in(hex)=" + bytesToHex(input)
            + " out=" + out);
        return out;
    };
});
"""
        return script
