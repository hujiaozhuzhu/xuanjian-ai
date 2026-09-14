# -*- coding: utf-8 -*-
"""技法 6：String 转 byte[] 定位。

原理：加解密入口普遍存在 String -> byte[]（getBytes）或
byte[] -> String（new String(bytes)）的编码转换；Hook 这些转换点即可
定位加解密入口并截获明文/密文边界数据。

自动化方式：静态找出调用 java.lang.String.getBytes 或以 byte[] 构造
String 的应用方法；脚本模板对 String.getBytes 与 String(byte[]) 注入
内容打印。
"""

from __future__ import annotations

from typing import List

from ..core.apk_context import ApkContext
from ..models import HookPoint, TechniqueResult
from .base import Technique, register_technique

STRING_TARGETS = {
    ("java.lang.String", "getBytes"),
    ("java.lang.String", "<init>"),
}


@register_technique
class StringHookTechnique(Technique):
    name = "string"
    description = "String转byte[]定位：Hook 字符串编码转换（加解密入口定位）"

    def analyze(self, context: ApkContext, **kwargs) -> TechniqueResult:
        result = self._new_result()
        limit = kwargs.get("limit", 50)
        hook_points: List[HookPoint] = []

        for cls in context.app_classes().values():
            if len(hook_points) >= limit:
                break
            for m in cls.methods:
                targets = sorted(set(t for t in m.invokes if t in STRING_TARGETS))
                if not targets:
                    continue
                # 关注 getBytes 与 byte[] 构造（加密前后的编码边界）
                crypto_evidence = [
                    s for s in m.strings
                    if any(k in s.lower() for k in
                           ("aes", "des", "rsa", "utf-8", "gbk", "iso-8859-1", "md5", "sha"))
                ]
                confidence = 0.55 + (0.15 if crypto_evidence else 0.0)
                hook_points.append(
                    self.make_hook_point(
                        class_name=m.class_name,
                        method_name=m.name,
                        param_signature=m.descriptor,
                        confidence=round(confidence, 4),
                        strings_matched=(crypto_evidence or m.strings)[:10],
                        reason=f"字符串编码转换调用 {targets}",
                        string_targets=targets,
                    )
                )
                if len(hook_points) >= limit:
                    break

        hook_points.sort(key=lambda p: p.confidence, reverse=True)
        return self._finish(result, hook_points)

    def system_hook_points(self) -> List[dict]:
        return [
            {"clazz": "java.lang.String", "method": "getBytes", "sig": [], "stack": True},
            {"clazz": "java.lang.String", "method": "getBytes",
             "sig": ["java.lang.String"], "stack": True},
            {"clazz": "java.lang.String", "method": "<init>",
             "sig": ["byte[]"], "stack": True},
        ]

    def generate_frida_script(self, hook_points: List[HookPoint]) -> str:
        script = super().generate_frida_script(hook_points)
        script += """
// ───── 技法6 预置：String <-> byte[] 编码边界监控 ─────
Java.perform(function () {
    var Str = Java.use("java.lang.String");
    // 明文 -> 字节（加密前的最后形态）
    Str.getBytes.overload().implementation = function () {
        var b = this.getBytes();
        console.log("[string] getBytes() src=\\"" + this + "\\" hex=" + bytesToHex(b));
        console.log(Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Throwable").$new()));
        return b;
    };
    Str.getBytes.overload("java.lang.String").implementation = function (charset) {
        var b = this.getBytes(charset);
        console.log("[string] getBytes(" + charset + ") src=\\"" + this + "\\" hex=" + bytesToHex(b));
        return b;
    };
    // 字节 -> 明文（解密后的第一形态）
    Str.$init.overload("[B").implementation = function (b) {
        this.$init(b);
        console.log("[string] new String(byte[]) result=\\"" + this.toString()
            + "\\" hex=" + bytesToHex(b));
    };
});
"""
        return script
