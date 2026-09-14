# -*- coding: utf-8 -*-
"""技法 5：JSON 定位。

原理：API 请求/响应多经过 JSON 序列化/反序列化；Hook JSON 构造与
toString 可以拦截加密前的明文数据包和解密后的响应。

自动化方式：静态找出调用 org.json.JSONObject(JSONArray)/Gson/FastJSON
的应用方法；脚本模板对 org.json.JSONObject(String) 构造器与 toString
注入内容打印。
"""

from __future__ import annotations

from typing import List

from ..core.apk_context import ApkContext
from ..models import HookPoint, TechniqueResult
from .base import Technique, register_technique

JSON_TARGETS = {
    ("org.json.JSONObject", "<init>"),
    ("org.json.JSONObject", "toString"),
    ("org.json.JSONArray", "<init>"),
    ("com.google.gson.Gson", "toJson"),
    ("com.google.gson.Gson", "fromJson"),
    ("com.alibaba.fastjson.JSON", "toJSONString"),
    ("com.alibaba.fastjson.JSON", "parseObject"),
}


@register_technique
class JsonHookTechnique(Technique):
    name = "json"
    description = "JSON 定位：追踪 JSON 序列化/反序列化（API 数据加解密定位）"

    def analyze(self, context: ApkContext, **kwargs) -> TechniqueResult:
        result = self._new_result()
        limit = kwargs.get("limit", 50)
        hook_points: List[HookPoint] = []

        for cls in context.app_classes().values():
            if len(hook_points) >= limit:
                break
            for m in cls.methods:
                targets = sorted(set(t for t in m.invokes if t in JSON_TARGETS))
                if not targets:
                    continue
                # 请求体特征字符串（URL/接口名）作为加分证据
                api_evidence = [
                    s for s in m.strings
                    if any(k in s.lower() for k in ("http", "api/", "json", "request", "response"))
                ]
                confidence = 0.55 + (0.1 if api_evidence else 0.0)
                hook_points.append(
                    self.make_hook_point(
                        class_name=m.class_name,
                        method_name=m.name,
                        param_signature=m.descriptor,
                        confidence=round(confidence, 4),
                        strings_matched=(api_evidence or m.strings)[:10],
                        reason=f"JSON 流转调用 {targets}",
                        json_targets=targets,
                    )
                )
                if len(hook_points) >= limit:
                    break

        hook_points.sort(key=lambda p: p.confidence, reverse=True)
        return self._finish(result, hook_points)

    def system_hook_points(self) -> List[dict]:
        return [
            {"clazz": "org.json.JSONObject", "method": "<init>",
             "sig": ["java.lang.String"], "stack": True},
            {"clazz": "org.json.JSONObject", "method": "toString", "sig": [], "stack": True},
        ]

    def generate_frida_script(self, hook_points: List[HookPoint]) -> str:
        script = super().generate_frida_script(hook_points)
        script += """
// ───── 技法5 预置：JSON 流监控（加密前明文 / 解密后响应） ─────
Java.perform(function () {
    var JSONObject = Java.use("org.json.JSONObject");
    // 反序列化入口：new JSONObject(String) —— 请求/响应明文出现点
    JSONObject.$init.overload("java.lang.String").implementation = function (json) {
        console.log("[json] JSONObject.<init>(String): " + json.substring(0, 2048));
        console.log(Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Throwable").$new()));
        return this.$init(json);
    };
    // 序列化出口：toString —— 即将发送/展示的内容
    JSONObject.toString.overload().implementation = function () {
        var s = this.toString();
        console.log("[json] JSONObject.toString: " + s.substring(0, 2048));
        return s;
    };
});
"""
        return script
