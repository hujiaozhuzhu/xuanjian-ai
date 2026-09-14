# -*- coding: utf-8 -*-
"""技法 2：HashMap/ArrayList 集合类 Hook。

原理：网络请求参数常先装入 HashMap/ArrayList 再序列化发送；Hook
集合类写入方法并打印调用栈，即可回溯到拼装参数的业务代码。

自动化方式：静态找出调用了 HashMap.put/get、ArrayList.add 的应用方法
作为候选点位；脚本模板对 java.util.HashMap.put / ArrayList.add 注入
调用栈打印。
"""

from __future__ import annotations

from typing import List

from ..core.apk_context import ApkContext
from ..models import HookPoint, TechniqueResult
from .base import Technique, register_technique

# 关注的集合类调用目标
COLLECTION_TARGETS = {
    ("java.util.HashMap", "put"),
    ("java.util.HashMap", "get"),
    ("java.util.Hashtable", "put"),
    ("java.util.ArrayList", "add"),
    ("org.json.JSONObject", "put"),
}


@register_technique
class CollectionHookTechnique(Technique):
    name = "collection"
    description = "HashMap/ArrayList Hook：打印集合写入调用栈（网络请求参数跟踪）"

    def analyze(self, context: ApkContext, **kwargs) -> TechniqueResult:
        result = self._new_result()
        limit = kwargs.get("limit", 50)
        hook_points: List[HookPoint] = []

        for cls in context.app_classes().values():
            if len(hook_points) >= limit:
                break
            for m in cls.methods:
                targets = [t for t in m.invokes if t in COLLECTION_TARGETS]
                if not targets:
                    continue
                # put/add 写入比 get 读取更有追踪价值
                writes = [t for t in targets if t[1] in ("put", "add")]
                confidence = 0.6 if writes else 0.45
                hook_points.append(
                    self.make_hook_point(
                        class_name=m.class_name,
                        method_name=m.name,
                        param_signature=m.descriptor,
                        confidence=confidence,
                        reason=f"集合操作调用 {sorted(set(targets))}",
                        collection_targets=sorted(set(targets)),
                    )
                )
                if len(hook_points) >= limit:
                    break

        hook_points.sort(key=lambda p: p.confidence, reverse=True)
        return self._finish(result, hook_points, scanned_classes=len(context.app_classes()))

    def system_hook_points(self) -> List[dict]:
        """预置的系统集合类 Hook 点位。"""
        return [
            {"clazz": "java.util.HashMap", "method": "put",
             "sig": ["java.lang.Object", "java.lang.Object"], "stack": True},
            {"clazz": "java.util.ArrayList", "method": "add",
             "sig": ["java.lang.Object"], "stack": True},
        ]

    def generate_frida_script(self, hook_points: List[HookPoint]) -> str:
        script = super().generate_frida_script(hook_points)
        # 追加系统集合类预置 Hook（隐雾规范：Java.perform + Java.use + 调用栈）
        script += self._system_hook_snippet()
        return script

    def _system_hook_snippet(self) -> str:
        return """
// ───── 技法2 预置：系统集合类写入监控（自动打印调用栈） ─-----
Java.perform(function () {
    var HashMap = Java.use("java.util.HashMap");
    HashMap.put.overload("java.lang.Object", "java.lang.Object").implementation = function (k, v) {
        var result = this.put(k, v);
        console.log("[collection] HashMap.put(" + k + " => " + v + ")");
        console.log(Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Throwable").$new()));
        return result;
    };
    var ArrayList = Java.use("java.util.ArrayList");
    ArrayList.add.overload("java.lang.Object").implementation = function (e) {
        console.log("[collection] ArrayList.add(" + e + ")");
        console.log(Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Throwable").$new()));
        return this.add(e);
    };
});
"""
