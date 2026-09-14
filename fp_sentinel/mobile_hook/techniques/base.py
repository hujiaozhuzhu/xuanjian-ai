# -*- coding: utf-8 -*-
"""Technique 基类与全局技法注册表。

七种定位技法（隐雾课程体系，规划文档 2.3.1）都继承 Technique：

1. keyword_search —— 关键字搜索定位
2. collection     —— HashMap/ArrayList 集合类 Hook
3. toast          —— Toast 调用栈回溯
4. log            —— Log 日志定位
5. json           —— JSON 序列化/反序列化定位
6. string         —— String 转 byte[] 编码转换定位
7. base64         —— Base64 编解码定位

每个技法必须实现：
- ``analyze(context)``：纯静态分析，产出 HookPoint 列表（不依赖 frida）；
- ``generate_frida_script(hook_points)``：生成符合隐雾培训规范的
  Frida 脚本模板（Java.perform 包裹 Java.use，overload 处理重载，
  打印参数/返回值/调用栈）。

技法必须"独立可运行"：只依赖 ApkContext，不依赖其它技法或引擎层。
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Type

from ..core.apk_context import ApkContext
from ..models import HookPoint, TechniqueResult

# ────────────────────────── 全局注册表 ──────────────────────────

_TECHNIQUE_REGISTRY: Dict[str, Type["Technique"]] = {}


def register_technique(cls: Type["Technique"]) -> Type["Technique"]:
    """类装饰器：注册技法到全局注册表。"""
    _TECHNIQUE_REGISTRY[cls.name] = cls
    return cls


def get_technique_registry() -> Dict[str, Type["Technique"]]:
    """返回全局技法注册表（含已 import 的全部内置技法）。"""
    _ensure_builtin_loaded()
    return dict(_TECHNIQUE_REGISTRY)


def _ensure_builtin_loaded() -> None:
    """惰性 import 内置技法，触发装饰器注册。"""
    if len(_TECHNIQUE_REGISTRY) >= 7:
        return
    # noqa: E402 —— 延迟导入避免循环依赖
    from . import (  # noqa: F401
        keyword_search,
        collection_hook,
        toast_hook,
        log_hook,
        json_hook,
        string_hook,
        base64_hook,
    )


def build_technique(name: str, goal: str = "generic") -> "Technique":
    """按名字实例化技法。"""
    _ensure_builtin_loaded()
    cls = _TECHNIQUE_REGISTRY.get(name)
    if cls is None:
        raise KeyError(name)
    return cls(goal=goal)


# ────────────────────────── Frida 脚本公共模板 ──────────────────────────
# 隐雾培训规范：
#   1. 一切 Hook 包在 Java.perform(function(){...}) 中；
#   2. Java.use(完整类名) 拿到类包装器，重载方法用 .overload(sig)；
#   3. implementation 内先打印参数，再调用原实现，再打印返回值；
#   4. 需要回溯调用方时打印 Throwable 栈。

FRIDA_HELPERS = """// ───── 玄鉴 v4.0 通用工具函数（隐雾规范） ─────
function bytesToHex(arr) {
    if (arr === null) return "null";
    var result = "";
    for (var i = 0; i < arr.length; ++i) {
        result += ("0" + (arr[i] & 0xFF).toString(16)).slice(-2);
    }
    return result;
}

function bytesToString(arr) {
    if (arr === null) return "null";
    try {
        return Java.use("java.lang.String").$new(arr, "UTF-8");
    } catch (e) {
        return bytesToHex(arr);
    }
}

function printStackTrace(tag) {
    console.log("[*] " + tag + " 调用栈:");
    console.log(Java.use("android.util.Log").getStackTraceString(
        Java.use("java.lang.Throwable").$new()));
}

// ───── hookPoint: {clazz, method, sig} —— 单个 Hook 的骨架 ─────
function hookMethod(hookPoint) {
    Java.perform(function () {
        try {
            var Cls = Java.use(hookPoint.clazz);
            var m = hookPoint.sig
                ? Cls[hookPoint.method].overload.apply(Cls[hookPoint.method], hookPoint.sig)
                : Cls[hookPoint.method].overload();
            m.implementation = function () {
                console.log("\\n[*] ==> " + hookPoint.clazz + "." + hookPoint.method
                    + " (" + hookPoint.sig + ") 触发");
                for (var i = 0; i < arguments.length; i++) {
                    var arg = arguments[i];
                    var shown = (arg !== null && arg !== undefined && arg.length !== undefined
                        && typeof arg !== "string") ? bytesToHex(arg) : String(arg);
                    console.log("    arg[" + i + "] = " + shown);
                }
                var ret = m.apply(this, arguments);
                var retShown = (ret !== null && ret !== undefined && ret.length !== undefined
                    && typeof ret !== "string") ? bytesToHex(ret) : String(ret);
                console.log("    return = " + retShown);
                printStackTrace(hookPoint.clazz + "." + hookPoint.method);
                return ret;
            };
            console.log("[+] Hooked: " + hookPoint.clazz + "." + hookPoint.method);
        } catch (e) {
            console.log("[-] Hook 失败 " + hookPoint.clazz + "." + hookPoint.method + ": " + e);
        }
    });
}
"""

FRIDA_ENTRY = """
// ───── 批量挂载入口 ─────
Java.perform(function () {
    console.log("[*] 玄鉴 mobile_hook 脚本加载完成, 共 %d 个点位", HOOK_POINTS.length);
});
HOOK_POINTS.forEach(hookMethod);
"""


class Technique(ABC):
    """定位技法基类。"""

    #: 技法唯一名（注册表 key）
    name: str = "unknown"
    #: 人类可读描述
    description: str = ""
    #: 该技法默认监控的 Hook 点位（Frida 侧目标，如 [("java.util.Base64", "decode")]）
    hook_targets: List = []

    def __init__(self, goal: str = "generic"):
        self.goal = goal

    # ────────────────────────── 静态分析 ──────────────────────────

    @abstractmethod
    def analyze(self, context: ApkContext, **kwargs) -> TechniqueResult:
        """静态分析：在上下文中查找与本技法相关的 Hook 点位。

        实现必须独立可运行，且不依赖 frida（Frida 不可用时降级为纯静态）。
        """

    # ────────────────────────── 结果封装 ──────────────────────────

    def _new_result(self) -> TechniqueResult:
        r = TechniqueResult(technique=self.name)
        r.start_timer()
        return r

    def _finish(self, result: TechniqueResult, hook_points: List[HookPoint], **meta) -> TechniqueResult:
        result.success = True
        result.hook_points = hook_points
        result.stop_timer()
        result.metadata.update(meta)
        return result

    # ────────────────────────── HookPoint 工厂 ──────────────────────────

    def make_hook_point(
        self,
        class_name: str,
        method_name: str,
        param_signature: str = "",
        confidence: float = 0.5,
        strings_matched: Optional[List[str]] = None,
        reason: str = "",
        **metadata,
    ) -> HookPoint:
        """构造属于本技法的 HookPoint（统一填 technique/source）。"""
        return HookPoint(
            class_name=class_name,
            method_name=method_name,
            param_signature=param_signature,
            technique=self.name,
            confidence=confidence,
            strings_matched=strings_matched or [],
            reason=reason or f"{self.name} 技法命中",
            source="static",
            metadata=metadata,
        )

    # ────────────────────────── Frida 脚本生成 ──────────────────────────

    def generate_frida_script(self, hook_points: List[HookPoint]) -> str:
        """生成 Frida 脚本模板（隐雾规范）。

        默认实现：把 HookPoint 列表注入通用 hookMethod 骨架；
        技法可重写以追加对系统类（如 android.util.Base64）的预置 Hook。
        """
        points = [
            {
                "clazz": hp.class_name,
                "method": hp.method_name,
                "sig": self._overload_args(hp.param_signature),
            }
            for hp in hook_points
        ]
        body = (
            f"// 技法: {self.name} —— {self.description}\n"
            f"// 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"// 目标: {len(points)} 个点位\n"
            + FRIDA_HELPERS
            + "\nvar HOOK_POINTS = " + _js_array(points) + ";\n"
            + FRIDA_ENTRY.replace("%d", str(len(points)))
        )
        return body

    @staticmethod
    def _overload_args(param_signature: str) -> List[str]:
        """把方法描述符 "(Ljava/lang/String;[B)V" 解析为 overload 参数类型列表。"""
        from .sig_utils import parse_descriptor

        return parse_descriptor(param_signature)

    # ────────────────────────── 系统类预置 Hook（技法通用） ──────────────────────────

    def system_hook_points(self) -> List[Dict]:
        """技法需要 Hook 的系统类点位（子类重写）。"""
        return []


def _js_array(points: List[Dict]) -> str:
    """把点位列表渲染为 JS 数组字面量。"""
    if not points:
        return "[]"
    lines = ["["]
    for p in points:
        sig = ", ".join(f"'{s}'" for s in p["sig"])
        lines.append(
            f"    {{clazz: '{p['clazz']}', method: '{p['method']}', sig: [{sig}]}},"
        )
    lines.append("]")
    return "\n".join(lines)
