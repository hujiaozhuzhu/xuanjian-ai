# -*- coding: utf-8 -*-
"""七种定位技法的单元测试：独立可运行性 + 命中正确性 + Frida 脚本规范。"""

from __future__ import annotations

import pytest

from fp_sentinel.mobile_hook.techniques import TECHNIQUE_NAMES, build_technique, get_technique_registry
from fp_sentinel.mobile_hook.techniques.base import (
    FRIDA_HELPERS,
    Technique,
    _js_array,
)
from fp_sentinel.mobile_hook.techniques.sig_utils import parse_descriptor, return_type


# ────────────────────────── 注册表 ──────────────────────────

def test_registry_contains_seven_techniques():
    registry = get_technique_registry()
    assert set(TECHNIQUE_NAMES) <= set(registry.keys())
    assert len(registry) == 7


def test_build_technique_unknown_raises():
    with pytest.raises(KeyError):
        build_technique("no-such-technique")


def test_techniques_independent(sample_context):
    """每种技法只依赖 ApkContext，独立可运行。"""
    for name in TECHNIQUE_NAMES:
        technique = build_technique(name)
        result = technique.analyze(sample_context)
        assert result.success, f"技法 {name} 独立运行失败: {result.error}"
        assert result.technique == name
        assert result.duration_ms >= 0


# ────────────────────────── 技法 1：关键字 ──────────────────────────

def test_keyword_finds_crypto_util(sample_context):
    result = build_technique("keyword").analyze(sample_context)
    names = {hp.qualified_method for hp in result.hook_points}
    assert "com.demo.bank.CryptoUtil#encrypt" in names
    top = result.hook_points[0]
    assert top.strings_matched  # 有字符串证据
    # 框架类被过滤
    assert all(not hp.class_name.startswith("android.") for hp in result.hook_points)


def test_keyword_goal_switch(sample_context):
    result = build_technique("keyword").analyze(sample_context, goal="root-detection")
    # root-detection 规则在本样本中无命中，也应正常成功返回
    assert result.success


# ────────────────────────── 技法 2：collection ──────────────────────────

def test_collection_finds_put_caller(sample_context):
    result = build_technique("collection").analyze(sample_context)
    hp = [p for p in result.hook_points if p.method_name == "buildParams"]
    assert hp, "应命中 RequestBuilder.buildParams（调用 HashMap.put）"
    assert hp[0].metadata["collection_targets"]


def test_collection_system_hook_script(sample_context):
    t = build_technique("collection")
    result = t.analyze(sample_context)
    script = t.generate_frida_script(result.hook_points)
    assert 'Java.use("java.util.HashMap")' in script
    assert "getStackTraceString" in script


# ────────────────────────── 技法 3：toast ──────────────────────────

def test_toast_finds_ui_methods(sample_context):
    result = build_technique("toast").analyze(sample_context)
    names = {hp.qualified_method for hp in result.hook_points}
    assert f"com.demo.bank.MainActivity#onCreate" in names
    assert f"com.demo.bank.LoginReceiver#onReceive" in names
    # 有 Toast 字符串证据的点位置信度更高
    assert all(p.confidence >= 0.6 for p in result.hook_points)


def test_toast_script_monitor_show(sample_context):
    t = build_technique("toast")
    script = t.generate_frida_script(t.analyze(sample_context).hook_points)
    assert 'Java.use("android.widget.Toast")' in script
    assert "Toast.show()" in script


# ────────────────────────── 技法 4：log ──────────────────────────

def test_log_finds_debug_dump(sample_context):
    result = build_technique("log").analyze(sample_context)
    hp = [p for p in result.hook_points if p.method_name == "debugDump"]
    assert hp
    assert hp[0].metadata["sensitive_strings"]  # password/session_token 敏感日志
    assert hp[0].confidence > 0.5


def test_log_script_hooks_all_levels():
    t = build_technique("log")
    script = t.generate_frida_script([])
    for level in ("d", "e", "i", "v", "w"):
        assert f'"{level}"' in script


# ────────────────────────── 技法 5：json ──────────────────────────

def test_json_finds_request_builder(sample_context):
    result = build_technique("json").analyze(sample_context)
    names = {hp.qualified_method for hp in result.hook_points}
    assert "com.demo.bank.RequestBuilder#buildParams" in names


def test_json_script_hooks_jsonobject(sample_context):
    t = build_technique("json")
    script = t.generate_frida_script(t.analyze(sample_context).hook_points)
    assert "JSONObject.$init.overload" in script
    assert "JSONObject.toString" in script


# ────────────────────────── 技法 6：string ──────────────────────────

def test_string_finds_getbytes_caller(sample_context):
    result = build_technique("string").analyze(sample_context)
    names = {hp.qualified_method for hp in result.hook_points}
    assert "com.demo.bank.CryptoUtil#encrypt" in names
    # 有 AES 特征字符串，置信度应加分
    hp = next(p for p in result.hook_points if p.method_name == "encrypt")
    assert hp.confidence >= 0.7


def test_string_script_hooks_getbytes(sample_context):
    t = build_technique("string")
    script = t.generate_frida_script(t.analyze(sample_context).hook_points)
    assert "Str.getBytes.overload()" in script
    assert "new String(byte[])" in script


# ────────────────────────── 技法 7：base64 ──────────────────────────

def test_base64_finds_encode_and_decode(sample_context):
    result = build_technique("base64").analyze(sample_context)
    by_method = {p.method_name: p for p in result.hook_points}
    assert "encrypt" in by_method and "decrypt" in by_method
    # decode 点位（有明文边界价值）置信度不低于 encode
    assert by_method["decrypt"].metadata["has_decode"] is True


def test_base64_script_hooks_decode(sample_context):
    t = build_technique("base64")
    script = t.generate_frida_script(t.analyze(sample_context).hook_points)
    assert "B64.decode.overload" in script
    assert "bytesToHex" in script


# ────────────────────────── Frida 脚本规范（隐雾培训规范） ──────────────────────────

@pytest.mark.parametrize("name", TECHNIQUE_NAMES)
def test_all_scripts_follow_yinwu_standard(sample_context, name):
    """所有技法脚本必须：Java.perform 包裹、Java.use 取类、有调用栈打印。"""
    technique = build_technique(name)
    result = technique.analyze(sample_context)
    script = technique.generate_frida_script(result.hook_points)
    assert "Java.perform" in script
    assert "Java.use(" in script
    assert FRIDA_HELPERS.strip() in script  # 通用工具函数齐全
    assert "hookMethod" in script
    # 生成的 JS 数组要能带出类名
    for hp in result.hook_points[:1]:
        assert hp.class_name.split(".")[-1] in script or hp.class_name in script


def test_script_includes_overload_signature():
    t = build_technique("base64")
    from fp_sentinel.mobile_hook.models import HookPoint

    hp = HookPoint(
        class_name="com.demo.bank.CryptoUtil",
        method_name="decrypt",
        param_signature="(Ljava/lang/String;I)[B",
        technique="base64",
        confidence=0.5,
    )
    script = t.generate_frida_script([hp])
    assert "'java.lang.String', 'int'" in script  # overload 参数按签名展开


def test_js_array_empty_and_filled():
    assert _js_array([]) == "[]"
    js = _js_array([{"clazz": "a.B", "method": "c", "sig": ["int"]}])
    assert "a.B" in js and "'int'" in js


def test_technique_hookpoint_factory_defaults():
    t = build_technique("toast")
    hp = t.make_hook_point("a.B", "c")
    assert hp.technique == "toast"
    assert hp.source == "static"
    assert hp.reason == "toast 技法命中"


def test_technique_result_timer(sample_context):
    t = build_technique("log")
    result = t.analyze(sample_context)
    assert result.duration_ms >= 0
    assert result.success


def test_technique_result_fail_priority():
    from fp_sentinel.mobile_hook.models import TechniqueResult

    r = TechniqueResult.fail("x", error="custom", exc=RuntimeError("ignored"))
    assert r.error == "custom"
    r2 = TechniqueResult.fail("x", exc=RuntimeError("boom2"))
    assert "boom2" in r2.error


@pytest.mark.parametrize("name", TECHNIQUE_NAMES)
def test_system_hook_points_declared(name):
    t = build_technique(name)
    for point in t.system_hook_points():
        assert {"clazz", "method", "sig"} <= set(point)


@pytest.mark.parametrize("name", TECHNIQUE_NAMES)
def test_analyze_respects_limit(sample_context, name):
    result = build_technique(name).analyze(sample_context, limit=1)
    assert result.success
    assert len(result.hook_points) <= 1


def test_verify_hook_without_context_skips_static():
    """无 APK 上下文时，静态复核跳过（mock 放行），脚本合法性仍校验。"""
    from fp_sentinel.mobile_hook.core.base import HookLocator
    from fp_sentinel.mobile_hook.models import HookPoint

    loc = HookLocator()
    hp = HookPoint(
        class_name="com.demo.bank.CryptoUtil", method_name="encrypt",
        param_signature="", technique="base64", confidence=0.5,
    )
    verdict = loc.verify_hook(hp)
    assert verdict["static_checked"] is False
    assert verdict["verified"] is True


def test_parse_descriptor_with_spaces():
    """androguard 描述符可能含空格：'(Landroid/content/Context; Landroid/content/Intent;)'"""
    assert parse_descriptor("(Landroid/content/Context; Landroid/content/Intent;)V") == [
        "android.content.Context", "android.content.Intent",
    ]
    assert return_type("(I) Ljava/lang/String;") == "java.lang.String"


# ────────────────────────── sig_utils ──────────────────────────

def test_parse_descriptor_primitives():
    assert parse_descriptor("()V") == []
    assert parse_descriptor("(IJBDSCFZ)V") == [
        "int", "long", "byte", "double", "short", "char", "float", "boolean",
    ]


def test_parse_descriptor_objects_and_arrays():
    assert parse_descriptor("(Ljava/lang/String;[B)V") == ["java.lang.String", "byte[]"]
    assert parse_descriptor("([[I)Ljava/lang/Object;") == ["int[][]"]
    assert parse_descriptor("") == []
    assert parse_descriptor("garbage") == []
    assert parse_descriptor("(Lno/semicolon") == []  # 缺右括号


def test_parse_descriptor_illegal_raises():
    with pytest.raises(ValueError):
        parse_descriptor("(X)V")


def test_return_type():
    assert return_type("(I)V") == "void"
    assert return_type("()[Ljava/lang/String;") == "java.lang.String[]"
    assert return_type("bad") == ""
