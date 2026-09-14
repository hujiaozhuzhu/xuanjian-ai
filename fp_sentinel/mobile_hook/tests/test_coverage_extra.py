# -*- coding: utf-8 -*-
"""补充覆盖：CLI 全分支、假 androguard 加载、frida/watcher 降级路径、边界用例。"""

from __future__ import annotations

import json
import sys
import types

import pytest
from typer.testing import CliRunner

from fp_sentinel.mobile_hook.core.apk_context import StaticApkContext
from fp_sentinel.mobile_hook.techniques.sig_utils import parse_descriptor, return_type

from .conftest import SAMPLE_CONTEXT_DATA

# ══════════════════════════ CLI 全分支 ══════════════════════════


@pytest.fixture()
def patched_apk_context(monkeypatch):
    """让 ApkContext.from_apk 返回样本上下文（不依赖真实 APK）。"""
    from fp_sentinel.mobile_hook.core import base as core_base

    def fake_from_apk(path, force_reload=False):
        data = dict(SAMPLE_CONTEXT_DATA)
        data["apk_path"] = str(path)
        return StaticApkContext(data)

    monkeypatch.setattr(core_base.ApkContext, "from_apk", staticmethod(fake_from_apk))


class TestCliFull:
    def _apk(self, tmp_path):
        apk = tmp_path / "fake.apk"
        apk.write_bytes(b"PK\x03\x04fake")
        return apk

    def test_recommend_full_output(self, tmp_path, patched_apk_context):
        from fp_sentinel.mobile_hook.cli import hook_app

        out_file = tmp_path / "rec.json"
        res = CliRunner().invoke(
            hook_app,
            ["recommend", str(self._apk(tmp_path)), "--top", "3",
             "--output", str(out_file)],
        )
        assert res.exit_code == 0, res.output
        assert "Rank" in res.output
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data["package_name"] == "com.demo.bank"
        assert len(data["hook_points"]) <= 3

    def test_technique_success_with_script(self, tmp_path, patched_apk_context):
        from fp_sentinel.mobile_hook.cli import hook_app

        out_file = tmp_path / "tech.json"
        script_file = tmp_path / "trace.js"
        res = CliRunner().invoke(
            hook_app,
            ["technique", "base64", "--apk", str(self._apk(tmp_path)),
             "--output", str(out_file), "--script", str(script_file)],
        )
        assert res.exit_code == 0, res.output
        assert script_file.exists()
        assert "Java.perform" in script_file.read_text(encoding="utf-8")

    def test_scan_all(self, tmp_path, patched_apk_context):
        from fp_sentinel.mobile_hook.cli import hook_app

        out_file = tmp_path / "scan.json"
        res = CliRunner().invoke(
            hook_app,
            ["scan", str(self._apk(tmp_path)), "--techniques", "all",
             "--goal", "request-plaintext", "--top", "5",
             "--output", str(out_file)],
        )
        assert res.exit_code == 0, res.output
        assert "组合扫描完成" in res.output

    def test_scan_explicit_list(self, tmp_path, patched_apk_context):
        from fp_sentinel.mobile_hook.cli import hook_app

        res = CliRunner().invoke(
            hook_app,
            ["scan", str(self._apk(tmp_path)), "--techniques", "base64,log"],
        )
        assert res.exit_code == 0, res.output

    def test_technique_invalid_apk(self, tmp_path):
        from fp_sentinel.mobile_hook.cli import hook_app

        res = CliRunner().invoke(
            hook_app,
            ["technique", "base64", "--apk", str(tmp_path / "missing.apk")],
        )
        assert res.exit_code == 2

    def test_recommend_invalid_apk(self, tmp_path):
        from fp_sentinel.mobile_hook.cli import hook_app

        res = CliRunner().invoke(
            hook_app, ["recommend", str(tmp_path / "missing.apk")],
        )
        assert res.exit_code != 0


# ══════════════════════════ 假 androguard 上下文加载 ══════════════════════════


class TestFakeAndroguardLoad:
    """用假 androguard 对象覆盖 _AndroguardContext._load 的解析逻辑。"""

    def _fake_androguard(self, monkeypatch):
        class FakeStringInsn:
            def get_op_value(self):
                return 0x1A

            def get_string(self):
                return "AES/CBC/PKCS5Padding"

        class FakeOtherInsn:
            def get_op_value(self):
                return 0x54

        class FakeMethodId:
            def __init__(self, name, cls):
                self.name = name
                self.cls = cls

            def get_name(self):
                return self.name

            def get_class_name(self):
                return self.cls

        class FakeCallee:
            name = "doFinal"

            def get_class_name(self):
                return "Ljavax/crypto/Cipher;"

            def get_descriptor(self):
                return "([B)[B"

        class FakeMA:
            def get_xref_to(self):
                return [(None, FakeCallee(), 8)]

        class FakeEncodedMethod:
            def get_name(self):
                return "encrypt"

            def get_descriptor(self):
                return "(Ljava/lang/String;) Ljava/lang/String;"

            def get_instructions(self):
                return [FakeStringInsn(), FakeOtherInsn()]

        class FakeDexClass:
            def get_name(self):
                return "Lcom/fake/app/Crypto;"

            def get_methods(self):
                return [FakeEncodedMethod()]

        class FakeDex:
            def get_classes(self):
                return [FakeDexClass()]

        class FakeApk:
            def get_package(self):
                return "com.fake.app"

            def get_activities(self):
                return ["com.fake.app.MainActivity"]

            def get_services(self):
                return []

            def get_receivers(self):
                return []

            def get_providers(self):
                return []

        def fake_analyze(apk_path):
            return FakeApk(), [FakeDex()], FakeAnalysis()

        class FakeAnalysis:
            def get_method(self, em):
                return FakeMA()

        misc = types.ModuleType("androguard.misc")
        misc.AnalyzeAPK = fake_analyze
        dex_mod = types.ModuleType("androguard.core.dex")
        monkeypatch.setitem(sys.modules, "androguard", types.ModuleType("androguard"))
        monkeypatch.setitem(sys.modules, "androguard.misc", misc)
        monkeypatch.setitem(sys.modules, "androguard.core", types.ModuleType("androguard.core"))
        monkeypatch.setitem(sys.modules, "androguard.core.dex", dex_mod)

    def test_load_via_fake_androguard(self, monkeypatch, tmp_path):
        from fp_sentinel.mobile_hook.core.apk_context import ApkContext

        self._fake_androguard(monkeypatch)
        apk = tmp_path / "fake.apk"
        apk.write_bytes(b"PK")

        ctx = ApkContext.from_apk(str(apk))
        assert ctx.package_name == "com.fake.app"
        assert "com.fake.app.MainActivity" in ctx.entry_point_list
        cls = ctx.get_class("com.fake.app.Crypto")
        assert cls is not None
        m = cls.method("encrypt")
        assert m.strings == ["AES/CBC/PKCS5Padding"]
        assert m.invokes == [("javax.crypto.Cipher", "doFinal")]
        # 缓存命中路径
        ctx2 = ApkContext.from_apk(str(apk))
        assert ctx2.get_class("com.fake.app.Crypto") is not None

    def test_get_method_absent_dx(self, monkeypatch, tmp_path):
        """dx 无 get_method 时 xref 解析静默降级为空。"""
        from fp_sentinel.mobile_hook.core.apk_context import ApkContext

        self._fake_androguard(monkeypatch)

        class NoGetMethod:
            pass

        class FakeDex2:
            def get_classes(self):
                return []

        class FakeApk2:
            def get_package(self):
                return "p"

            def get_activities(self):
                return []

            def get_services(self):
                return []

            def get_receivers(self):
                return []

            def get_providers(self):
                return []

        misc = sys.modules["androguard.misc"]
        misc.AnalyzeAPK = lambda p: (FakeApk2(), [FakeDex2()], NoGetMethod())

        apk = tmp_path / "fake2.apk"
        apk.write_bytes(b"PK")
        ctx = ApkContext.from_apk(str(apk), force_reload=True)
        assert ctx.summary()["classes"] == 0

    def test_load_bad_instruction_raises_guarded(self, monkeypatch, tmp_path):
        """单方法指令遍历异常不影响整体加载。"""
        from fp_sentinel.mobile_hook.core.apk_context import ApkContext

        class BoomInsn:
            def get_op_value(self):
                raise RuntimeError("bad insn")

        class FakeMethod:
            def get_name(self):
                return "broken"

            def get_descriptor(self):
                return "()V"

            def get_instructions(self):
                return [BoomInsn()]

        class FakeDexClass:
            def get_name(self):
                return "Lcom/fake/app/Bad;"

            def get_methods(self):
                return [FakeMethod()]

        class FakeDex:
            def get_classes(self):
                return [FakeDexClass()]

        class FakeApk:
            def get_package(self):
                return "com.fake.app"

            def get_activities(self):
                return []

            def get_services(self):
                return []

            def get_receivers(self):
                return []

            def get_providers(self):
                return []

        misc = types.ModuleType("androguard.misc")

        class NoXrefMA:
            def get_xref_to(self):
                raise RuntimeError("xref fail")

        class FakeAnalysis:
            def get_method(self, em):
                return NoXrefMA()

        misc.AnalyzeAPK = lambda p: (FakeApk(), [FakeDex()], FakeAnalysis())
        monkeypatch.setitem(sys.modules, "androguard", types.ModuleType("androguard"))
        monkeypatch.setitem(sys.modules, "androguard.misc", misc)
        monkeypatch.setitem(sys.modules, "androguard.core", types.ModuleType("androguard.core"))
        monkeypatch.setitem(sys.modules, "androguard.core.dex", types.ModuleType("androguard.core.dex"))

        apk = tmp_path / "fake3.apk"
        apk.write_bytes(b"PK")
        ctx = ApkContext.from_apk(str(apk))
        assert ctx.get_class("com.fake.app.Bad") is not None

    def test_dvm_fallback_import(self, monkeypatch, tmp_path):
        """旧版 androguard (core.bytecodes.dvm) 回退导入路径。"""
        from fp_sentinel.mobile_hook.core.apk_context import _AndroguardContext

        misc = types.ModuleType("androguard.misc")
        misc.AnalyzeAPK = lambda p: None
        core_pkg = types.ModuleType("androguard.core")
        core_pkg.__path__ = []  # 标记为 package
        bc_pkg = types.ModuleType("androguard.core.bytecodes")
        bc_pkg.__path__ = []
        dvm_mod = types.ModuleType("androguard.core.bytecodes.dvm")
        monkeypatch.setitem(sys.modules, "androguard", types.ModuleType("androguard"))
        monkeypatch.setitem(sys.modules, "androguard.misc", misc)
        monkeypatch.setitem(sys.modules, "androguard.core", core_pkg)
        monkeypatch.setitem(sys.modules, "androguard.core.bytecodes", bc_pkg)
        monkeypatch.setitem(sys.modules, "androguard.core.bytecodes.dvm", dvm_mod)
        # 主路径（core.dex）必须失败才能走进回退
        monkeypatch.delitem(sys.modules, "androguard.core.dex", raising=False)
        import importlib

        real_import = importlib.import_module

        def fake_import(name):
            if name == "androguard.core.dex":
                raise ImportError("no dex module in this fake")
            return real_import(name)

        import builtins

        orig_import = builtins.__import__

        def guard(name, *args, **kwargs):
            if name == "androguard.core.dex":
                raise ImportError("no dex module in this fake")
            return orig_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", guard)
        fn, mod = _AndroguardContext._import_androguard()
        assert fn is misc.AnalyzeAPK
        assert mod is dvm_mod

    def test_androguard_import_error_message(self, monkeypatch):
        from fp_sentinel.mobile_hook.core.apk_context import (
            AndroguardUnavailableError,
            _AndroguardContext,
        )

        monkeypatch.setitem(sys.modules, "androguard", None)  # import 触发 ImportError
        with pytest.raises(AndroguardUnavailableError):
            _AndroguardContext._import_androguard()


# ══════════════════════════ frida / watcher 降级 ══════════════════════════


class TestFridaDegrade:
    def test_is_available_false_when_no_frida(self, monkeypatch):
        from fp_sentinel.mobile_hook.dynamic import FridaTracer

        monkeypatch.setitem(sys.modules, "frida", None)
        tracer = FridaTracer()
        assert tracer.is_available() is False

    def test_import_error_on_attach_without_frida(self, monkeypatch):
        from fp_sentinel.mobile_hook.dynamic import (
            FridaTracer,
            FridaUnavailableError,
        )

        monkeypatch.setitem(sys.modules, "frida", None)
        tracer = FridaTracer(dry_run=False, package="com.x")
        with pytest.raises(FridaUnavailableError):
            tracer.attach([])

    def test_watcher_start_fallback_on_unavailable_frida(self, monkeypatch):
        from fp_sentinel.mobile_hook.dynamic import MemoryWatcher

        monkeypatch.setitem(sys.modules, "frida", None)
        watcher = MemoryWatcher(dry_run=False, package="com.x")
        out = watcher.start()
        assert out["mode"] == "static_fallback"
        assert "降级" in out["message"]

    def test_watcher_live_start_attach_failure_falls_back(self, monkeypatch):
        from fp_sentinel.mobile_hook.dynamic import MemoryWatcher

        class BrokenTracer:
            def __init__(self, **kw):
                pass

            def is_available(self):
                return True

            def attach(self, points, on_message=None):
                raise RuntimeError("attach boom")

        import fp_sentinel.mobile_hook.dynamic.watcher as wmod
        monkeypatch.setattr(wmod, "FridaTracer", BrokenTracer)

        watcher = MemoryWatcher(dry_run=False, package="com.x")
        out = watcher.start()
        assert out["mode"] == "static_fallback"
        assert "attach boom" in out["message"]


# ══════════════════════════ 边界用例 ══════════════════════════


def test_sig_utils_edge_cases():
    assert parse_descriptor("([[[I)V") == ["int[][][]"]
    assert parse_descriptor("(Ljava/lang/String;)", ) == ["java.lang.String"]
    assert return_type("bad)string") == "string"  # 非法返回类型原样返回
    assert return_type("") == ""


def test_scorer_learn_write_failure(sample_context, tmp_path):
    from fp_sentinel.mobile_hook.core.critical_scorer import CriticalScorer

    # 把经验文件路径指向一个目录 -> 写入失败被吞掉
    scorer = CriticalScorer(sample_context, experience_file=str(tmp_path))
    scorer.learn("base64", success=True)
    assert scorer.experience_score("base64") >= 0


def test_scorer_experience_non_numeric_ignored(sample_context, tmp_path):
    from fp_sentinel.mobile_hook.core.critical_scorer import EXPERIENCE_PRIOR, CriticalScorer

    f = tmp_path / "exp.json"
    f.write_text(json.dumps({"base64": "not-a-number", "custom": 0.9}), encoding="utf-8")
    scorer = CriticalScorer(sample_context, experience_file=str(f))
    assert scorer.experience_score("base64") == EXPERIENCE_PRIOR["base64"]
    assert scorer.experience_score("custom") == 0.9


def test_call_chain_callees_deep(sample_context):
    from fp_sentinel.mobile_hook.core.call_chain_analyzer import CallChainAnalyzer

    analyzer = CallChainAnalyzer(sample_context)
    analyzer.invalidate()  # 强制重建索引覆盖 invalidate 分支
    callees = analyzer.callers_of("com.demo.bank.CryptoUtil", "decrypt", depth=2)
    assert ("com.demo.bank.LoginReceiver", "onReceive") in callees


def test_call_chain_analyzer_rebuild_after_invalidate(sample_context):
    from fp_sentinel.mobile_hook.core.call_chain_analyzer import CallChainAnalyzer

    analyzer = CallChainAnalyzer(sample_context)
    assert analyzer.callers_of("com.demo.bank.CryptoUtil", "encrypt")
    analyzer.invalidate()
    assert analyzer.callers_of("com.demo.bank.CryptoUtil", "encrypt")


def test_recommendation_top_and_degraded_flag(locator):
    rec = locator.recommend()
    rec2 = locator.recommend()
    assert rec.timestamp > 0
    assert rec.degraded is False
    assert rec.top.confidence == max(p.confidence for p in rec.hook_points)


def test_js_array_special_chars():
    from fp_sentinel.mobile_hook.techniques.base import _js_array

    js = _js_array([{"clazz": "a.B$Inner", "method": "<init>", "sig": []}])
    assert "a.B$Inner" in js and "<init>" in js
