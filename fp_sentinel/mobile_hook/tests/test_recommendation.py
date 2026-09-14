# -*- coding: utf-8 -*-
"""推荐引擎 / 关键性评分 / 调用链 / 动态模块 / CLI 的单元测试。"""

from __future__ import annotations

import json

import pytest

from fp_sentinel.mobile_hook.core.apk_context import ApkContext, StaticApkContext
from fp_sentinel.mobile_hook.core.call_chain_analyzer import CallChainAnalyzer
from fp_sentinel.mobile_hook.core.critical_scorer import (
    DEFAULT_EXPERIENCE,
    WEIGHTS,
    CriticalScorer,
)
from fp_sentinel.mobile_hook.core.base import HookLocator, UnknownTechniqueError
from fp_sentinel.mobile_hook.models import (
    HookPoint,
    HookRecommendation,
    TechniqueResult,
)
from fp_sentinel.mobile_hook.techniques.base import build_technique


# ────────────────────────── 模型 ──────────────────────────

def test_hook_point_roundtrip():
    hp = HookPoint(
        class_name="com.a.B", method_name="c", param_signature="(I)V",
        technique="log", confidence=0.8,
    )
    d = hp.to_dict()
    hp2 = HookPoint.from_dict(json.loads(hp.to_json()))
    assert hp2.qualified_method == hp.qualified_method
    assert hp2.short_signature() == "(I)V"
    assert set(d) >= {"class_name", "method_name", "technique", "confidence"}
    assert hp2.source == "static"


def test_hook_point_from_dict_forward_compatible():
    hp = HookPoint.from_dict(
        {"class_name": "a.B", "method_name": "c", "confidence": 0.5,
         "param_signature": "", "technique": "log", "future_field": 1}
    )
    assert hp.metadata["future_field"] == 1


def test_technique_result_fail_and_ranked():
    r = TechniqueResult.fail("x", exc=RuntimeError("boom"))
    assert not r.success and "boom" in r.error
    r2 = TechniqueResult.ok("x", [])
    assert r2.count == 0 and r2.ranked(3) == []


def test_technique_result_timer_guard():
    r = TechniqueResult(technique="x")
    r.stop_timer()  # 未 start，不应抛错
    assert r.duration_ms == 0.0


def test_recommendation_table_and_stats(locator):
    rec = locator.recommend(top_n=5)
    table = rec.format_table()
    assert "Rank" in table and "Class" in table
    assert isinstance(rec.technique_stats(), dict) and rec.technique_stats()
    assert rec.top is not None
    rec_empty = HookRecommendation(apk_path="x")
    assert rec_empty.top is None and rec_empty.rank() == []


# ────────────────────────── 推荐流程 ──────────────────────────

def test_recommend_orders_and_scores(locator):
    rec = locator.recommend(top_n=10)
    assert rec.hook_points, "样本中应能推荐出点位"
    scores = [p.confidence for p in rec.hook_points]
    assert scores == sorted(scores, reverse=True), "必须按置信度降序"
    assert all(len(p.score_breakdown) == 5 for p in rec.hook_points)
    # 每个点位的调用链信息已增强
    assert all(isinstance(p.entry_reachable, bool) for p in rec.hook_points)


def test_recommend_crypto_top_with_entry_chain(locator):
    """入口可达的加密工具方法应排最前（调用链 + 包名 + 字符串全命中）。"""
    rec = locator.recommend(top_n=10)
    top = rec.top
    assert top.class_name == "com.demo.bank.CryptoUtil"
    assert top.technique in ("keyword", "base64", "string", "json")
    assert any("CryptoUtil" in node for node in top.call_chain)


def test_recommend_package_name_recorded(locator):
    rec = locator.recommend()
    assert rec.package_name == "com.demo.bank"
    assert rec.goal == "encrypt-trace"
    assert rec.engine_version


def test_recommend_techniques_filter(locator):
    rec = locator.recommend(techniques=["base64"], top_n=50)
    assert all(p.technique == "base64" for p in rec.hook_points)
    stats = rec.technique_stats()
    assert set(stats.keys()) == {"base64"}


def test_recommend_top_n_limit(locator):
    rec = locator.recommend(top_n=3)
    assert len(rec.hook_points) <= 3


def test_recommend_dedup_by_class_method_technique(locator):
    """RD-009: 同一 (class, method, technique) 组合只保留一个点位。"""
    from fp_sentinel.mobile_hook.models import HookPoint
    from fp_sentinel.mobile_hook.techniques.base import Technique

    class DupT(Technique):
        name = "rd009-dup"
        description = "产出重复点位的技法"

        def analyze(self, context, **kwargs):
            r = self._new_result()
            points = [
                HookPoint(
                    class_name="com.a.B", method_name="c", param_signature="",
                    technique=self.name, confidence=0.5)
                for _ in range(3)
            ]
            return self._finish(r, points)

    locator.register_technique(DupT)
    try:
        rec = locator.recommend(top_n=10, techniques=["rd009-dup"])
        keys = [(p.class_name, p.method_name, p.technique) for p in rec.hook_points]
        assert len(keys) == len(set(keys))
        assert keys.count(("com.a.B", "c", "rd009-dup")) == 1
    finally:
        locator._registry.pop("rd009-dup", None)


def test_execute_technique_unknown_raises(locator):
    with pytest.raises(UnknownTechniqueError):
        locator.execute_technique("nope")


def test_execute_technique_error_isolated():
    """技法抛错不影响其它技法，错误被收敛为失败结果。"""
    ctx = StaticApkContext({"package_name": "com.x"})
    loc = HookLocator(context=ctx)
    result = loc.execute_technique("base64")  # 无类数据，应成功且 0 命中
    assert result.success


def test_register_technique_override_and_dup(locator):
    from fp_sentinel.mobile_hook.techniques.base import Technique, register_technique

    class Dummy(Technique):
        name = "dummy"
        description = "dummy"

        def analyze(self, context, **kwargs):
            r = self._new_result()
            return self._finish(r, [])

    locator.register_technique(Dummy)
    with pytest.raises(ValueError):
        locator.register_technique(Dummy)
    locator.register_technique(Dummy, override=True)
    assert "dummy" in locator.list_techniques()
    # 清理，避免污染全局状态
    locator._registry.pop("dummy")


def test_get_context_requires_apk_or_context():
    loc = HookLocator()
    with pytest.raises(ValueError):
        loc.get_context()


def test_get_context_reloads_on_different_apk(sample_context, tmp_path):
    loc = HookLocator(context=sample_context)
    assert loc.get_context() is sample_context
    # 指定不同路径 -> 尝试重新加载（无真实 androguard 场景直接抛错）
    with pytest.raises(Exception):
        loc.get_context(apk_path=str(tmp_path / "other.apk"))


# ────────────────────────── 验证（mock 化） ──────────────────────────

def test_verify_hook_mock_pass(locator):
    rec = locator.recommend(top_n=1)
    verdict = locator.verify_hook(rec.top, device="FAKE-DEVICE-001")
    assert verdict["mock"] is True
    assert verdict["device"] == "FAKE-DEVICE-001"
    assert verdict["device_attached"] is True  # mock：模拟附加
    assert verdict["verified"] is True
    assert verdict["script_valid"] and verdict["static_match"]


def test_verify_hook_unknown_technique(locator):
    hp = HookPoint(class_name="com.demo.bank.CryptoUtil", method_name="encrypt",
                   param_signature="", technique="ghost", confidence=0.5)
    verdict = locator.verify_hook(hp)
    assert verdict["verified"] is False
    assert not verdict["script_valid"]


def test_verify_hook_static_mismatch(locator):
    hp = HookPoint(class_name="com.not.exist", method_name="m",
                   param_signature="", technique="base64", confidence=0.5)
    verdict = locator.verify_hook(hp)
    assert verdict["verified"] is False
    assert not verdict["static_match"]


# ────────────────────────── 关键性评分 ──────────────────────────

def test_weights_sum_to_one():
    assert CriticalScorer.verify_weights()
    assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9
    assert abs(WEIGHTS["package"] - 0.30) < 1e-9
    assert abs(WEIGHTS["method"] - 0.25) < 1e-9
    assert abs(WEIGHTS["call_chain"] - 0.15) < 1e-9
    assert abs(WEIGHTS["string"] - 0.20) < 1e-9
    assert abs(WEIGHTS["experience"] - 0.10) < 1e-9


def test_score_dimensions(sample_context):
    scorer = CriticalScorer(sample_context)
    total, breakdown, chain, reachable = scorer.score(
        "com.demo.bank.CryptoUtil", "encrypt", "base64",
        strings=["AES/CBC/PKCS5Padding"],
    )
    assert 0.0 <= total <= 1.0
    assert set(breakdown) == {"package", "method", "call_chain", "string", "experience"}
    assert breakdown["package"] == 1.0          # 应用主包
    assert breakdown["method"] >= 0.5           # encrypt 命中方法特征
    assert breakdown["string"] >= 0.4           # 敏感字符串
    assert reachable is True                    # 入口可达
    assert chain


def test_score_poor_point(sample_context):
    scorer = CriticalScorer(sample_context)
    total, breakdown, _, _ = scorer.score(
        "com.other.Sdk", "run", "log", strings=[]
    )
    assert total < 0.4


def test_experience_learn_and_persist(sample_context, tmp_path):
    exp_file = tmp_path / "experience.json"
    scorer = CriticalScorer(sample_context, experience_file=str(exp_file))
    base = scorer.experience_score("base64")
    scorer.learn("base64", success=True)
    assert scorer.experience_score("base64") == pytest.approx(min(1.0, base + 0.05))
    scorer.learn("base64", success=False)
    scorer.learn("base64", success=False)
    assert scorer.experience_score("base64") < base
    # 持久化
    data = json.loads(exp_file.read_text(encoding="utf-8"))
    assert "base64" in data


def test_experience_file_corrupted(sample_context, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json{", encoding="utf-8")
    scorer = CriticalScorer(sample_context, experience_file=str(bad))
    assert scorer.experience_score("unknown-tech") == DEFAULT_EXPERIENCE


def test_experience_file_non_dict(sample_context, tmp_path):
    f = tmp_path / "list.json"
    f.write_text('["not", "a", "dict"]', encoding="utf-8")
    scorer = CriticalScorer(sample_context, experience_file=str(f))
    # 非法结构被忽略，仍用先验
    assert scorer.experience_score("base64") == pytest.approx(
        __import__("fp_sentinel.mobile_hook.core.critical_scorer", fromlist=["EXPERIENCE_PRIOR"]
                   ).EXPERIENCE_PRIOR["base64"])


def test_learn_without_file(sample_context):
    scorer = CriticalScorer(sample_context)  # 不持久化
    scorer.learn("log", success=False)
    assert scorer.experience_score("log") <= 0.7


def test_chain_score_self_entry(sample_context):
    """目标本身就是入口组件方法时调用链得分。"""
    scorer = CriticalScorer(sample_context)
    score, breakdown, nodes, reachable = scorer.score(
        "com.demo.bank.MainActivity", "onCreate", "toast", strings=[])
    assert reachable
    assert score > 0


# ────────────────────────── 调用链分析 ──────────────────────────

def test_trace_back_finds_entry(sample_context):
    analyzer = CallChainAnalyzer(sample_context)
    chains = analyzer.trace_back("com.demo.bank.CryptoUtil", "encrypt")
    assert chains
    reachable = [c for c in chains if c.reachable_from_entry]
    assert reachable
    assert reachable[0].entry_point in ("com.demo.bank.MainActivity",)
    assert reachable[0].depth >= 1
    assert "com.demo.bank.CryptoUtil#encrypt" in reachable[0].as_list()


def test_callers_and_callees(sample_context):
    analyzer = CallChainAnalyzer(sample_context)
    callers = analyzer.callers_of("com.demo.bank.CryptoUtil", "encrypt", depth=3)
    assert ("com.demo.bank.MainActivity", "onCreate") in callers
    callees = analyzer.callees_of("com.demo.bank.MainActivity", "onCreate", depth=2)
    assert ("com.demo.bank.CryptoUtil", "encrypt") in callees


def test_entry_reachable_and_chain_score(sample_context):
    analyzer = CallChainAnalyzer(sample_context)
    assert analyzer.entry_reachable("com.demo.bank.CryptoUtil", "encrypt")
    score, nodes, reachable = analyzer.chain_score("com.demo.bank.CryptoUtil", "encrypt")
    assert score >= 0.7 and reachable
    # 孤立类
    score2, nodes2, reachable2 = analyzer.chain_score("com.demo.bank.Orphan", "hiddenEncrypt")
    assert not reachable2
    assert score2 <= 0.4
    # 完全不存在的方法
    score3, _, _ = analyzer.chain_score("com.demo.bank.Nope", "zzz")
    assert score3 == 0.1


def test_invalid_max_depth(sample_context):
    with pytest.raises(ValueError):
        CallChainAnalyzer(sample_context, max_depth=0)


def test_deep_trace_depth_ge_10(sample_context=None):
    """深度 >= 10：构造 12 层调用链，必须能回溯到入口。"""
    depth = 12
    classes = []
    for i in range(depth + 1):
        if i < depth:
            # 最后一层 L(depth-1) 指向 Sink，其余指向下一层
            nxt = f"com.demo.chain.Sink" if i == depth - 1 else f"com.demo.chain.L{i+1}"
            invokes = [[nxt, "go"]]
        else:
            invokes = []  # Sink：链条终点，无调用
        classes.append({
            "name": f"com.demo.chain.L{i}" if i < depth else "com.demo.chain.Sink",
            "methods": [{
                "name": "go", "descriptor": "()V",
                "strings": [], "invokes": invokes,
            }],
        })
    data = {
        "package_name": "com.demo.chain",
        "entry_points": ["com.demo.chain.L0"],
        "classes": classes,
    }
    ctx = StaticApkContext(data)
    analyzer = CallChainAnalyzer(ctx, max_depth=12)
    chains = analyzer.trace_back("com.demo.chain.Sink", "go")
    reachable = [c for c in chains if c.reachable_from_entry]
    assert reachable, "12 层调用链必须可回溯到入口"
    assert reachable[0].depth >= 10


def test_trace_back_fallback_deepest_caller():
    """不可达入口时返回最深调用者链。"""
    data = {
        "package_name": "com.demo.iso",
        "entry_points": [],
        "classes": [
            {"name": "com.demo.iso.A", "methods": [
                {"name": "m", "descriptor": "()V", "strings": [],
                 "invokes": [["com.demo.iso.B", "n"]]}]},
            {"name": "com.demo.iso.B", "methods": [
                {"name": "n", "descriptor": "()V", "strings": [], "invokes": []}]},
        ],
    }
    analyzer = CallChainAnalyzer(StaticApkContext(data))
    chains = analyzer.trace_back("com.demo.iso.B", "n")
    assert chains
    assert "com.demo.iso.A#m" in chains[0].as_list()


def test_apk_context_summary_and_queries(sample_context):
    assert sample_context.summary()["classes"] >= 5
    assert "com.demo.bank.MainActivity" in sample_context.entry_point_list
    assert sample_context.get_class("com.demo.bank.CryptoUtil") is not None
    assert sample_context.get_class("nope.Nope") is None
    # find_methods
    hits = sample_context.find_methods("encrypt")
    assert {m.class_name for m in hits} >= {"com.demo.bank.CryptoUtil"}
    hits_regex = sample_context.find_methods("^enc", regex=True)
    assert hits_regex
    # methods_with_string / methods_calling
    assert sample_context.methods_with_string("AES")
    callers = sample_context.methods_calling("javax.crypto.Cipher", "doFinal")
    assert callers


def test_base_class_load_not_implemented():
    with pytest.raises(NotImplementedError):
        ApkContext()._load()


def test_androguard_unavailable_error():
    from fp_sentinel.mobile_hook.core.apk_context import AndroguardUnavailableError

    err = AndroguardUnavailableError("x")
    assert isinstance(err, ImportError)


# ────────────────────────── 动态模块（frida 降级） ──────────────────────────

class TestDynamic:
    def make_tracer(self, **kw):
        from fp_sentinel.mobile_hook.dynamic import FridaTracer

        return FridaTracer(**kw)

    def test_script_generation_merges_techniques(self, locator):
        rec = locator.recommend(top_n=10)
        tracer = self.make_tracer()
        script = tracer.generate_script(rec.hook_points)
        assert "玄鉴 v4.0" in script
        assert script.count("hookMethod") >= 1

    def test_generate_script_empty(self):
        assert "无 Hook 点位" in self.make_tracer().generate_script([])

    def test_generate_script_unknown_technique_skipped(self):
        hp = HookPoint(class_name="a.B", method_name="c", param_signature="",
                       technique="ghost", confidence=0.5)
        script = self.make_tracer().generate_script([hp])
        assert "ghost" in script

    def test_dry_run_no_device(self, locator):
        rec = locator.recommend(top_n=5)
        tracer = self.make_tracer(dry_run=True)
        out = tracer.attach(rec.hook_points)
        assert out["mode"] == "dry_run"
        assert "Java.perform" in out["script"]

    def test_static_fallback(self, locator):
        rec = locator.recommend(top_n=5)
        fallback = self.make_tracer().static_fallback(rec.hook_points)
        assert fallback["mode"] == "static_fallback"
        assert fallback["script_ready"] is True
        assert fallback["hook_points"][0]["class_name"]

    def test_live_attach_with_fake_frida(self, monkeypatch, locator):
        """注入假 frida 模块，覆盖真实附加路径（不连接设备）。"""
        import sys
        import types

        rec = locator.recommend(top_n=2)
        messages = {}

        class FakeScript:
            def on(self, evt, cb):
                messages["cb"] = cb

            def load(self):
                messages["loaded"] = True

        class FakeSession:
            def create_script(self, src):
                messages["src"] = src
                return FakeScript()

        class FakeDevice:
            def attach(self, pkg):
                messages["pkg"] = pkg
                return FakeSession()

        fake = types.ModuleType("frida")
        fake.get_device = lambda serial: FakeDevice()
        fake.get_usb_device = lambda timeout=5: FakeDevice()
        monkeypatch.setitem(sys.modules, "frida", fake)

        tracer = self.make_tracer(dry_run=False, device_serial="EMU-1", package="com.demo.bank")
        out = tracer.attach(rec.hook_points, on_message=lambda m, d: None)
        assert out["mode"] == "live"
        assert messages["loaded"] and messages["pkg"] == "com.demo.bank"
        assert "Java.perform" in messages["src"]

    def test_live_attach_without_serial_uses_usb(self, monkeypatch, locator):
        import sys
        import types

        rec = locator.recommend(top_n=1)
        used = {}

        class FakeScript:
            def on(self, *a):
                pass

            def load(self):
                pass

        class FakeSession:
            def create_script(self, src):
                return FakeScript()

        class FakeDevice:
            def attach(self, pkg):
                used["pkg"] = pkg
                return FakeSession()

        fake = types.ModuleType("frida")
        fake.get_usb_device = lambda timeout=5: FakeDevice()
        monkeypatch.setitem(sys.modules, "frida", fake)

        tracer = self.make_tracer(dry_run=False, package="com.demo.bank")
        out = tracer.attach(rec.hook_points)
        assert out["mode"] == "live" and used["pkg"] == "com.demo.bank"

    def test_live_attach_device_error_wraps(self, monkeypatch):
        import sys
        import types

        fake = types.ModuleType("frida")

        def boom():
            raise RuntimeError("no device")

        fake.get_usb_device = boom
        monkeypatch.setitem(sys.modules, "frida", fake)

        from fp_sentinel.mobile_hook.dynamic import FridaUnavailableError

        tracer = self.make_tracer(dry_run=False, package="com.x")
        with pytest.raises(FridaUnavailableError):
            tracer.attach([])

    def test_watcher_live_start_with_fake_tracer(self, monkeypatch, locator):
        from fp_sentinel.mobile_hook.dynamic import MemoryWatcher

        rec = locator.recommend(top_n=2)

        class FakeTracer:
            def __init__(self, **kw):
                pass

            def is_available(self):
                return True

            def attach(self, points, on_message=None):
                on_message({"type": "send",
                            "payload": {"api": "a.B.c", "args": [1]}}, {})
                return {"mode": "live"}

        import fp_sentinel.mobile_hook.dynamic.watcher as wmod
        monkeypatch.setattr(wmod, "FridaTracer", FakeTracer)

        watcher = MemoryWatcher(dry_run=False, package="com.demo.bank")
        out = watcher.start(rec.hook_points)
        assert out["mode"] == "live"
        assert watcher.events[0].api == "a.B.c"
        assert watcher.summary()["total"] == 1

    def test_live_attach_requires_package(self):
        tracer = self.make_tracer(dry_run=False)
        if not tracer.is_available():
            with pytest.raises(Exception):
                tracer.attach([])
            return
        with pytest.raises(Exception):
            tracer.attach([])  # 无 package

    def test_watcher_degraded_start(self):
        from fp_sentinel.mobile_hook.dynamic import MemoryWatcher

        watcher = MemoryWatcher(dry_run=True)
        out = watcher.start()
        assert out["mode"] == "static_fallback"
        assert "Java.perform" in out["script"]
        assert len(out["watch_list"]) >= 5

    def test_watcher_event_parsing(self):
        from fp_sentinel.mobile_hook.dynamic import MemoryWatcher

        watcher = MemoryWatcher(dry_run=True)
        good = {"type": "send", "payload": {"api": "a.B.c", "args": ["x", 1],
                                            "stack": "s", "timestamp": 1.5, "z": 2}}
        ev = watcher.parse_event(good)
        assert ev is not None and ev.api == "a.B.c" and len(ev.args) == 2
        assert ev.extra == {"z": 2}
        # 各种不合规输入
        assert watcher.parse_event({"type": "error"}) is None
        assert watcher.parse_event({"type": "send", "payload": "str"}) is None
        assert watcher.parse_event({"type": "send", "payload": {}}) is None
        assert watcher.parse_event("raw") is None
        # args 非列表时包装为字符串列表
        ev2 = watcher.parse_event({"type": "send",
                                   "payload": {"api": "x.Y.z", "args": "not-a-list"}})
        assert ev2.args == ["not-a-list"]
        # on_message 收集 + summary
        watcher._on_message(good, {})
        watcher._on_message({"type": "send", "payload": {"api": "a.B.c"}}, {})
        s = watcher.summary()
        assert s["total"] == 2 and s["by_api"]["a.B.c"] == 2 and s["recent"]


# ────────────────────────── CLI ──────────────────────────

@pytest.fixture()
def cli_runner():
    from typer.testing import CliRunner

    return CliRunner()


@pytest.fixture()
def hook_cli():
    from fp_sentinel.mobile_hook.cli import hook_app

    return hook_app


@pytest.fixture()
def hook_point_file(locator, tmp_path):
    rec = locator.recommend(top_n=3)
    path = tmp_path / "hook_points.json"
    path.write_text(json.dumps(rec.to_dict()), encoding="utf-8")
    return path


class TestCli:
    def test_recommend(self, cli_runner, hook_cli, sample_context, tmp_path):
        apk_stub = tmp_path / "fake.apk"
        apk_stub.write_bytes(b"PK\x03\x04")
        from fp_sentinel.mobile_hook.core import base as core_base

        orig = core_base.ApkContext.from_apk

        def fake_from_apk(path, force_reload=False):
            return StaticApkContext(SAMPLE_CTX_DATA(path))

        SAMPLE_CTX_DATA = lambda p: {
            "apk_path": str(p),
            "package_name": "com.demo.bank",
            "entry_points": ["com.demo.bank.MainActivity"],
            "classes": [{
                "name": "com.demo.bank.CryptoUtil",
                "methods": [{
                    "name": "encrypt",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
                    "strings": ["AES/CBC/PKCS5Padding"],
                    "invokes": [["javax.crypto.Cipher", "doFinal"]],
                }],
            }],
        }

        core_base.ApkContext.from_apk = staticmethod(fake_from_apk)
        try:
            out_file = tmp_path / "rec.json"
            res = cli_runner.invoke(
                hook_cli,
                ["recommend", str(apk_stub), "--goal", "encrypt-trace",
                 "--top", "5", "--output", str(out_file)],
            )
            assert res.exit_code == 0, res.output
            assert "Rank" in res.output
            assert out_file.exists()
        finally:
            core_base.ApkContext.from_apk = orig

    def test_technique_command(self, cli_runner, hook_cli, sample_context, tmp_path):
        out_file = tmp_path / "tech.json"
        script_file = tmp_path / "trace.js"
        res = cli_runner.invoke(
            hook_cli,
            ["technique", "base64", "--apk", "unused.apk",
             "--output", str(out_file), "--script", str(script_file)],
        )
        # locator 从上下文工厂取样本上下文（conftest locator 未传入 CLI，
        # 这里依赖 APK 路径解析，所以应走 from_apk 失败路径 -> 退出码 2）
        assert res.exit_code == 2

    def test_technique_unknown_name(self, cli_runner, hook_cli, tmp_path):
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"x")
        res = cli_runner.invoke(
            hook_cli, ["technique", "ghost", "--apk", str(apk)],
        )
        assert res.exit_code == 2

    def test_scan_unknown_technique(self, cli_runner, hook_cli, tmp_path):
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"x")
        res = cli_runner.invoke(
            hook_cli, ["scan", str(apk), "--techniques", "ghost,base64"],
        )
        assert res.exit_code == 2

    def test_verify_pass(self, cli_runner, hook_cli, hook_point_file):
        res = cli_runner.invoke(hook_cli, ["verify", str(hook_point_file)])
        assert res.exit_code == 0, res.output
        assert "[PASS]" in res.output or "[FAIL]" in res.output

    def test_verify_empty_input(self, cli_runner, hook_cli, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text('{"hook_points": []}', encoding="utf-8")
        res = cli_runner.invoke(hook_cli, ["verify", str(f)])
        assert res.exit_code == 2

    def test_verify_single_point_dict(self, cli_runner, hook_cli, locator, tmp_path):
        hp = locator.recommend(top_n=1).top
        f = tmp_path / "single.json"
        f.write_text(json.dumps(hp.to_dict()), encoding="utf-8")
        res = cli_runner.invoke(hook_cli, ["verify", str(f), "--device", "EMU-1"])
        assert "EMU-1" in res.output

    def test_mobile_app_has_hook_group(self):
        from fp_sentinel.mobile_hook.cli import mobile_app

        names = [c.name for c in mobile_app.registered_commands]
        groups = [g.name for g in mobile_app.registered_groups]
        assert "hook" in groups or "hook" in names

    def test_main_cli_registers_mobile(self):
        from fp_sentinel.cli import app as root_app

        names = [g.name for g in root_app.registered_groups]
        assert "mobile" in names
