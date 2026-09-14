"""mobile_insight 单元测试 —— 67 条规则全量触发 + 引擎/模型/上下文/优先级/CLI。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from fp_sentinel.mobile_insight import __version__
from fp_sentinel.mobile_insight.cli import build_context, build_parser, main
from fp_sentinel.mobile_insight.core.context import (
    AnalysisContext,
    is_framework_class,
    is_resource_marker,
)
from fp_sentinel.mobile_insight.core.engine import InsightEngine, Rule, get_all_rules
from fp_sentinel.mobile_insight.core.priority import filter_insights, sort_insights
from fp_sentinel.mobile_insight.models.insight import (
    CodeLocation,
    DifficultyLevel,
    InsightCategory,
    InsightReport,
    Severity,
    TechnicalInsight,
)
from fp_sentinel.mobile_insight.rules import RULE_COUNT, get_all_rules
from fp_sentinel.mobile_insight.rules.anti_analysis_rules import RULES as AA
from fp_sentinel.mobile_insight.rules.component_rules import RULES as CP
from fp_sentinel.mobile_insight.rules.crypto_rules import RULES as CR
from fp_sentinel.mobile_insight.rules.network_rules import RULES as NW
from fp_sentinel.mobile_insight.rules.privacy_rules import RULES as PV
from fp_sentinel.mobile_insight.rules.storage_rules import RULES as ST

from ._regex_sample import BENIGN_STRINGS, SUSPECT_KIT, sample_for_rule

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SAMPLE_APK = (
    PROJECT_ROOT / "test_apps" / "2023移动安全培训：资料" / "3、第三阶段app漏洞"
    / "8.Android APP组件安全之Broadcast Receiver常见风险" / "InsecureBankv2.apk"
)

ALL_PACKS = [CR, NW, ST, CP, AA, PV]
EXPECTED_COUNTS = [15, 10, 11, 12, 10, 9]


def make_rule_ctx(rule: Rule) -> AnalysisContext:
    """为指定规则构造必然命中的上下文。"""
    ctx = AnalysisContext(package_name="com.test.app")
    ctx.add_strings(SUSPECT_KIT)
    ctx.add_strings(sample_for_rule(rule))
    ctx.add_classes(["com.test.app.MainActivity"])
    ctx.add_methods(["onCreate", "doRequest"])
    ctx.add_permissions([
        "android.permission.INTERNET",
        "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS", "android.permission.READ_SMS",
        "android.permission.ACCESS_FINE_LOCATION",
    ])
    ctx.add_exported_components([
        "com.test.app.MainActivity (exported=true)",
        "com.test.app.DemoService (exported=true)",
        "com.test.app.DemoReceiver (exported=true)",
        "com.test.app.DemoProvider (exported=true)",
    ])
    ctx.set_manifest_flags({"has_activity": True, "has_provider": True,
                            "has_service": True, "has_receiver": True,
                            "debuggable": True, "allow_backup": True,
                            "network_security_config": "@xml/network_security"})
    return ctx


# ============================================================ 1. 规则库完整性
class TestRuleCatalog:
    def test_total_rules_matches_count(self):
        rules = get_all_rules()
        assert len(rules) == RULE_COUNT == 67

    @pytest.mark.parametrize("pack,expected", list(zip(ALL_PACKS, EXPECTED_COUNTS)))
    def test_per_module_counts(self, pack, expected):
        assert len(pack) == expected

    def test_unique_ids(self):
        ids = [r.id for r in get_all_rules()]
        assert len(set(ids)) == len(ids)

    def test_every_rule_has_cwe_and_masvs(self):
        for rule in get_all_rules():
            assert rule.cwe_ids, f"{rule.id} missing CWE"
            assert all(c.startswith("CWE-") for c in rule.cwe_ids), rule.id
            assert rule.masvs_refs, f"{rule.id} missing MASVS"
            assert all(m.startswith("MASVS-") for m in rule.masvs_refs), rule.id

    def test_every_rule_has_guidance(self):
        for rule in get_all_rules():
            assert rule.title and rule.description and rule.technical_context
            assert rule.next_steps, f"{rule.id} missing next_steps"
            assert rule.suggested_technique

    def test_category_mapping(self):
        assert {r.category for r in CR} == {InsightCategory.CRYPTO}
        assert {r.category for r in NW} == {InsightCategory.NETWORK}
        assert {r.category for r in ST} == {InsightCategory.STORAGE}
        assert {r.category for r in CP} == {InsightCategory.COMPONENT}
        assert {r.category for r in AA} == {InsightCategory.ANTI_ANALYSIS}
        assert {r.category for r in PV} == {InsightCategory.PRIVACY}

    def test_confidence_range(self):
        for rule in get_all_rules():
            assert 0.0 < rule.confidence <= 1.0


# ============================================================ 2. 全规则触发
class TestAllRulesFire:
    def test_every_rule_triggers_on_curated_context(self):
        for rule in get_all_rules():
            ctx = make_rule_ctx(rule)
            evidence = rule.match(ctx)
            assert evidence, f"{rule.id} did not fire on curated context"

    def test_no_false_positive_on_benign_context(self):
        ctx = AnalysisContext(package_name="com.benign")
        ctx.add_strings(BENIGN_STRINGS)
        engine = InsightEngine()
        report = engine.run(ctx, target="benign")
        assert report.insights == [], \
            [i.rule_id for i in report.insights]

    def test_every_rule_builds_insight(self):
        engine = InsightEngine()
        for rule in engine.rules:
            ctx = make_rule_ctx(rule)
            report = InsightEngine(rules=[rule], auto_sort=False).run(ctx)
            assert len(report.insights) == 1, rule.id
            insight = report.insights[0]
            assert insight.id == f"INS-{rule.id}"
            assert insight.severity == rule.severity
            assert insight.category == rule.category
            assert insight.cwe_ids == rule.cwe_ids
            assert insight.fix_hint == rule.fix_hint
            assert insight.evidence


# ============================================================ 3. 引擎
class TestInsightEngine:
    def test_default_engine_registers_all(self):
        engine = InsightEngine()
        assert len(engine.rules) == 67

    def test_register_duplicate_id(self):
        rule = Rule(id="X-001", title="t", category=InsightCategory.CRYPTO,
                    severity=Severity.LOW, confidence=0.5, patterns=["a"],
                    description="d", technical_context="c", suggested_technique="s",
                    next_steps=["n"])
        engine = InsightEngine(rules=[rule])
        with pytest.raises(ValueError, match="duplicate"):
            engine.register(rule)

    def test_register_rule_without_matcher(self):
        bad = Rule(id="X-002", title="t", category=InsightCategory.CRYPTO,
                   severity=Severity.LOW, confidence=0.5, patterns=[],
                   description="d", technical_context="c", suggested_technique="s",
                   next_steps=["n"])
        engine = InsightEngine(rules=[])
        with pytest.raises(ValueError, match="patterns or check"):
            engine.register(bad)

    def test_check_based_rule(self):
        rule = Rule(id="X-003", title="t", category=InsightCategory.CRYPTO,
                    severity=Severity.LOW, confidence=0.5, patterns=[],
                    description="d", technical_context="c", suggested_technique="s",
                    next_steps=["n"],
                    check=lambda ctx: ["evidence"] if ctx.has_signal("password") else [])
        ctx = AnalysisContext()
        ctx.add_strings(["password"])
        report = InsightEngine(rules=[rule]).run(ctx)
        assert report.rules_matched == 1 and report.insights[0].evidence == ["evidence"]

    def test_check_returning_none_is_safe(self):
        rule = Rule(id="X-004", title="t", category=InsightCategory.CRYPTO,
                    severity=Severity.LOW, confidence=0.5, patterns=["nomatch"],
                    description="d", technical_context="c", suggested_technique="s",
                    next_steps=["n"], check=lambda ctx: None)
        report = InsightEngine(rules=[rule]).run(AnalysisContext())
        assert report.insights == []

    def test_run_with_category_filter(self):
        ctx = make_rule_ctx(get_all_rules()[0])
        ctx.add_strings(["http://plain.example.com"])
        report = InsightEngine().run(ctx, category=InsightCategory.NETWORK)
        assert report.insights and all(
            i.category == InsightCategory.NETWORK for i in report.insights)

    def test_run_with_min_severity(self):
        ctx = make_rule_ctx(get_all_rules()[0])
        ctx.add_strings(["http://plain.example.com", "password=abc12345"])
        report = InsightEngine().run(ctx, min_severity=Severity.HIGH)
        assert all(i.severity.value >= Severity.HIGH.value for i in report.insights)

    def test_run_report_stats(self):
        ctx = make_rule_ctx(CR[0])
        report = InsightEngine().run(ctx, target="demo.apk")
        assert report.rules_total == 67
        assert report.rules_matched >= 1
        assert report.duration_sec >= 0
        assert report.to_dict()["insight_count"] == len(report.insights)


# ============================================================ 4. 模型
class TestModels:
    def test_severity_parse(self):
        assert Severity.parse("high") is Severity.HIGH
        assert Severity.parse(Severity.LOW) is Severity.LOW
        with pytest.raises(ValueError):
            Severity.parse("bogus")

    def test_category_parse(self):
        assert InsightCategory.parse("crypto") is InsightCategory.CRYPTO
        with pytest.raises(ValueError):
            InsightCategory.parse("nope")

    def test_technical_insight_to_dict(self):
        insight = TechnicalInsight(
            id="INS-TEST", title="t", category=InsightCategory.CRYPTO,
            severity=Severity.HIGH, confidence=0.9, description="d",
            affected_component="a", code_reference=CodeLocation(file="f", line=3),
            next_steps=["s"], cwe_ids=["CWE-327"], masvs_refs=["MASVS-CRYPTO-1"],
            rule_id="CR-TEST",
        )
        d = insight.to_dict()
        assert d["id"] == "INS-TEST" and d["severity"] == "HIGH"
        assert d["code_reference"]["line"] == 3
        assert d["estimated_difficulty"] == "中"

    def test_insight_report_to_dict(self):
        report = InsightReport(target="t", insights=[], rules_total=65)
        d = report.to_dict()
        assert d["rules_total"] == 65 and d["insight_count"] == 0
        assert d["severity_distribution"]["CRITICAL"] == 0


# ============================================================ 5. 上下文
class TestAnalysisContext:
    def test_add_chaining_and_signal(self):
        ctx = (AnalysisContext()
               .add_strings(["SecretKeySpec"])
               .add_classes(["com.a.B"])
               .add_methods(["encrypt"])
               .add_permissions(["android.permission.CAMERA"]))
        assert ctx.has_signal(r"SecretKeySpec")
        assert ctx.has_signal(r"com\.a\.B")
        assert ctx.has_signal(r"CAMERA")
        assert not ctx.has_signal(r"nothing_matches_this")

    def test_manifest_flag_signal(self):
        ctx = AnalysisContext().set_manifest_flags({"has_activity": True})
        assert ctx.has_signal(r"has_activity")

    def test_exported_component_signal(self):
        ctx = AnalysisContext().add_exported_components(["A (exported=true)"])
        assert ctx.has_signal(r"exported")

    def test_find_evidence_limit(self):
        ctx = AnalysisContext().add_strings(["http://a", "http://b", "http://c"])
        assert len(ctx.find_evidence(r"http://", limit=2)) == 2

    def test_from_apk_missing_file(self):
        with pytest.raises(OSError):
            AnalysisContext.from_apk("no_such_file.apk")

    def test_from_apk_real_sample(self):
        if not SAMPLE_APK.exists():
            pytest.skip("InsecureBankv2.apk 不在测试靶场")
        ctx = AnalysisContext.from_apk(str(SAMPLE_APK))
        assert ctx.classes, "APK 类名抽取失败"
        assert ctx.strings, "APK 字符串抽取失败"
        assert any("android.permission." in p for p in ctx.permissions)

    def test_source_dir_builder(self, tmp_path):
        src = tmp_path / "com" / "a"
        src.mkdir(parents=True)
        (src / "B.java").write_text("public class B { void x() { \"http://e.com\" } }\n",
                                    encoding="utf-8")
        ctx = build_context(str(tmp_path))
        assert "com.a.B" in ctx.classes
        assert ctx.has_signal(r"http://e")


# ============================================================ 6. 优先级
class TestPriority:
    def _insight(self, sev, conf=0.5, cat=InsightCategory.CRYPTO, rid="R") -> TechnicalInsight:
        return TechnicalInsight(id=f"INS-{rid}", title="t", category=cat,
                                severity=sev, confidence=conf, description="d",
                                affected_component="a", rule_id=rid)

    def test_sort_by_severity_then_confidence(self):
        items = [self._insight(Severity.LOW, 0.9, rid="L"),
                 self._insight(Severity.CRITICAL, 0.1, rid="C"),
                 self._insight(Severity.HIGH, 0.9, rid="H2"),
                 self._insight(Severity.HIGH, 0.5, rid="H1")]
        ordered = sort_insights(items)
        assert [i.rule_id for i in ordered] == ["C", "H2", "H1", "L"]

    def test_sort_category_tiebreak(self):
        a = self._insight(Severity.LOW, 0.5, cat=InsightCategory.PRIVACY, rid="P")
        b = self._insight(Severity.LOW, 0.5, cat=InsightCategory.CRYPTO, rid="C")
        assert sort_insights([a, b])[0].rule_id == "C"

    def test_filter_category_string(self):
        items = [self._insight(Severity.LOW, cat=InsightCategory.CRYPTO, rid="C"),
                 self._insight(Severity.LOW, cat=InsightCategory.NETWORK, rid="N")]
        out = filter_insights(items, category="CRYPTO")
        assert [i.rule_id for i in out] == ["C"]

    def test_filter_invalid_category(self):
        with pytest.raises(ValueError):
            filter_insights([], category="NOPE")

    def test_filter_min_severity(self):
        items = [self._insight(Severity.LOW, rid="L"),
                 self._insight(Severity.CRITICAL, rid="C")]
        out = filter_insights(items, min_severity="HIGH")
        assert [i.rule_id for i in out] == ["C"]


# ============================================================ 7. CLI
class TestCLI:
    def test_rules_command(self, capsys):
        assert main(["rules"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["total"] == 67
        first = out["rules"][0]
        assert {"id", "title", "category", "severity", "cwe", "masvs"} <= set(first)

    def test_scan_signals_json(self, tmp_path, capsys):
        signals = tmp_path / "signals.json"
        signals.write_text(json.dumps({
            "package_name": "com.demo",
            "strings": ["http://api.demo.com/login", "password=123456",
                        "AES/ECB/PKCS5Padding"],
        }), encoding="utf-8")
        assert main(["scan", str(signals)]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["insight_count"] >= 2
        ids = {i["rule_id"] for i in payload["insights"]}
        assert "NW-001" in ids

    def test_scan_with_filters(self, tmp_path, capsys):
        signals = tmp_path / "s.json"
        signals.write_text(json.dumps({
            "strings": ["http://api.demo.com/login", "AES/ECB/PKCS5Padding"]}),
            encoding="utf-8")
        assert main(["scan", str(signals), "--category", "crypto",
                     "--min-severity", "HIGH"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["insights"]
        assert all(i["category"] == "CRYPTO" for i in payload["insights"])
        assert all(i["severity"] in ("HIGH", "CRITICAL") for i in payload["insights"])

    def test_scan_summary_and_output_file(self, tmp_path, capsys):
        signals = tmp_path / "s.json"
        signals.write_text(json.dumps({"strings": ["http://api.demo.com"]}),
                           encoding="utf-8")
        out = tmp_path / "summary.txt"
        assert main(["scan", str(signals), "--format", "summary",
                     "--output", str(out)]) == 0
        assert out.exists() and "insights" in out.read_text(encoding="utf-8")

    def test_scan_max_insights(self, tmp_path, capsys):
        signals = tmp_path / "s.json"
        signals.write_text(json.dumps({"strings": [
            "http://a.com", "http://b.com", "password=12345678"]}),
            encoding="utf-8")
        assert main(["scan", str(signals), "--max-insights", "1"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["insight_count"] == 1

    def test_scan_missing_target(self, capsys):
        assert main(["scan", "definitely_missing.file"]) == 2
        assert "error" in capsys.readouterr().out

    def test_scan_bad_json(self, tmp_path, capsys):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        assert main(["scan", str(bad)]) == 2

    def test_scan_real_apk_end_to_end(self, tmp_path, capsys):
        if not SAMPLE_APK.exists():
            pytest.skip("InsecureBankv2.apk 不在测试靶场")
        out = tmp_path / "insights.json"
        assert main(["scan", str(SAMPLE_APK), "--output", str(out)]) == 0
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["insight_count"] > 0
        assert payload["rules_total"] == 67

    def test_build_parser(self):
        assert build_parser().prog == "fp-sentinel mobile insight"

    def test_scan_unsupported_target(self, tmp_path):
        weird = tmp_path / "x.txt"
        weird.write_text("hello", encoding="utf-8")
        with pytest.raises(FileNotFoundError):
            build_context(str(weird))


def test_package_version():
    assert __version__ == "4.0.0"


# ============================================================ 8. 补充分支覆盖
class TestExtraBranches:
    def test_engine_get_all_rules_helper(self):
        from fp_sentinel.mobile_insight.core import engine as engine_mod
        assert len(engine_mod.get_all_rules()) == 67

    def test_severity_rank(self):
        from fp_sentinel.mobile_insight.core.priority import severity_rank
        insight = TechnicalInsight(
            id="I", title="t", category=InsightCategory.CRYPTO,
            severity=Severity.CRITICAL, confidence=0.9, description="d",
            affected_component="a", rule_id="R")
        assert severity_rank(insight) == Severity.CRITICAL.value

    def test_regex_sample_edge_ops(self):
        from fp_sentinel.mobile_insight.tests._regex_sample import sample_for_pattern
        assert sample_for_pattern(r"[^x]") != "x"  # NOT_LITERAL 分支取非 x 字符
        assert sample_for_pattern(r"^\w{3}$") == "aaa"
        assert sample_for_pattern(r"a|b") == "a"
        assert sample_for_pattern(r"\d+") == "1"
        assert sample_for_pattern(r"(foo)") == "foo"
        assert sample_for_pattern(r"(?:bar)") == "bar"
        assert sample_for_pattern(r"foo(?=bar)") == "foobar"  # 前瞻内容并入样本, search 仍可命中
        assert isinstance(sample_for_pattern(r"(?P<n>x)(?P=n)"), str)  # 组引用走启发式回退

    def test_regex_sample_groupref_fallback(self):
        # GROUPREF 走 'a' 回退分支
        from fp_sentinel.mobile_insight.tests._regex_sample import sample_for_pattern
        assert sample_for_pattern(r"(x)\1").startswith("x")


# ============================================================ 9. Round 2 修复回归
# RD-003 白名单/二次确认 + RD-005 新规则

class TestRound2Filtering:
    """RD-003: 框架白名单与资源标记过滤。"""

    def test_is_framework_class(self):
        assert is_framework_class("android.view.ActionProvider")
        assert is_framework_class("java.lang.String")
        assert is_framework_class("org.apache.http.impl.client.DefaultHttpClient")
        assert is_framework_class("com.google.android.gms.common.api.GoogleApiClient")
        assert not is_framework_class("com.android.insecurebankv2.DoLogin")
        # 应用包名前缀内的 com.android.* 类是业务类，不是框架类
        assert not is_framework_class("com.android.insecurebankv2.MyBMi", "com.android.insecurebankv2")

    def test_is_resource_marker(self):
        assert is_resource_marker("xmlns:tools=http://schemas.android.com/tools")
        assert is_resource_marker("http://schemas.android.com/apk/res/android")
        assert is_resource_marker("@+id/textView1")
        assert is_resource_marker("@android:string/ok")
        assert is_resource_marker("tools:ignore=UnusedAttribute")
        assert not is_resource_marker("http://api.example.com/login")
        assert not is_resource_marker("password=SuperSecret123")

    def test_benign_corpus_zero_hits(self):
        """专家误报样例（ActionProvider/xmlns/signatures/CRC32）零命中。"""
        ctx = AnalysisContext(package_name="com.benign")
        ctx.add_strings(BENIGN_STRINGS)
        report = InsightEngine().run(ctx, target="benign")
        assert report.insights == [], [i.rule_id for i in report.insights]

    def test_context_filters_framework_class_and_marker(self):
        ctx = AnalysisContext(package_name="com.demo")
        ctx.add_classes(["android.view.ActionProvider", "com.demo.RealBiz"])
        ctx.add_strings([
            "xmlns:tools=http://schemas.android.com/tools",
            "http://evil.example.com/collect",
        ])
        # 框架类不参与信号匹配（业务类池过滤）
        assert ctx.has_signal(r"RealBiz")
        assert not ctx.has_signal(r"ActionProvider")
        # 资源标记不参与信号匹配
        assert not ctx.has_signal(r"schemas\.android")
        assert ctx.has_signal(r"evil\.example")


class TestRound2DoubleEvidence:
    """RD-003: 二次确认（单一证据不再命中）。"""

    def test_exported_provider_needs_manifest(self):
        # 只有框架类名字符串、无 exported 组件/manifest 标记 → 不命中
        ctx = AnalysisContext(package_name="com.demo")
        ctx.add_strings(["android.view.ActionProvider"])
        rule = next(r for r in CP if r.id == "CP-001")
        assert rule.match(ctx) == []

    def test_signature_check_needs_both(self):
        rule = next(r for r in AA if r.id == "AA-006")
        ctx_bare = AnalysisContext(package_name="com.demo")
        ctx_bare.add_strings(["signatures"])
        assert rule.match(ctx_bare) == []
        ctx_full = AnalysisContext(package_name="com.demo")
        ctx_full.add_strings(["getPackageInfo", "signatures[]"])
        assert rule.match(ctx_full)

    def test_crc32_needs_context(self):
        rule = next(r for r in AA if r.id == "AA-007")
        ctx_bare = AnalysisContext(package_name="com.demo")
        ctx_bare.add_strings(["CRC32", "java.util.zip.CRC32;"])
        assert rule.match(ctx_bare) == []
        ctx_full = AnalysisContext(package_name="com.demo")
        ctx_full.add_strings(["CRC32", "getPackageCodePath"])
        assert rule.match(ctx_full)

    def test_double_evidence_check_present(self):
        """RD-003: 反分析高风险误报规则均需 check 双证据二次确认。"""
        for rid in ("AA-003", "AA-006", "AA-007"):
            rule = next(r for r in AA if r.id == rid)
            assert rule.check is not None, f"{rid} 缺少二次确认 check"


class TestRound2NewRules:
    """RD-005: ST-009 SQL 注入 / PV-009 短信外发 / CR-007 密钥素材判定。"""

    def test_st009_fires_on_double_evidence(self):
        rule = next(r for r in ST if r.id == "ST-009")
        ctx = AnalysisContext(package_name="com.demo")
        ctx.add_strings(["rawQuery", "SELECT * FROM users WHERE name="])
        assert rule.match(ctx)
        ctx_api_only = AnalysisContext(package_name="com.demo")
        ctx_api_only.add_strings(["rawQuery"])
        assert rule.match(ctx_api_only) == []

    def test_pv009_fires_on_sms_send(self):
        rule = next(r for r in PV if r.id == "PV-009")
        ctx = AnalysisContext(package_name="com.demo")
        ctx.add_strings(["sendTextMessage", "SEND_SMS"])
        ctx.add_permissions(["android.permission.SEND_SMS"])
        assert rule.match(ctx)
        ctx_no_perm = AnalysisContext(package_name="com.demo")
        ctx_no_perm.add_strings(["sendTextMessage"])
        assert rule.match(ctx_no_perm) == []

    def test_cr007_needs_key_material(self):
        rule = next(r for r in CR if r.id == "CR-007")
        ctx_api_only = AnalysisContext(package_name="com.demo")
        ctx_api_only.add_strings(["SecretKeySpec"])
        assert rule.match(ctx_api_only) == []
        ctx_full = AnalysisContext(package_name="com.demo")
        ctx_full.add_strings(["SecretKeySpec", "AES/CBC/PKCS5Padding",
                              "1234567890abcdef"])
        assert rule.match(ctx_full)

    def test_find_password_literals_kv(self):
        from fp_sentinel.mobile_insight.rules.context_filters import find_password_literals
        ctx = AnalysisContext(package_name="com.demo")
        ctx.add_strings(["password=SuperSecret123", "com.demo.util",
                         "https://api.example.com"])
        evidence = find_password_literals(ctx)
        assert evidence and "SuperSecret123" in evidence[0]
