"""搜索模型 / 关键性评分 / 字符串提取 / 交叉引用 / 格式化 / CLI 测试。"""

from __future__ import annotations

import json
import subprocess

import pytest
from typer.testing import CliRunner

from fp_sentinel.mobile_decompile.cli import decompile_app
from fp_sentinel.mobile_decompile.core.android_java import AndroidJavaDecompiler
from fp_sentinel.mobile_decompile.models.class_info import (
    ClassHierarchy,
    ClassInfo,
    ClassNode,
    FieldInfo,
    MethodInfo,
)
from fp_sentinel.mobile_decompile.models.decompile_result import (
    CallGraph,
    ComponentInfo,
    DecompileResult,
    ManifestInfo,
    SourceFile,
    StringEntry,
)
from fp_sentinel.mobile_decompile.models.search_result import (
    MatchType,
    SearchOptions,
    SearchResult,
    compute_critical_score,
)
from fp_sentinel.mobile_decompile.models.decompile_result import DecompileConfig
from fp_sentinel.mobile_decompile.output.cross_reference import CrossReferenceAnalyzer
from fp_sentinel.mobile_decompile.output.formatter import (
    format_class_hierarchy,
    format_manifest,
    format_result,
    format_search_results,
)
from fp_sentinel.mobile_decompile.output.string_extractor import (
    ExtractedString,
    StringCategory,
    StringExtractor,
)

from . import INSECURE_BANK_APK, requires_insecure_bank, suppress_androguard_logs

runner = CliRunner()


# --------------------------------------------------------------------------
# MatchType / SearchResult / SearchOptions
# --------------------------------------------------------------------------


class TestMatchType:
    def test_values(self):
        assert {t.value for t in MatchType} == {"TEXT", "STRING", "CALL", "XREF"}


class TestSearchResult:
    def test_defaults_and_to_dict(self):
        r = SearchResult(keyword="token", file_path="a.java", class_name="Login", method_name="go")
        assert r.match_type == MatchType.TEXT
        assert r.critical_score == 0.0
        d = r.to_dict()
        assert d["keyword"] == "token"
        assert d["match_type"] == "TEXT"


class TestSearchOptions:
    def test_defaults(self):
        opts = SearchOptions()
        assert len(opts.match_types) == 4
        assert opts.allows(MatchType.CALL)
        assert opts.in_scope("anything")

    def test_scope(self):
        opts = SearchOptions(scope="com.bank")
        assert opts.in_scope("com.bank.Login")
        assert opts.in_scope("Lcom/bank/Login;")
        assert not opts.in_scope("com.other.Login")


# --------------------------------------------------------------------------
# critical_score 关键性评分
# --------------------------------------------------------------------------


class TestCriticalScore:
    def test_neutral_baseline(self):
        score = compute_critical_score("zzz", "java.lang.Object", "toString", "plain code")
        assert 0.0 <= score < 0.2

    def test_package_relevance_boost(self):
        low = compute_critical_score("encrypt", "com.app.Util", "run", "")
        high = compute_critical_score("encrypt", "com.app.EncryptUtil", "encrypt", "")
        assert high > low
        assert 0.0 <= high <= 1.0

    def test_crypto_feature_boost(self):
        score = compute_critical_score("zzz", "com.app.CipherHelper", "aesDecrypt", "")
        assert score > 0.2

    def test_snippet_boost(self):
        score = compute_critical_score("token", "com.app.X", "", "token=abc123")
        assert score > 0.2

    def test_call_chain_boost(self):
        no_call = compute_critical_score("zzz", "com.app.X", "", "", call_count=0)
        hot = compute_critical_score("zzz", "com.app.X", "", "", call_count=100)
        assert hot > no_call

    def test_clamped(self):
        extreme = compute_critical_score(
            "encrypt", "com.app.Encrypt", "encrypt", "encrypt", call_count=999
        )
        assert extreme <= 1.0
        assert compute_critical_score("", "", "", "", call_count=-5) >= 0.0


# --------------------------------------------------------------------------
# StringExtractor
# --------------------------------------------------------------------------


class TestStringExtractor:
    def setup_method(self):
        self.ex = StringExtractor(source="test.apk")

    def _classify(self, value):
        hit = self.ex.classify(value)
        return hit

    def test_url(self):
        hit = self._classify("https://api.bank.com/login?a=1")
        assert hit.category == StringCategory.URL
        assert hit.value.startswith("https://")
        assert hit.source == "test.apk"

    def test_jwt(self):
        hit = self._classify(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.4xT7ZJ2bFq0Kz8mZ0wZ6yVQ3n5s9vB1cD2eF4gH6iJ8"
        )
        assert hit.category == StringCategory.JWT

    def test_email(self):
        hit = self._classify("admin@insecurebank.com")
        assert hit.category == StringCategory.EMAIL

    def test_phone(self):
        hit = self._classify("13812345678")
        assert hit.category == StringCategory.PHONE

    def test_ip(self):
        hit = self._classify("192.168.1.100")
        assert hit.category == StringCategory.IP

    def test_package_name(self):
        hit = self._classify("com.android.insecurebankv2")
        assert hit.category == StringCategory.PACKAGE_NAME

    def test_api_endpoint(self):
        hit = self._classify('"/api/v1/account/transfer"')
        assert hit.category == StringCategory.API_ENDPOINT

    def test_token_assignment(self):
        hit = self._classify('api_token="a1b2c3d4e5f6g7h8"')
        assert hit.category == StringCategory.TOKEN

    def test_api_key(self):
        hit = self._classify("api_key: 'A1b2C3d4E5f6G7h8'")
        assert hit.category == StringCategory.API_KEY

    def test_aes_key(self):
        hit = self._classify('aes_key = "1234567890abcdef"')
        assert hit.category == StringCategory.AES_KEY

    def test_db_conn(self):
        hit = self._classify("jdbc:mysql://localhost:3306/bank")
        assert hit.category == StringCategory.DB_CONN

    def test_aws_key(self):
        hit = self._classify("AKIAIOSFODNN7EXAMPLE")
        assert hit.category == StringCategory.API_KEY

    def test_plain_and_short(self):
        assert self._classify("just a plain sentence") is None
        assert self._classify("ab") is None
        assert self._classify("") is None

    def test_extract_dedupe(self):
        results = self.ex.extract(
            ["https://a.com", "https://a.com", "admin@a.com", "nothing special"]
        )
        values = [(r.category, r.value) for r in results]
        assert len(values) == len(set(values))
        assert len(results) == 2

    def test_extract_from_source(self):
        source = 'String url = "http://evil.com/x";\nString mail = "a@b.com";'
        hits = self.ex.extract_from_source(source)
        categories = {h.category for h in hits}
        assert StringCategory.URL in categories
        assert StringCategory.EMAIL in categories

    def test_sensitive_only(self):
        results = [
            ExtractedString("http://a.com", StringCategory.URL, 0.8),
            ExtractedString("AKIAIOSFODNN7EXAMPLE", StringCategory.API_KEY, 0.95),
        ]
        assert len(StringExtractor.sensitive_only(results)) == 1

    def test_to_dict(self):
        hit = self._classify("https://a.com")
        d = hit.to_dict()
        assert d["category"] == "URL" and d["confidence"] > 0


# --------------------------------------------------------------------------
# CrossReferenceAnalyzer
# --------------------------------------------------------------------------


class TestCrossReference:
    def test_add_and_query(self):
        xref = CrossReferenceAnalyzer()
        xref.add_reference("A.m", "B.n")
        xref.add_reference("C.k", "B.n")
        xref.add_reference("A.m", "B.n")  # 去重
        assert xref.get_references("A.m") == ["B.n"]
        assert sorted(xref.get_referenced_by("B.n")) == ["A.m", "C.k"]
        by, refs = xref.xrefs_of("B.n")
        assert len(by) == 2 and refs == []

    def test_self_reference_ignored(self):
        xref = CrossReferenceAnalyzer()
        xref.add_reference("A", "A")
        assert len(xref) == 0
        assert xref.symbols() == []

    def test_from_call_graph(self):
        xref = CrossReferenceAnalyzer({"a": ["b", "c"], "d": ["b"]})
        assert len(xref.get_referenced_by("b")) == 2
        assert xref.most_referenced(1) == [("b", 2)]

    def test_most_referenced_empty(self):
        assert CrossReferenceAnalyzer().most_referenced(5) == []

    def test_to_dict(self):
        xref = CrossReferenceAnalyzer({"a": ["b"]})
        assert xref.to_dict() == {"a": ["b"]}
        assert xref.get_references("missing") == []
        assert xref.get_referenced_by("missing") == []
        assert xref.xrefs_of("missing") == ([], [])


# --------------------------------------------------------------------------
# CallGraph / ClassHierarchy
# --------------------------------------------------------------------------


class TestCallGraph:
    def test_edges(self):
        g = CallGraph()
        g.add_edge("a", "b")
        g.add_edge("a", "b")  # 去重
        g.add_edge("a", "a")  # 自环忽略
        assert g.callees("a") == ["b"]
        assert g.callers("b") == ["a"]
        assert g.edge_count == 1
        assert g.node_count == 2

    def test_to_dot_and_dict(self):
        g = CallGraph()
        caller = 'Lcom/A;->x("q")V'
        callee = "Lcom/B;->y()V"
        g.add_edge(caller, callee)
        dot = g.to_dot()
        assert dot.startswith("digraph")
        assert "Lcom/A;->x('q')V" in dot  # DOT 内引号已转义
        assert g.to_dict()[caller] == [callee]  # to_dict 保留原始签名

    def test_callees_missing(self):
        g = CallGraph()
        assert g.callees("nope") == []
        assert g.callers("nope") == []


class TestClassHierarchy:
    def test_tree_ops(self):
        h = ClassHierarchy()
        h.add_class("Child", "Parent")
        h.add_class("Parent", "Grand")
        h.add_class("Child2", "Parent")
        assert h.get_children("Parent") == ["Child", "Child2"]
        assert h.get_ancestors("Child") == ["Parent", "Grand"]
        assert set(h.get_descendants("Parent")) == {"Child", "Child2"}
        assert len(h) == 4  # Child/Parent/Child2/Grand
        assert h.to_dict()["Child"]["parent"] == "Parent"

    def test_unknown_and_cycles(self):
        h = ClassHierarchy()
        assert h.get_children("x") == []
        assert h.get_ancestors("x") == []
        assert h.get_descendants("x") == []
        h.add_class("Loop", "Loop")
        assert h.get_ancestors("Loop") == ["Loop"]
        assert h.get_descendants("Loop") == []

    def test_add_class_without_parent(self):
        h = ClassHierarchy()
        h.add_class("Root")
        assert h.nodes["Root"].parent is None
        assert ClassNode("X").to_dict()["children"] == []


class TestClassInfo:
    def test_java_name_package(self):
        info = ClassInfo(name="Lcom/bank/Sub/Cls;")
        assert info.java_name == "com.bank.Sub.Cls"
        assert info.package == "com.bank.Sub"

    def test_find_methods(self):
        info = ClassInfo(
            name="Lcom/X;",
            methods=[MethodInfo("doEncrypt", "()V")],
        )
        assert len(info.find_methods("encrypt")) == 1
        assert info.find_methods("ENCRYPT")[0].name == "doEncrypt"
        assert info.find_methods("zzz", case_sensitive=True) == []

    def test_to_dict(self):
        info = ClassInfo(name="Lcom/X;")
        d = info.to_dict()
        assert d["java_name"] == "com.X"
        assert d["methods"] == [] and d["fields"] == []

    def test_method_full_signature_passthrough(self):
        m = MethodInfo("a", "Lcom/X;->a()V", "public", "Lcom/X;")
        assert m.full_signature == "Lcom/X;->a()V"
        m2 = MethodInfo("a", "()V", "public", "Lcom/X;")
        assert m2.full_signature == "Lcom/X;->a()V"
        assert m2.simple_signature == "X.a()V"
        assert MethodInfo("a").to_dict()["full_signature"]
        assert FieldInfo("f").to_dict() == {"name": "f", "type_desc": "", "access_flags": ""}


# --------------------------------------------------------------------------
# DecompileResult / ManifestInfo / SourceFile
# --------------------------------------------------------------------------


class TestResultModels:
    def test_summary_and_errors(self):
        r = DecompileResult(success=True, target_path="a.apk", engine_used="jadx")
        r.add_error("e1")
        r.add_warning("w1")
        s = r.summary()
        assert s["success"] and s["error_count"] == 1 and s["warning_count"] == 1

    def test_summary_with_manifest_and_graph(self):
        g = CallGraph()
        g.add_edge("a", "b")
        r = DecompileResult(
            success=True,
            manifest_info=ManifestInfo(package_name="p"),
            call_graph=g,
        )
        assert r.summary()["has_manifest"]
        assert r.summary()["call_graph_edges"] == 1

    def test_source_file_size(self):
        sf = SourceFile(path="x", content="hello")
        assert sf.size_bytes == 5
        assert sf.to_dict()["language"] == "java"

    def test_string_entry(self):
        assert StringEntry("v").to_dict()["category"] == "plain"

    def test_manifest_properties(self):
        info = ManifestInfo(
            package_name="p",
            components=[
                ComponentInfo("activity", "A", True),
                ComponentInfo("service", "S", False),
                ComponentInfo("receiver", "R", True),
            ],
        )
        assert len(info.exported_components) == 2
        assert info.activities[0].name == "A"
        d = info.to_dict()
        assert set(d["exported_components"]) == {"A", "R"}


# --------------------------------------------------------------------------
# Formatter
# --------------------------------------------------------------------------


def _sample_result() -> DecompileResult:
    r = DecompileResult(success=True, target_path="a.apk", engine_used="androguard")
    r.source_files.append(SourceFile(path="x", relative_path="x.java", content="class X {}"))
    r.class_count = 1
    r.method_count = 2
    r.string_table.append(StringEntry("http://a.com"))
    r.add_error("boom")
    r.add_warning("careful")
    r.duration_sec = 1.234
    r.quality_score = 0.6
    return r


def _sample_results() -> list:
    return [
        SearchResult(
            keyword="encrypt",
            file_path="A.java",
            class_name="Crypto",
            method_name="encrypt",
            line_number=10,
            code_snippet="encrypt(data)",
            match_type=MatchType.CALL,
            relevance_score=0.7,
            critical_score=0.9,
        )
    ]


class TestFormatter:
    def test_format_result(self):
        r = _sample_result()
        text = format_result(r, "text")
        assert "成功" in text and "boom" in text and "careful" in text
        js = json.loads(format_result(r, "json"))
        assert js["engine_used"] == "androguard"
        md = format_result(r, "markdown")
        assert md.startswith("# 反编译报告") and "boom" in md

    def test_format_result_failure(self):
        r = DecompileResult(success=False, target_path="a.apk")
        assert "失败" in format_result(r, "text")

    def test_format_search_results(self):
        rows = _sample_results()
        text = format_search_results(rows, "text")
        assert "encrypt" in text and "CALL" in text
        js = json.loads(format_search_results(rows, "json"))
        assert js[0]["critical_score"] == 0.9
        md = format_search_results(rows, "markdown")
        assert "| encrypt |" in md.replace("encrypt |", "encrypt |") or "encrypt" in md

    def test_format_search_results_empty(self):
        text = format_search_results([], "text")
        assert "KEYWORD" in text

    def test_format_manifest(self):
        info = ManifestInfo(
            package_name="com.x",
            version_name="1.0",
            version_code="1",
            min_sdk="21",
            target_sdk="31",
            permissions=["android.permission.INTERNET"],
            components=[ComponentInfo("activity", "A", True)],
        )
        text = format_manifest(info)
        assert "com.x" in text and "exported" in text
        js = json.loads(format_manifest(info, "json"))
        assert js["package_name"] == "com.x"

    def test_format_hierarchy(self):
        h = ClassHierarchy()
        h.add_class("Child", "Parent")
        h.add_class("Parent", "Grand")
        text = format_class_hierarchy(h)
        assert "Grand" in text and "- Child" in text
        md = format_class_hierarchy(h, fmt="markdown")
        assert md.startswith("# 类层次结构")
        js = json.loads(format_class_hierarchy(h, fmt="json"))
        assert js["Parent"]["parent"] == "Grand"
        rooted = format_class_hierarchy(h, root="Parent")
        assert "Child" in rooted and "Grand" not in rooted

    def test_format_hierarchy_empty(self):
        assert format_class_hierarchy(ClassHierarchy()) == "(empty hierarchy)"

    def test_invalid_format(self):
        with pytest.raises(ValueError):
            format_result(_sample_result(), "xml")
        with pytest.raises(ValueError):
            format_search_results([], "csv")
        with pytest.raises(ValueError):
            format_manifest(ManifestInfo(), "html")
        with pytest.raises(ValueError):
            format_class_hierarchy(ClassHierarchy(), fmt="dot")


# --------------------------------------------------------------------------
# CLI（typer）
# --------------------------------------------------------------------------


class TestCliBasics:
    def test_help(self):
        result = runner.invoke(decompile_app, ["--help"])
        assert result.exit_code == 0
        for cmd in ("run", "search", "strings", "manifest", "hierarchy"):
            assert cmd in result.output

    def test_missing_target(self, tmp_path):
        result = runner.invoke(decompile_app, ["manifest", str(tmp_path / "nope.apk")])
        assert result.exit_code == 2

    def test_bad_match_type(self, tmp_path):
        target = tmp_path / "a.apk"
        target.write_bytes(b"PK\x03\x04")
        result = runner.invoke(decompile_app, ["search", str(target), "x", "--type", "bogus"])
        assert result.exit_code != 0

    def test_manifest_not_apk(self, tmp_path):
        target = tmp_path / "plain.txt"
        target.write_text("x", encoding="utf-8")
        result = runner.invoke(decompile_app, ["manifest", str(target)])
        assert result.exit_code == 2

    def test_run_unsupported_target(self, tmp_path):
        target = tmp_path / "plain.txt"
        target.write_text("x", encoding="utf-8")
        result = runner.invoke(decompile_app, ["run", str(target), "--format", "json"])
        assert result.exit_code == 0
        assert '"success": false' in result.output


class TestCliRealApk:
    @requires_insecure_bank
    def test_manifest(self):
        suppress_androguard_logs()
        result = runner.invoke(decompile_app, ["manifest", str(INSECURE_BANK_APK)])
        assert result.exit_code == 0
        assert "com.android.insecurebankv2" in result.output
        js = runner.invoke(decompile_app, ["manifest", str(INSECURE_BANK_APK), "--format", "json"])
        data = json.loads(js.output)
        assert "SEND_SMS" in "".join(data["permissions"])

    @requires_insecure_bank
    def test_strings(self):
        suppress_androguard_logs()
        result = runner.invoke(
            decompile_app,
            ["strings", str(INSECURE_BANK_APK), "--pattern", "http", "--limit", "20"],
        )
        assert result.exit_code == 0
        assert "URL" in result.output
        js = runner.invoke(
            decompile_app,
            ["strings", str(INSECURE_BANK_APK), "--pattern", "http", "--limit", "5", "--format", "json"],
        )
        data = json.loads(js.output)
        assert isinstance(data, list) and len(data) <= 5

    @requires_insecure_bank
    def test_strings_sensitive(self):
        suppress_androguard_logs()
        result = runner.invoke(
            decompile_app, ["strings", str(INSECURE_BANK_APK), "--sensitive", "--limit", "20"]
        )
        assert result.exit_code == 0

    @requires_insecure_bank
    def test_search_string(self, insecure_bank_parser):
        result = runner.invoke(
            decompile_app,
            [
                "search",
                str(INSECURE_BANK_APK),
                "http",
                "--type",
                "string",
                "--limit",
                "5",
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert 0 < len(data) <= 5

    @requires_insecure_bank
    def test_hierarchy_root(self, insecure_bank_parser):
        result = runner.invoke(
            decompile_app,
            [
                "hierarchy",
                str(INSECURE_BANK_APK),
                "--root",
                "Lcom/android/insecurebankv2/MyBroadCastReceiver;",
            ],
        )
        assert result.exit_code == 0
        assert "MyBroadCastReceiver" in result.output

    @requires_insecure_bank
    def test_run_with_fake_jadx(self, monkeypatch, tmp_path):
        from fp_sentinel.mobile_decompile.core import android_java as aj

        monkeypatch.setattr(AndroidJavaDecompiler, "find_jadx", staticmethod(lambda: "fake-jadx"))

        def fake_run(argv, **kwargs):
            import pathlib

            out_dir = pathlib.Path(argv[2]) / "s" / "c"
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "T.java").write_text("class T {}", encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr(aj.subprocess, "run", fake_run)
        out = tmp_path / "cli_out"
        result = runner.invoke(
            decompile_app,
            ["run", str(INSECURE_BANK_APK), "--engine", "jadx", "--output", str(out)],
        )
        assert result.exit_code == 0
        assert "成功" in result.output

    @requires_insecure_bank
    def test_run_androguard_fallback(self, monkeypatch, insecure_bank_parser):
        monkeypatch.setattr(AndroidJavaDecompiler, "find_jadx", staticmethod(lambda: None))
        monkeypatch.setattr(
            AndroidJavaDecompiler, "try_install_jadx", staticmethod(lambda: None))
        suppress_androguard_logs()
        result = runner.invoke(
            decompile_app, ["run", str(INSECURE_BANK_APK), "--format", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["success"]
