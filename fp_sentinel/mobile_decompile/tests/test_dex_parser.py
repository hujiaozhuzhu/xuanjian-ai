"""DexParser / ManifestParser 单元测试 + 真实 APK 集成测试。

集成测试使用 test_apps 下的 InsecureBankv2.apk（缺失时自动跳过）。
"""

from __future__ import annotations

import zipfile

import pytest

from fp_sentinel.mobile_decompile.models.class_info import ClassInfo
from fp_sentinel.mobile_decompile.parsers.dex_parser import (
    DexParser,
    _dedupe,
    _java_to_internal,
    get_dex_parser,
    make_method_signature,
)

from . import INSECURE_BANK_APK, requires_insecure_bank, suppress_androguard_logs


# --------------------------------------------------------------------------
# 纯单元测试（无外部依赖）
# --------------------------------------------------------------------------


class TestSignatureHelpers:
    def test_make_method_signature_composes(self):
        sig = make_method_signature("Lcom/A;", "foo", "(I)V")
        assert sig == "Lcom/A;->foo(I)V"

    def test_make_method_signature_passthrough_full_descriptor(self):
        assert make_method_signature("Lcom/A;", "foo", "Lcom/A;->bar()V") == "Lcom/A;->bar()V"

    def test_java_to_internal(self):
        assert _java_to_internal("com.android.app.Cls") == "Lcom/android/app/Cls;"

    def test_dedupe_preserves_order(self):
        assert _dedupe(["b", "a", "b", "c", "a"]) == ["b", "a", "c"]


class TestDexParserErrors:
    def test_missing_file(self, tmp_path):
        parser = DexParser(str(tmp_path / "nope.apk"), load=False)
        with pytest.raises(FileNotFoundError):
            parser.load()

    def test_unsupported_type(self, tmp_path):
        target = tmp_path / "not_apk.txt"
        target.write_text("hello", encoding="utf-8")
        parser = DexParser(str(target), load=False)
        with pytest.raises(ValueError):
            parser.load()

    def test_zip_without_dex(self, tmp_path):
        target = tmp_path / "empty.apk"
        with zipfile.ZipFile(target, "w") as zf:
            zf.writestr("AndroidManifest.xml", "dummy")
        parser = DexParser(str(target), load=False)
        with pytest.raises(ValueError, match="classes"):
            parser.load()

    def test_androguard_missing_hint(self, tmp_path, monkeypatch):
        import fp_sentinel.mobile_decompile.parsers.dex_parser as mod

        monkeypatch.setattr(mod, "HAS_ANDROGUARD", False)
        parser = DexParser(str(tmp_path / "x.apk"), load=False)
        with pytest.raises(ImportError, match="pip install androguard"):
            parser.load()


# --------------------------------------------------------------------------
# 真实 APK 集成测试（InsecureBankv2.apk）
# --------------------------------------------------------------------------


@requires_insecure_bank
class TestDexParserIntegration:
    def test_load_basic(self, insecure_bank_parser):
        parser = insecure_bank_parser
        assert parser.dex_count >= 1
        assert parser.class_count > 0
        assert parser.method_count > 0

    def test_strings(self, insecure_bank_parser):
        strings = insecure_bank_parser.strings()
        assert len(strings) > 1000
        assert any("http" in s.lower() for s in strings[:2000])

    def test_search_strings(self, insecure_bank_parser):
        hits = insecure_bank_parser.search_strings("password", limit=10)
        assert hits and all("password" in h.lower() for h in hits)
        hits_regex = insecure_bank_parser.search_strings(r"https?://\S+", regex=True, limit=5)
        assert hits_regex

    def test_classes_and_class_info(self, insecure_bank_parser):
        classes = insecure_bank_parser.classes()
        assert classes
        target = next(
            (c for c in classes if c.name == "Lcom/android/insecurebankv2/MyBroadCastReceiver;"),
            None,
        )
        assert target is not None
        assert target.java_name == "com.android.insecurebankv2.MyBroadCastReceiver"
        assert target.package == "com.android.insecurebankv2"
        assert target.is_internal("com.android.insecurebankv2")
        assert not target.is_internal("com.other.app")
        assert any(m.name == "onReceive" for m in target.methods)

    def test_get_class(self, insecure_bank_parser):
        info = insecure_bank_parser.get_class("com.android.insecurebankv2.LoginActivity")
        assert info is not None
        assert info.name == "Lcom/android/insecurebankv2/LoginActivity;"
        missing = insecure_bank_parser.get_class("com.not.existing.Nope")
        assert missing is None

    def test_get_class_dex_internal_form(self, insecure_bank_parser):
        info = insecure_bank_parser.get_class("Lcom/android/insecurebankv2/LoginActivity;")
        assert info is not None

    def test_class_hierarchy(self, insecure_bank_parser):
        hierarchy = insecure_bank_parser.class_hierarchy()
        assert len(hierarchy) > 0
        name = "Lcom/android/insecurebankv2/MyBroadCastReceiver;"
        ancestors = hierarchy.get_ancestors(name)
        assert "Landroid/content/BroadcastReceiver;" in ancestors
        assert hierarchy.get_children(name) == []
        assert hierarchy.get_children("Lno/such/Node;") == []

    def test_xref_and_call_graph(self, insecure_bank_parser):
        parser = insecure_bank_parser
        matches = parser.find_methods("login", limit=20)
        assert matches  # InsecureBankv2 含 LoginActivity
        sig, caller_count = max(matches, key=lambda x: x[1])
        callers, callees = parser.method_xrefs(sig)
        assert isinstance(callers, list) and isinstance(callees, list)
        if caller_count > 0:
            assert len(callers) == caller_count
        graph = parser.call_graph()
        assert graph.edge_count > 0
        some_caller = next(iter(graph.edges))
        assert isinstance(graph.callees(some_caller), list)
        assert graph.node_count > 0
        assert "digraph" in graph.to_dot()

    def test_find_methods_unknown(self, insecure_bank_parser):
        assert insecure_bank_parser.find_methods("zzz_not_exist_zzz", limit=5) == []

    def test_method_xrefs_unknown(self, insecure_bank_parser):
        callers, callees = insecure_bank_parser.method_xrefs("Lnope/Cls;->foo()V")
        assert callers == [] and callees == []

    def test_method_xrefs_malformed_sig(self, insecure_bank_parser):
        callers, callees = insecure_bank_parser.method_xrefs("not-a-signature")
        assert callers == [] and callees == []

    def test_parser_cache_shared(self, insecure_bank_parser):
        assert get_dex_parser(str(INSECURE_BANK_APK)) is insecure_bank_parser


# --------------------------------------------------------------------------
# ManifestParser
# --------------------------------------------------------------------------


class TestManifestParser:
    def test_missing_androguard(self, tmp_path, monkeypatch):
        import fp_sentinel.mobile_decompile.parsers.manifest_parser as mod

        monkeypatch.setattr(mod, "HAS_ANDROGUARD", False)
        with pytest.raises(ImportError, match="pip install androguard"):
            mod.ManifestParser(str(tmp_path / "x.apk"))

    def test_missing_file(self, tmp_path):
        from fp_sentinel.mobile_decompile.parsers.manifest_parser import ManifestParser

        with pytest.raises(FileNotFoundError):
            ManifestParser(str(tmp_path / "nope.apk"))

    def test_not_apk(self, tmp_path):
        from fp_sentinel.mobile_decompile.parsers.manifest_parser import ManifestParser

        target = tmp_path / "plain.txt"
        target.write_text("data", encoding="utf-8")
        with pytest.raises(ValueError):
            ManifestParser(str(target))

    @requires_insecure_bank
    def test_parse_real_apk(self):
        from fp_sentinel.mobile_decompile.parsers.manifest_parser import ManifestParser

        suppress_androguard_logs()
        parser = ManifestParser(str(INSECURE_BANK_APK))
        info = parser.parse()
        assert info.package_name == "com.android.insecurebankv2"
        assert info.version_name == "1.0"
        assert info.version_code == "1"
        assert info.min_sdk == "15"
        assert "android.permission.SEND_SMS" in info.permissions
        # 权限排序
        assert info.permissions == sorted(info.permissions)
        types = {c.type for c in info.components}
        assert {"activity", "receiver", "provider"} <= types
        exported_names = {c.name for c in info.exported_components}
        assert "com.android.insecurebankv2.MyBroadCastReceiver" in exported_names
        # 二次调用走缓存 APK 对象
        assert parser.parse().package_name == info.package_name
        assert parser.apk is not None
        assert parser.exported_components()

    @requires_insecure_bank
    def test_intent_filters(self):
        from fp_sentinel.mobile_decompile.parsers.manifest_parser import ManifestParser

        suppress_androguard_logs()
        parser = ManifestParser(str(INSECURE_BANK_APK))
        filters = parser.get_intent_filters(
            "receiver", "com.android.insecurebankv2.MyBroadCastReceiver"
        )
        assert isinstance(filters, dict)
        assert filters  # 该 receiver 声明了 intent-filter
        # 不存在的组件返回空 dict（不抛异常）
        assert parser.get_intent_filters("activity", "com.not.exist.Cls") == {}


# --------------------------------------------------------------------------
# 补充覆盖：xref 归一化 / 兜底匹配 / 字符串缓存
# --------------------------------------------------------------------------


class TestDexParserInternals:
    def test_xref_entry_signature_garbage(self):
        assert DexParser._xref_entry_signature("not-a-method") is None
        assert DexParser._xref_entry_signature((1, 2, 3)) is None
        assert DexParser._xref_entry_signature(None) is None

    def test_method_xrefs_name_fallback(self, insecure_bank_parser):
        """签名 descriptor 不匹配但方法名相同时走兜底匹配。"""
        callers, callees = insecure_bank_parser.method_xrefs(
            "Lcom/android/insecurebankv2/LoginActivity;->onCreate()V"
        )
        assert isinstance(callers, list) and isinstance(callees, list)

    def test_method_xrefs_class_not_found(self, insecure_bank_parser):
        callers, callees = insecure_bank_parser.method_xrefs(
            "Lcom/definitely/Missing;->foo()V"
        )
        assert callers == [] and callees == []

    def test_strings_cache_identity(self, insecure_bank_parser):
        assert insecure_bank_parser.strings() is insecure_bank_parser.strings()

    def test_search_strings_no_match(self, insecure_bank_parser):
        assert insecure_bank_parser.search_strings("zzz-no-match-zzz") == []
        assert insecure_bank_parser.search_strings(r"zzz\-no\-regex\-match", regex=True) == []

    def test_unloaded_parser_counts(self, tmp_path):
        parser = DexParser(str(tmp_path / "x.apk"), load=False)
        assert parser.dex_count == 0
        assert parser.class_count == 0
        assert parser.method_count == 0
        assert parser.strings() == []
        assert parser.search_strings("x") == []


class TestManifestIsExported:
    class _StubApk:
        def __init__(self, value):
            self._value = value

        def get_all_attribute_value(self, comp_type, attr, **kwargs):
            # androguard 4.x 接口: 返回候选值列表（Round 3 起按 name 过滤）
            if attr == "exported" and self._value is not None:
                return [self._value]
            return []

    def test_explicit_bool(self):
        from fp_sentinel.mobile_decompile.parsers.manifest_parser import ManifestParser

        assert ManifestParser.is_exported(self._StubApk(True), "activity", "A", False)
        assert not ManifestParser.is_exported(self._StubApk(False), "activity", "A", True)

    def test_explicit_string(self):
        from fp_sentinel.mobile_decompile.parsers.manifest_parser import ManifestParser

        assert ManifestParser.is_exported(self._StubApk("true"), "activity", "A", False)
        assert not ManifestParser.is_exported(self._StubApk("false"), "activity", "A", True)

    def test_implicit_by_filters(self):
        from fp_sentinel.mobile_decompile.parsers.manifest_parser import ManifestParser

        assert ManifestParser.is_exported(self._StubApk(None), "activity", "A", True)
        assert not ManifestParser.is_exported(self._StubApk(None), "activity", "A", False)
