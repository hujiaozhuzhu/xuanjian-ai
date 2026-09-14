"""AndroidJavaDecompiler 单元测试 + 真实 APK 集成测试。

覆盖：
- jadx 命令行路径（模拟可执行文件与成功/失败退出码）；
- androguard 优雅降级路径（jadx 不可用）；
- 关键字搜索（TEXT/STRING/CALL/XREF）；
- Native/iOS 反编译桩的降级与错误路径。
"""

from __future__ import annotations

import asyncio
import struct
import subprocess

import pytest

from fp_sentinel.mobile_decompile.core.android_java import (
    AndroidJavaDecompiler,
    render_class_outline,
    split_signature,
)
from fp_sentinel.mobile_decompile.core.android_native import (
    AndroidNativeDecompiler,
    parse_elf_header,
)
from fp_sentinel.mobile_decompile.core.ios_decompiler import (
    IosDecompiler,
    parse_macho_header,
)
from fp_sentinel.mobile_decompile.models.class_info import (
    ClassInfo,
    FieldInfo,
    MethodInfo,
)
from fp_sentinel.mobile_decompile.models.decompile_result import (
    DecompileConfig,
    SourceFile,
)
from fp_sentinel.mobile_decompile.models.search_result import MatchType

from . import (
    INSECURE_BANK_APK,
    requires_insecure_bank,
    suppress_androguard_logs,
)


def _run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------
# 纯单元测试
# --------------------------------------------------------------------------


class TestHelpers:
    def test_split_signature(self):
        cls, meth, desc = split_signature("Lcom/pkg/Cls;->doWork(I)V")
        assert cls == "Lcom/pkg/Cls;"
        assert meth == "doWork"
        assert desc == "(I)V"

    def test_split_signature_malformed(self):
        cls, meth, desc = split_signature("weird")
        assert cls == "" and meth == "weird" and desc == ""

    def test_render_class_outline(self):
        info = ClassInfo(
            name="Lcom/bank/Secure;",
            super_name="Ljava/lang/Object;",
            interfaces=["Ljava/io/Serializable;"],
            methods=[MethodInfo("encrypt", "(Ljava/lang/String;)[B", "public", "Lcom/bank/Secure;")],
            fields=[FieldInfo("KEY", "Ljava/lang/String;", "private static")],
        )
        text = render_class_outline(info)
        assert "package com.bank;" in text
        assert "class Secure extends java.lang.Object" in text
        assert "implements java.io.Serializable" in text
        assert "encrypt(Ljava/lang/String;)[B" in text
        assert "KEY" in text
        # 空字段/无父类的类也能渲染
        bare = render_class_outline(ClassInfo(name="Lcom/bank/Bare;", super_name=""))
        assert "class Bare {" in bare
        assert "extends" not in bare.split("{")[0]


class TestSupports:
    def test_apk_and_dex(self, tmp_path):
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        dex = tmp_path / "a.dex"
        dex.write_bytes(b"dexn")
        assert AndroidJavaDecompiler.supports(str(apk))
        assert AndroidJavaDecompiler.supports(str(dex))

    def test_zip_without_extension(self, tmp_path):
        target = tmp_path / "zipfile"
        with __import__("zipfile").ZipFile(target, "w") as zf:
            zf.writestr("x.txt", "x")
        assert AndroidJavaDecompiler.supports(str(target))

    def test_negative(self, tmp_path):
        txt = tmp_path / "a.txt"
        txt.write_text("hello", encoding="utf-8")
        assert not AndroidJavaDecompiler.supports(str(txt))
        assert not AndroidJavaDecompiler.supports(str(tmp_path / "missing.apk"))

    def test_decompile_missing_and_unsupported(self, tmp_path):
        dec = AndroidJavaDecompiler()
        result = _run(dec.decompile(str(tmp_path / "missing.apk")))
        assert not result.success and result.errors
        txt = tmp_path / "plain.txt"
        txt.write_text("x", encoding="utf-8")
        result2 = _run(dec.decompile(str(txt)))
        assert not result2.success and result2.errors


# --------------------------------------------------------------------------
# jadx 路径模拟
# --------------------------------------------------------------------------


class TestJadxPath:
    def test_find_jadx_returns_none_or_str(self):
        result = AndroidJavaDecompiler.find_jadx()
        assert result is None or isinstance(result, str)

    def test_decompile_via_fake_jadx(self, tmp_path, monkeypatch):
        """模拟 jadx 可用：校验命令行调用与源码收集。"""
        fake_apk = tmp_path / "fake.apk"
        fake_apk.write_bytes(b"PK\x03\x04fake")
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            out_dir = argv[2]
            java_dir = __import__("pathlib").Path(out_dir) / "sources" / "com" / "app"
            java_dir.mkdir(parents=True, exist_ok=True)
            (java_dir / "MainActivity.java").write_text(
                "public class MainActivity { String token = \"http://x\"; }",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

        monkeypatch.setattr(AndroidJavaDecompiler, "find_jadx", staticmethod(lambda: "fake-jadx"))
        monkeypatch.setattr(
            "fp_sentinel.mobile_decompile.core.android_java.subprocess.run", fake_run
        )
        out = tmp_path / "out"
        dec = AndroidJavaDecompiler(
            target_path=str(fake_apk),
            dex_parser=_FakeParser(),
        )
        result = _run(
            dec.decompile(
                str(fake_apk),
                DecompileConfig(output_dir=str(out), engine="auto", include_strings=False),
            )
        )
        assert result.success
        assert result.engine_used == "jadx"
        assert result.quality_score == 0.9
        assert any(sf.language == "java" for sf in result.source_files)
        assert calls and calls[0][0] == "fake-jadx"
        # TEXT 搜索应能命中 jadx 产出的源码
        hits = dec.search_keyword("token", match_types=[MatchType.TEXT])
        assert hits and hits[0].code_snippet.startswith("public class")

    def test_jadx_failure_falls_back(self, tmp_path, monkeypatch):
        """jadx 退出码非 0 时：记录警告并降级（此处目标为非法输入，只验证降级触发）。"""
        monkeypatch.setattr(AndroidJavaDecompiler, "find_jadx", staticmethod(lambda: "fake-jadx"))
        monkeypatch.setattr(
            "fp_sentinel.mobile_decompile.core.android_java.subprocess.run",
            lambda argv, **kw: subprocess.CompletedProcess(argv, 1, stdout="", stderr="boom"),
        )
        dec = AndroidJavaDecompiler(dex_parser=_FakeParser())
        target = tmp_path / "whatever.apk"
        target.write_bytes(b"PK\x03\x04fake")
        result = _run(dec.decompile(str(target), DecompileConfig(engine="auto")))
        assert any("jadx" in w for w in result.warnings)


class _FakeParser:
    """最小 DexParser 替身：无需 androguard。"""

    def __init__(self):
        from fp_sentinel.mobile_decompile.models.class_info import ClassInfo

        self._cls = ClassInfo(
            name="Lcom/app/Main;",
            super_name="Landroid/app/Activity;",
            methods=[],
            fields=[],
        )

    @property
    def class_count(self):
        return 1

    @property
    def method_count(self):
        return 0

    def classes(self, app_package=None):
        return [self._cls]

    def strings(self):
        return []


# --------------------------------------------------------------------------
# 真实 APK 集成：androguard 降级反编译 + 搜索
# --------------------------------------------------------------------------


@requires_insecure_bank
class TestAndroidJavaIntegration:
    def test_decompile_androguard_fallback(self, tmp_path, monkeypatch):
        """jadx 不可用 -> androguard outline 反编译（RD-006 降级标注）。"""
        monkeypatch.setattr(AndroidJavaDecompiler, "find_jadx", staticmethod(lambda: None))
        monkeypatch.setattr(
            AndroidJavaDecompiler, "try_install_jadx", staticmethod(lambda: None))
        suppress_androguard_logs()
        dec = AndroidJavaDecompiler()
        out = tmp_path / "outline_out"
        cfg = DecompileConfig(
            output_dir=str(out),
            engine="auto",
            max_source_files=30,
            include_strings=True,
            max_strings=500,
        )
        result = _run(dec.decompile(str(INSECURE_BANK_APK), cfg))
        assert result.success
        assert result.engine_used == "androguard"
        assert 0 < len(result.source_files) <= 30
        assert result.class_count > 0
        assert result.method_count > 0
        assert result.quality_score == 0.3
        assert result.duration_sec > 0
        assert result.string_table
        # RD-006: 降级质量明确标注
        assert any("不可用于代码审计" in w for w in result.warnings)
        summary = result.summary()
        assert summary["quality_label"] == "outline-only (jadx unavailable)"
        assert summary["degrade_warning"] is True
        # Manifest 已解析
        assert result.manifest_info is not None
        assert result.manifest_info.package_name == "com.android.insecurebankv2"
        # outline 文件确实写盘
        assert any(out.rglob("*.java"))
        # max_source_files 截断产生警告
        assert any("截断" in w for w in result.warnings)

    def test_manifest_info_components(self):
        suppress_androguard_logs()
        dec = AndroidJavaDecompiler(target_path=str(INSECURE_BANK_APK))
        info = dec.get_manifest()
        assert info is not None
        exported = info.exported_components
        assert exported
        activities = info.activities
        assert any(a.name == "com.android.insecurebankv2.LoginActivity" for a in activities)
        to_dict = info.to_dict()
        assert to_dict["exported_components"]

    def test_search_string_match(self):
        suppress_androguard_logs()
        dec = AndroidJavaDecompiler(target_path=str(INSECURE_BANK_APK))
        results = dec.search_keyword("http", match_types=[MatchType.STRING], limit=20)
        assert results
        assert all(r.match_type == MatchType.STRING for r in results)
        assert all(0.0 <= r.critical_score <= 1.0 for r in results)

    def test_search_call_and_xref(self, insecure_bank_parser):
        suppress_androguard_logs()
        dec = AndroidJavaDecompiler(
            target_path=str(INSECURE_BANK_APK), dex_parser=insecure_bank_parser
        )
        call_hits = dec.search_keyword("login", match_types=[MatchType.CALL], limit=10)
        assert call_hits
        assert all(h.match_type == MatchType.CALL for h in call_hits)
        xref_hits = dec.search_keyword("login", match_types=[MatchType.XREF], limit=10)
        assert xref_hits
        assert all(0.0 <= h.critical_score <= 1.0 for h in xref_hits)

    def test_search_scope_filter(self, insecure_bank_parser):
        dec = AndroidJavaDecompiler(
            target_path=str(INSECURE_BANK_APK), dex_parser=insecure_bank_parser
        )
        results = dec.search_keyword(
            "login", match_types=[MatchType.CALL], scope="com.android.insecurebankv2", limit=20
        )
        assert all("com.android.insecurebankv2" in r.class_name for r in results)

    def test_text_search_on_injected_sources(self):
        dec = AndroidJavaDecompiler()
        dec._source_files = {
            "sources/Login.java": SourceFile(
                path="sources/Login.java",
                relative_path="sources/Login.java",
                content="public class Login {\n    String password = \"secret123\";\n}",
                language="java",
            )
        }
        hits = dec.search_keyword("password", match_types=[MatchType.TEXT])
        assert len(hits) == 1
        hit = hits[0]
        assert hit.line_number == 2
        assert hit.class_name == "Login"
        assert "secret123" in hit.code_snippet
        assert hit.context_before == "public class Login {"
        assert hit.context_after == "}"
        assert 0.0 <= hit.relevance_score <= 1.0

    def test_class_hierarchy_and_call_graph(self, insecure_bank_parser):
        dec = AndroidJavaDecompiler(
            target_path=str(INSECURE_BANK_APK), dex_parser=insecure_bank_parser
        )
        hierarchy = dec.get_class_hierarchy()
        assert len(hierarchy) > 0
        graph = dec.get_call_graph()
        assert graph.edge_count > 0

    def test_string_table(self, insecure_bank_parser):
        dec = AndroidJavaDecompiler(
            target_path=str(INSECURE_BANK_APK), dex_parser=insecure_bank_parser
        )
        table = dec.string_table(limit=50)
        assert len(table) <= 50
        assert table[0].source_file == str(INSECURE_BANK_APK)

    def test_get_class_info(self, insecure_bank_parser):
        dec = AndroidJavaDecompiler(
            target_path=str(INSECURE_BANK_APK), dex_parser=insecure_bank_parser
        )
        info = dec.get_class_info("com.android.insecurebankv2.LoginActivity")
        assert info is not None
        assert dec.get_class_info("com.nope.Nope") is None


# --------------------------------------------------------------------------
# Native 层（Ghidra/IDA 桩）
# --------------------------------------------------------------------------


def _elf_bytes(bits: int = 64) -> bytes:
    if bits == 64:
        head = struct.pack("<4B", 0x7F, 0x45, 0x4C, 0x46) + bytes([2, 1, 1, 0]) + b"\x00" * 8
        head += struct.pack("<HHIQ", 3, 0xB7, 1, 0x1000)
        return head
    head = struct.pack("<4B", 0x7F, 0x45, 0x4C, 0x46) + bytes([1, 1, 1, 0]) + b"\x00" * 8
    head += struct.pack("<HHII", 3, 0x28, 1, 0x1000)
    return head


class TestAndroidNative:
    def test_supports(self, tmp_path):
        so = tmp_path / "lib.so"
        so.write_bytes(_elf_bytes())
        assert AndroidNativeDecompiler.supports(str(so))
        txt = tmp_path / "x.txt"
        txt.write_text("x", encoding="utf-8")
        assert not AndroidNativeDecompiler.supports(str(txt))
        assert not AndroidNativeDecompiler.supports(str(tmp_path / "nope.so"))

    def test_decompile_unavailable_tools_degrades(self, tmp_path, monkeypatch):
        target = tmp_path / "libnative.so"
        target.write_bytes(_elf_bytes())
        monkeypatch.setattr(AndroidNativeDecompiler, "find_ghidra", staticmethod(lambda: None))
        monkeypatch.setattr(AndroidNativeDecompiler, "find_ida", staticmethod(lambda: None))
        result = _run(AndroidNativeDecompiler().decompile(str(target)))
        assert result.success
        assert result.engine_used == "elf-header"
        assert result.quality_score == 0.1
        assert "elf_header" in result.cross_references
        assert any("Ghidra" in e for e in result.errors)
        assert any("降级" in w for w in result.warnings)

    def test_decompile_ghidra_available_not_implemented(self, tmp_path, monkeypatch):
        target = tmp_path / "libnative.so"
        target.write_bytes(_elf_bytes())
        monkeypatch.setattr(
            AndroidNativeDecompiler, "find_ghidra", staticmethod(lambda: "/fake/analyzeHeadless")
        )
        with pytest.raises(NotImplementedError):
            _run(AndroidNativeDecompiler().decompile(str(target)))

    def test_decompile_errors(self, tmp_path):
        dec = AndroidNativeDecompiler()
        result = _run(dec.decompile(str(tmp_path / "missing.so")))
        assert not result.success
        txt = tmp_path / "x.so"
        txt.write_text("garbage", encoding="utf-8")
        result2 = _run(dec.decompile(str(txt)))
        assert not result2.success

    def test_search_and_hierarchy_stub(self):
        dec = AndroidNativeDecompiler()
        assert dec.search_keyword("anything") == []
        assert len(dec.get_class_hierarchy()) == 0

    def test_find_ghidra_and_ida(self, monkeypatch):
        monkeypatch.delenv("GHIDRA_HOME", raising=False)
        assert AndroidNativeDecompiler.find_ida() is None or isinstance(
            AndroidNativeDecompiler.find_ida(), str
        )

    def test_parse_elf_header(self, tmp_path):
        target = tmp_path / "lib.so"
        target.write_bytes(_elf_bytes(64))
        info = parse_elf_header(str(target))
        assert info["bits"] == 64 and info["little_endian"] and info["entry_point"] == 0x1000
        target32 = tmp_path / "lib32.so"
        target32.write_bytes(_elf_bytes(32))
        assert parse_elf_header(str(target32))["bits"] == 32

    def test_parse_elf_header_invalid(self, tmp_path):
        target = tmp_path / "bad.so"
        target.write_bytes(b"NOTELF!" * 8)
        with pytest.raises(ValueError):
            parse_elf_header(str(target))
        short = tmp_path / "short.so"
        short.write_bytes(b"\x7fELF" + b"\x00" * 3)
        with pytest.raises(ValueError):
            parse_elf_header(str(short))


# --------------------------------------------------------------------------
# iOS 层（class-dump 桩）
# --------------------------------------------------------------------------


def _macho_bytes() -> bytes:
    return struct.pack("<6I", 0xFEEDFACF, 0x0100000C, 3, 2, 0, 1) + b"\x00" * 8


class TestIosDecompiler:
    def test_supports(self, tmp_path):
        ipa = tmp_path / "App.ipa"
        ipa.write_bytes(b"PK\x03\x04")
        macho = tmp_path / "binary"
        macho.write_bytes(_macho_bytes())
        assert IosDecompiler.supports(str(ipa))
        assert IosDecompiler.supports(str(macho))
        txt = tmp_path / "x.txt"
        txt.write_text("x", encoding="utf-8")
        assert not IosDecompiler.supports(str(txt))
        assert not IosDecompiler.supports(str(tmp_path / "nope.ipa"))

    def test_decompile_errors(self, tmp_path):
        dec = IosDecompiler()
        result = _run(dec.decompile(str(tmp_path / "missing.ipa")))
        assert not result.success
        txt = tmp_path / "x.ipa"
        txt.write_text("garbage", encoding="utf-8")
        result2 = _run(dec.decompile(str(txt)))
        assert not result2.success

    def test_decompile_ipa_degrades(self, tmp_path, monkeypatch):
        ipa = tmp_path / "App.ipa"
        with __import__("zipfile").ZipFile(ipa, "w") as zf:
            zf.writestr("Payload/Demo.app/Demo", b"\xcf\xfa\xed\xfe")
        monkeypatch.setattr(IosDecompiler, "find_class_dump", staticmethod(lambda: None))
        # IPA 不是裸 Mach-O：降级解析头部失败 -> 报错返回
        result = _run(dec_decompile_ipa(ipa))
        assert not result.success
        assert result.errors

    def test_decompile_macho_degrades(self, tmp_path, monkeypatch):
        macho = tmp_path / "binary"
        macho.write_bytes(_macho_bytes())
        monkeypatch.setattr(IosDecompiler, "find_class_dump", staticmethod(lambda: None))
        result = _run(IosDecompiler().decompile(str(macho)))
        assert result.success
        assert result.engine_used == "macho-header"
        assert "macho_header" in result.cross_references

    def test_decompile_class_dump_available_not_implemented(self, tmp_path, monkeypatch):
        macho = tmp_path / "binary"
        macho.write_bytes(_macho_bytes())
        monkeypatch.setattr(
            IosDecompiler, "find_class_dump", staticmethod(lambda: "/fake/class-dump")
        )
        with pytest.raises(NotImplementedError):
            _run(IosDecompiler().decompile(str(macho)))

    def test_ipa_without_executable(self, tmp_path):
        ipa = tmp_path / "Empty.ipa"
        with __import__("zipfile").ZipFile(ipa, "w") as zf:
            zf.writestr("Payload/Demo.app/Info.plist", b"plist")
        with pytest.raises(ValueError):
            IosDecompiler._count_macho_in_ipa(str(ipa))

    def test_search_and_hierarchy_stub(self):
        dec = IosDecompiler()
        assert dec.search_keyword("anything") == []
        assert len(dec.get_class_hierarchy()) == 0

    def test_find_class_dump(self):
        assert IosDecompiler.find_class_dump() is None or isinstance(
            IosDecompiler.find_class_dump(), str
        )

    def test_parse_macho_header(self, tmp_path):
        target = tmp_path / "bin"
        target.write_bytes(_macho_bytes())
        info = parse_macho_header(str(target))
        assert info["bits"] == 64 and info["little_endian"] and info["filetype"] == 2

    def test_parse_macho_header_invalid(self, tmp_path):
        bad = tmp_path / "bad"
        bad.write_bytes(b"XXXX" + b"\x00" * 28)
        with pytest.raises(ValueError):
            parse_macho_header(str(bad))
        short = tmp_path / "short"
        short.write_bytes(b"\xcf\xfa")
        with pytest.raises(ValueError):
            parse_macho_header(str(short))


def dec_decompile_ipa(ipa):
    return IosDecompiler().decompile(str(ipa))


# --------------------------------------------------------------------------
# 补充覆盖：jadx 异常路径 / 降级细节 / 搜索选项
# --------------------------------------------------------------------------


class TestDecompileEdgeCases:
    def test_engine_jadx_explicit_unavailable(self, tmp_path, monkeypatch):
        """engine=jadx 但不可用 -> 警告并降级 androguard。"""
        monkeypatch.setattr(AndroidJavaDecompiler, "find_jadx", staticmethod(lambda: None))
        monkeypatch.setattr(
            AndroidJavaDecompiler, "try_install_jadx", staticmethod(lambda: None))
        target = tmp_path / "a.apk"
        target.write_bytes(b"PK\x03\x04")
        dec = AndroidJavaDecompiler(dex_parser=_FakeParser())
        result = _run(
            dec.decompile(str(target), DecompileConfig(engine="jadx", output_dir=str(tmp_path)))
        )
        assert any("jadx 不可用" in w for w in result.warnings)
        assert result.engine_used == "androguard"
        assert result.success

    def test_jadx_timeout_falls_back(self, tmp_path, monkeypatch):
        monkeypatch.setattr(AndroidJavaDecompiler, "find_jadx", staticmethod(lambda: "fake-jadx"))

        def fake_run(argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd="jadx", timeout=1)

        monkeypatch.setattr(
            "fp_sentinel.mobile_decompile.core.android_java.subprocess.run", fake_run
        )
        target = tmp_path / "a.apk"
        target.write_bytes(b"PK\x03\x04")
        dec = AndroidJavaDecompiler(dex_parser=_FakeParser())
        result = _run(dec.decompile(str(target), DecompileConfig(engine="auto")))
        assert any("jadx 调用异常" in w for w in result.warnings)
        assert result.engine_used == "androguard"

    def test_jadx_zero_output_falls_back(self, tmp_path, monkeypatch):
        """jadx 返回 0 但无产物 -> 警告并降级。"""
        monkeypatch.setattr(AndroidJavaDecompiler, "find_jadx", staticmethod(lambda: "fake-jadx"))
        monkeypatch.setattr(
            "fp_sentinel.mobile_decompile.core.android_java.subprocess.run",
            lambda argv, **kw: subprocess.CompletedProcess(argv, 0, stdout="", stderr=""),
        )
        target = tmp_path / "a.apk"
        target.write_bytes(b"PK\x03\x04")
        dec = AndroidJavaDecompiler(dex_parser=_FakeParser())
        result = _run(dec.decompile(str(target), DecompileConfig(engine="auto")))
        assert any("未产出源码" in w for w in result.warnings)
        assert result.engine_used == "androguard"

    def test_quality_score_zero_without_sources(self):
        dec = AndroidJavaDecompiler()
        assert dec._quality_score(DecompileConfig()) == 0.0

    def test_get_manifest_invalid_target(self, tmp_path):
        target = tmp_path / "plain.txt"
        target.write_text("x", encoding="utf-8")
        dec = AndroidJavaDecompiler(target_path=str(target))
        assert dec.get_manifest() is None

    def test_manifest_parse_error_downgraded(self, tmp_path, monkeypatch):
        """jadx 成功但 Manifest 解析失败 -> 仅记录警告不阻断。"""
        monkeypatch.setattr(AndroidJavaDecompiler, "find_jadx", staticmethod(lambda: "fake-jadx"))

        def fake_run(argv, **kwargs):
            import pathlib

            java_dir = pathlib.Path(argv[2]) / "s"
            java_dir.mkdir(parents=True, exist_ok=True)
            (java_dir / "T.java").write_text("class T {}", encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr(
            "fp_sentinel.mobile_decompile.core.android_java.subprocess.run", fake_run
        )

        import fp_sentinel.mobile_decompile.core.android_java as aj_module

        def bad_manifest_parser(path):
            raise ValueError("broken manifest")

        monkeypatch.setattr(aj_module, "ManifestParser", bad_manifest_parser)
        target = tmp_path / "a.apk"
        target.write_bytes(b"PK\x03\x04")
        dec = AndroidJavaDecompiler(dex_parser=_FakeParser())
        result = _run(
            dec.decompile(str(target), DecompileConfig(engine="auto", include_manifest=True))
        )
        assert result.success
        assert any("Manifest 解析跳过" in w for w in result.warnings)

    def test_source_texts(self):
        dec = AndroidJavaDecompiler()
        assert dec.source_texts() == {}
        dec._source_files = {"a.java": SourceFile(path="a", relative_path="a.java", content="X")}
        assert dec.source_texts() == {"a.java": "X"}


class TestSearchEdgeCases:
    def _inject(self, dec: AndroidJavaDecompiler, lines):
        content = "\n".join(lines)
        dec._source_files = {
            "src/Cls.java": SourceFile(
                path="src/Cls.java",
                relative_path="src/Cls.java",
                content=content,
                language="java",
            )
        }

    def test_text_search_limit(self):
        dec = AndroidJavaDecompiler()
        self._inject(dec, [f"token{i} = {i}" for i in range(10)])
        hits = dec.search_keyword("token", match_types=[MatchType.TEXT], limit=3)
        assert len(hits) == 3

    def test_text_search_case_sensitive(self):
        dec = AndroidJavaDecompiler()
        self._inject(dec, ["lower token", "UPPER Token", "plain"])
        # 大写 Token 仅命中第 2 行；小写 token 才命中第 1 行
        hits = dec.search_keyword("Token", match_types=[MatchType.TEXT], case_sensitive=True)
        assert len(hits) == 1
        assert "UPPER" in hits[0].code_snippet
        hits_lower = dec.search_keyword("token", match_types=[MatchType.TEXT], case_sensitive=True)
        assert len(hits_lower) == 1
        assert hits_lower[0].line_number == 1

    def test_text_relevance_exact(self):
        dec = AndroidJavaDecompiler()
        self._inject(dec, ["token"])
        hit = dec.search_keyword("token", match_types=[MatchType.TEXT])[0]
        assert hit.relevance_score == 0.8

    def test_string_scope_filters_all(self, insecure_bank_parser):
        dec = AndroidJavaDecompiler(
            target_path=str(INSECURE_BANK_APK), dex_parser=insecure_bank_parser
        )
        results = dec.search_keyword(
            "http", match_types=[MatchType.STRING], scope="no.such.pkg", limit=10
        )
        assert results == []

    def test_call_search_limit(self, insecure_bank_parser):
        dec = AndroidJavaDecompiler(
            target_path=str(INSECURE_BANK_APK), dex_parser=insecure_bank_parser
        )
        results = dec.search_keyword("login", match_types=[MatchType.CALL], limit=1)
        assert len(results) <= 1


class TestStubToolDiscovery:
    def test_find_ghidra_from_home_env(self, tmp_path, monkeypatch):
        import fp_sentinel.mobile_decompile.core.android_native as an

        home = tmp_path / "ghidra"
        (home / "support").mkdir(parents=True)
        bat = home / "support" / "analyzeHeadless.bat"
        bat.write_text("@echo off", encoding="utf-8")
        monkeypatch.setattr(an.shutil, "which", lambda x: None)
        monkeypatch.setenv("GHIDRA_HOME", str(home))
        assert AndroidNativeDecompiler.find_ghidra() == str(bat)
        # GHIDRA_HOME 指向空目录 -> None
        empty = tmp_path / "empty_ghidra"
        empty.mkdir()
        monkeypatch.setenv("GHIDRA_HOME", str(empty))
        assert AndroidNativeDecompiler.find_ghidra() is None
        monkeypatch.delenv("GHIDRA_HOME")
        assert AndroidNativeDecompiler.find_ghidra() is None

    def test_find_ida_found(self, monkeypatch):
        import fp_sentinel.mobile_decompile.core.android_native as an

        monkeypatch.setattr(an.shutil, "which", lambda x: "C:/ida/ida64.exe")
        assert AndroidNativeDecompiler.find_ida() == "C:/ida/ida64.exe"

    def test_find_class_dump_found(self, monkeypatch):
        import fp_sentinel.mobile_decompile.core.ios_decompiler as ios

        monkeypatch.setattr(ios.shutil, "which", lambda x: "/usr/bin/class-dump")
        assert IosDecompiler.find_class_dump() == "/usr/bin/class-dump"

    def test_native_decompile_invalid_no_extension(self, tmp_path):
        target = tmp_path / "garbage"
        target.write_text("junk", encoding="utf-8")
        result = _run(AndroidNativeDecompiler().decompile(str(target)))
        assert not result.success
        assert any("ELF/SO" in e for e in result.errors)

    def test_ios_decompile_invalid_no_extension(self, tmp_path):
        target = tmp_path / "garbage"
        target.write_text("junk", encoding="utf-8")
        result = _run(IosDecompiler().decompile(str(target)))
        assert not result.success
        assert any("IPA/Mach-O" in e for e in result.errors)

    def test_parse_macho_header_big_endian(self, tmp_path):
        target = tmp_path / "bin_be"
        target.write_bytes(struct.pack(">6I", 0xFEEDFACF, 0x0100000C, 3, 2, 0, 1) + b"\x00" * 8)
        info = parse_macho_header(str(target))
        assert info["little_endian"] is False
        assert info["bits"] == 64

    def test_base_now(self):
        from fp_sentinel.mobile_decompile.core.base import Decompiler

        assert Decompiler.now() > 0
