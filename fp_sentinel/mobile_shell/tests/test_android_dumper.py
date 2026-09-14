"""
test_android_dumper —— Android 脱壳引擎单元测试

覆盖：
- 静态模式：真实无加固 APK 的明文 dex 提取（InsecureBankv2 / vuls_v4.4）
- 静态模式：加固 APK 的"需动态脱壳"降级路径
- 动态模式：frida-dexdump 可用/不可用/失败三种分支（mock）
- S1 红线：非 localhost remote_host 必须被拒绝
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from fp_sentinel.mobile_shell.core.android_dumper import AndroidDumper
from fp_sentinel.mobile_shell.core.base import UnsafeTargetError
from fp_sentinel.mobile_shell.models.dump_result import (
    DumpConfig,
    DumpMode,
    DumpTarget,
    FileFormat,
)
from fp_sentinel.mobile_shell.models.protection_info import PROTECTION_NONE

from .conftest import build_apk


# ─────────────────────── 引擎接口 ───────────────────────


class TestEngineInterface:
    def test_supported_formats_and_platform(self):
        dumper = AndroidDumper()
        assert dumper.platform == "android"
        assert FileFormat.APK in dumper.get_supported_formats()
        assert FileFormat.DEX in dumper.get_supported_formats()

    def test_platform_mismatch_rejected(self, insecure_bank_apk):
        """iOS 目标交给 Android 引擎 → ValueError。"""
        from fp_sentinel.mobile_shell.models.dump_result import Platform

        target = DumpTarget(
            path=str(insecure_bank_apk), platform_hint=Platform.IOS
        )
        with pytest.raises(ValueError, match="仅支持"):
            AndroidDumper().dump(target, DumpConfig())

    def test_unsupported_format_rejected(self, tmp_path):
        exe = tmp_path / "app.exe"
        exe.write_bytes(b"MZ")
        # 后缀校验在 DumpTarget 层直接拒绝
        with pytest.raises(ValueError, match="不支持的文件格式"):
            DumpTarget(path=str(exe))

    def test_target_missing_file(self):
        with pytest.raises(FileNotFoundError):
            DumpTarget(path="Z:/no/app.apk")

    def test_s1_guard_non_local(self, insecure_bank_apk):
        """S1：remote_host 非 localhost 必须抛 UnsafeTargetError。"""
        target = DumpTarget(
            path=str(insecure_bank_apk), remote_host="10.1.2.3:27042", package="com.a"
        )
        with pytest.raises(UnsafeTargetError):
            AndroidDumper().dump(target, DumpConfig())

    def test_s1_guard_local_ok(self, insecure_bank_apk, tmp_path):
        """S1：127.0.0.1 允许通过守卫（随后 frida 不可用降级静态）。"""
        target = DumpTarget(
            path=str(insecure_bank_apk), remote_host="127.0.0.1:27042", package="com.a"
        )
        result = AndroidDumper().dump(
            target, DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.FRIDA)
        )
        assert result.mode == DumpMode.STATIC  # frida 不可用 → 降级


# ─────────────────────── 静态模式（真实 APK） ───────────────────────


class TestStaticDumpRealApk:
    def test_dump_unpacked_apk(self, insecure_bank_apk, tmp_path):
        """无加固 APK → 静态提取明文 dex 成功。"""
        dumper = AndroidDumper()
        target = DumpTarget(path=str(insecure_bank_apk))
        config = DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.STATIC)
        result = dumper.dump(target, config)
        assert result.success is True
        assert result.mode == DumpMode.STATIC
        assert result.protection_type == PROTECTION_NONE
        assert result.dex_count >= 1
        assert result.sha256_before
        assert result.sha256_after
        assert result.dumped_path is not None
        dumped = list(Path(result.dumped_path).glob("*.dex"))
        assert len(dumped) == result.dex_count
        # 提取的 dex 与原 APK 内条目字节一致
        with zipfile.ZipFile(insecure_bank_apk) as zf:
            src = zf.read("classes.dex")
        assert dumped[0].read_bytes() == src
        assert result.duration_sec >= 0

    def test_dump_vuls_apk(self, vuls_apk, tmp_path):
        dumper = AndroidDumper()
        target = DumpTarget(path=str(vuls_apk))
        result = dumper.dump(
            target, DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.STATIC)
        )
        assert result.success is True
        assert result.dex_count >= 1

    def test_dump_bare_dex(self, insecure_bank_apk, tmp_path):
        """裸 DEX 目标 → 直接复制。"""
        dex_src = tmp_path / "classes.dex"
        with zipfile.ZipFile(insecure_bank_apk) as zf:
            dex_src.write_bytes(zf.read("classes.dex"))
        result = AndroidDumper().dump(
            DumpTarget(path=str(dex_src)),
            DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.STATIC),
        )
        assert result.success is True
        assert result.file_format == FileFormat.DEX
        assert result.dex_count == 1
        assert result.sha256_after == result.sha256_before

    def test_dump_packed_apk_static_degrades(self, tmp_path):
        """加固 APK 静态模式 → 不产出 dex，给出动态脱壳告警。"""
        apk = build_apk(tmp_path / "packed.apk", {
            "classes.dex": b"\x00" * 16,
            "lib/armeabi-v7a/libjiagu.so": b"x",
            "lib/arm64-v8a/libjiagu_64.so": b"x",
            "assets/ijiami.dat": b"x",
        })
        result = AndroidDumper(use_androguard=False).dump(
            DumpTarget(path=str(apk)),
            DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.STATIC),
        )
        assert result.success is False
        assert result.dumped_path is None
        assert any("动态脱壳" in w for w in result.warnings)

    def test_dump_apk_without_dex(self, tmp_path):
        """无 dex 条目的 APK → 静态提取失败并告警。"""
        apk = build_apk(tmp_path / "empty.apk", {"assets/a.txt": b"hi"})
        result = AndroidDumper(use_androguard=False).dump(
            DumpTarget(path=str(apk)),
            DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.STATIC),
        )
        assert result.success is False
        assert any("未找到 dex" in w for w in result.warnings)


# ─────────────────────── 动态模式（mock frida-dexdump） ───────────────────────


class _FakeWrapper:
    """FridaDexDump 替身。"""

    def __init__(self, available: bool, fail: bool = False):
        self._available = available
        self._fail = fail

    @property
    def available(self) -> bool:
        return self._available

    def dump(self, **kwargs):
        if self._fail:
            raise RuntimeError("device not found")
        out = Path(kwargs["output_dir"])
        out.mkdir(parents=True, exist_ok=True)
        (out / "classes.dex").write_bytes(b"dex\n035\x00" + b"\x00" * 32)
        (out / "classes2.dex").write_bytes(b"dex\n035\x00" + b"\x00" * 32)
        return out

    @staticmethod
    def list_dumped_dex(dump_dir):
        return sorted(Path(dump_dir).glob("*.dex"), key=lambda f: f.name)


class TestFridaMode:
    def _apk(self, tmp_path):
        return build_apk(tmp_path / "plain.apk", {
            "classes.dex": b"\x00" * 16, "AndroidManifest.xml": b"\x03\x00",
        })

    def test_frida_success(self, tmp_path, monkeypatch):
        """frida-dexdump 成功 → mode=FRIDA 且统计 dex。"""
        import fp_sentinel.mobile_shell.integrations.frida_dexdump as mod

        monkeypatch.setattr(mod, "FridaDexDump", lambda: _FakeWrapper(True))
        result = AndroidDumper().dump(
            DumpTarget(path=str(self._apk(tmp_path)), package="com.a"),
            DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.FRIDA),
        )
        assert result.success is True
        assert result.mode == DumpMode.FRIDA
        assert result.dex_count == 2
        assert result.sha256_after

    def test_frida_unavailable_degrades(self, tmp_path, monkeypatch):
        """frida-dexdump 不可用 → 降级静态并成功提取明文 dex。"""
        import fp_sentinel.mobile_shell.integrations.frida_dexdump as mod

        monkeypatch.setattr(mod, "FridaDexDump", lambda: _FakeWrapper(False))
        result = AndroidDumper().dump(
            DumpTarget(path=str(self._apk(tmp_path)), package="com.a"),
            DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.FRIDA),
        )
        assert result.mode == DumpMode.STATIC
        assert result.success is True
        assert any("不可用" in w for w in result.warnings)

    def test_frida_failure_degrades(self, tmp_path, monkeypatch):
        """frida-dexdump 抛异常 → 降级静态。"""
        import fp_sentinel.mobile_shell.integrations.frida_dexdump as mod

        monkeypatch.setattr(mod, "FridaDexDump", lambda: _FakeWrapper(True, fail=True))
        result = AndroidDumper().dump(
            DumpTarget(path=str(self._apk(tmp_path)), package="com.a"),
            DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.FRIDA),
        )
        assert result.mode == DumpMode.STATIC
        assert result.success is True
        assert any("frida-dexdump 失败" in w for w in result.warnings)

    def test_frida_no_package_skipped(self, tmp_path, monkeypatch):
        """无法确定包名 → 跳过 frida-dexdump。"""
        import fp_sentinel.mobile_shell.integrations.frida_dexdump as mod

        monkeypatch.setattr(mod, "FridaDexDump", lambda: _FakeWrapper(True))
        # 无 package 且 androguard 关闭/解析失败 → package 为 None
        result = AndroidDumper(use_androguard=False).dump(
            DumpTarget(path=str(self._apk(tmp_path))),
            DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.FRIDA),
        )
        assert result.mode == DumpMode.STATIC
        assert any("包名" in w for w in result.warnings)

    def test_frida_dex_target_skipped(self, insecure_bank_apk, tmp_path):
        """裸 DEX 目标 → 直接走静态。"""
        dex = tmp_path / "classes.dex"
        with zipfile.ZipFile(insecure_bank_apk) as zf:
            dex.write_bytes(zf.read("classes.dex"))
        result = AndroidDumper().dump(
            DumpTarget(path=str(dex)),
            DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.FRIDA),
        )
        assert result.mode == DumpMode.STATIC
        assert result.success is True

    def test_androguard_package_read_failure(self, tmp_path):
        """androguard 解析失败 → 返回 None（记录 debug 日志）。"""
        apk = self._apk(tmp_path)
        assert AndroidDumper()._read_package(str(apk)) is None

    def test_androguard_package_read_ok(self, insecure_bank_apk):
        """真实 APK 可读取包名。"""
        pkg = AndroidDumper()._read_package(str(insecure_bank_apk))
        assert pkg and pkg.startswith("com.")


# ─────────────────────── 工具方法 ───────────────────────


class TestHelpers:
    def test_list_dex_entries_sorted(self, tmp_path):
        apk = build_apk(tmp_path / "m.apk", {
            "classes2.dex": b"\x00", "classes.dex": b"\x00", "assets/a": b"",
        })
        entries = AndroidDumper._list_dex_entries(str(apk))
        assert entries == ["classes.dex", "classes2.dex"]

    def test_prepare_output(self, tmp_path):
        out = AndroidDumper._prepare_output(str(tmp_path / "o"), "app")
        assert out.is_dir()
        assert out.name == "dumped"

    def test_dir_digest_deterministic(self, tmp_path):
        a = tmp_path / "a.dex"
        b = tmp_path / "b.dex"
        a.write_bytes(b"AAA")
        b.write_bytes(b"BBB")
        d1 = AndroidDumper._dir_digest([a, b])
        d2 = AndroidDumper._dir_digest([b, a])  # 顺序无关
        assert d1 == d2
        assert len(d1) == 64
