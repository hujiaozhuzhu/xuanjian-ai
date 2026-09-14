"""
test_ios_dumper —— iOS 脱壳引擎单元测试

覆盖：
- Mach-O cryptid 解析（64/32 位、大小端、FAT、异常输入）
- IPA 加密状态检测（FairPlay / 未加密 / 未知）
- 静态导出（未加密 IPA）
- frida 动态路径（mock frida 模块：成功 / 失败 / 未安装）
- 检测模式降级（无越狱设备）
- S1 红线
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

from fp_sentinel.mobile_shell.core.base import UnsafeTargetError
from fp_sentinel.mobile_shell.core.ios_dumper import (
    IOSDumper,
    PROTECTION_FAIRPLAY,
    PROTECTION_UNENCRYPTED,
    parse_macho_cryptid,
)
from fp_sentinel.mobile_shell.models.dump_result import (
    DumpConfig,
    DumpMode,
    DumpTarget,
    FileFormat,
    Platform,
)

from .conftest import build_fat_macho, build_ipa, build_macho


# ─────────────────────── Mach-O cryptid 解析 ───────────────────────


class TestMachoParsing:
    def test_64bit_little_encrypted(self):
        assert parse_macho_cryptid(build_macho(1)) == 1

    def test_64bit_little_unencrypted(self):
        assert parse_macho_cryptid(build_macho(0)) == 0

    def test_64bit_big_endian(self):
        assert parse_macho_cryptid(build_macho(1, little=False)) == 1

    def test_32bit_little(self):
        assert parse_macho_cryptid(build_macho(1, is64=False)) == 1

    def test_32bit_big_endian(self):
        assert parse_macho_cryptid(build_macho(0, is64=False, little=False)) == 0

    def test_fat_binary(self):
        assert parse_macho_cryptid(build_fat_macho(1)) == 1

    def test_fat_bad_magic_inside(self):
        """FAT 表指向非法 slice → None。"""
        blob = b"\xca\xfe\xba\xbe" + (b"\x00" * 24)
        assert parse_macho_cryptid(blob) is None

    def test_too_short(self):
        assert parse_macho_cryptid(b"\x00" * 10) is None

    def test_invalid_magic(self):
        assert parse_macho_cryptid(b"ELF..." + b"\x00" * 64) is None

    def test_zero_load_commands(self):
        blob = build_macho(1)[:16] + (b"\x00" * 4) + build_macho(1)[20:]
        # ncmds=0 → 无 LC → None
        assert parse_macho_cryptid(blob) is None

    def test_truncated_load_commands(self):
        """cmdsize 溢出边界 → 循环终止不崩溃。"""
        blob = build_macho(1)
        blob = blob[:16] + (10).to_bytes(4, "little") + blob[20:]  # ncmds=10
        assert isinstance(parse_macho_cryptid(blob), (int, type(None)))

    def test_bad_cmdsize_guard(self):
        """cmdsize=0 → 防死循环守卫生效。"""
        import struct

        blob = build_macho(1)
        # 替换第一个 load command 为 LC_SEGMENT 且 cmdsize=0
        blob = blob[:32] + struct.pack("<II", 0x1, 0) + blob[40:]
        assert parse_macho_cryptid(blob) is None


# ─────────────────────── IPA 检测 ───────────────────────


class TestIpaDetection:
    def test_detect_fairplay(self, tmp_path):
        ipa = build_ipa(tmp_path / "enc.ipa", build_macho(1))
        info = IOSDumper().detect_protection(str(ipa))
        assert info.protection == PROTECTION_FAIRPLAY
        assert info.is_packed is True
        assert info.confidence == 0.9
        assert info.details["cryptid"] == 1

    def test_detect_unencrypted(self, tmp_path):
        ipa = build_ipa(tmp_path / "plain.ipa", build_macho(0))
        info = IOSDumper().detect_protection(str(ipa))
        assert info.protection == PROTECTION_UNENCRYPTED
        assert info.is_packed is False

    def test_detect_no_binary(self, tmp_path):
        """IPA 无 MacOS 主二进制 → unknown。"""
        ipa = tmp_path / "empty.ipa"
        import zipfile

        with zipfile.ZipFile(ipa, "w") as zf:
            zf.writestr("Payload/App.app/Info.plist", b"x")
        info = IOSDumper().detect_protection(str(ipa))
        assert info.protection == "unknown"
        assert info.confidence <= 0.3

    def test_detect_bad_zip(self, tmp_path):
        fake = tmp_path / "fake.ipa"
        fake.write_text("junk", encoding="utf-8")
        info = IOSDumper().detect_protection(str(fake))
        assert info.protection == "unknown"

    def test_detect_missing_file(self):
        with pytest.raises(FileNotFoundError):
            IOSDumper().detect_protection("Z:/no/app.ipa")

    def test_detect_bare_macho(self, tmp_path):
        bin_path = tmp_path / "Demo.bin"
        bin_path.write_bytes(build_macho(1))
        info = IOSDumper().detect_protection(str(bin_path))
        assert info.protection == PROTECTION_FAIRPLAY


# ─────────────────────── dump：静态导出与降级 ───────────────────────


class TestIosDumpStatic:
    def test_dump_unencrypted_ipa(self, tmp_path):
        """未加密 IPA → 直接复制成功。"""
        ipa = build_ipa(tmp_path / "plain.ipa", build_macho(0))
        out_dir = tmp_path / "out"
        result = IOSDumper().dump(
            DumpTarget(path=str(ipa)),
            DumpConfig(output_dir=str(out_dir), mode=DumpMode.STATIC),
        )
        assert result.success is True
        assert result.mode == DumpMode.STATIC
        assert result.dumped_path and Path(result.dumped_path).is_file()
        assert result.sha256_after

    def test_dump_encrypted_no_device(self, tmp_path):
        """FairPlay IPA 无设备 → 检测模式降级。"""
        ipa = build_ipa(tmp_path / "enc.ipa", build_macho(1))
        result = IOSDumper().dump(
            DumpTarget(path=str(ipa)),
            DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.STATIC),
        )
        assert result.success is False
        assert result.mode == DumpMode.DETECT
        assert any("降级为检测模式" in w for w in result.warnings)

    def test_dump_platform_mismatch(self, insecure_bank_apk):
        """APK 交给 iOS 引擎 → ValueError。"""
        target = DumpTarget(path=str(insecure_bank_apk))
        with pytest.raises(ValueError, match="仅支持"):
            IOSDumper().dump(target, DumpConfig())

    def test_s1_guard_non_local(self, tmp_path):
        """S1：非 localhost 远程设备被拒绝。"""
        ipa = build_ipa(tmp_path / "enc.ipa", build_macho(1))
        target = DumpTarget(
            path=str(ipa), package="com.a", remote_host="192.168.1.5:27042",
            platform_hint=Platform.IOS,
        )
        with pytest.raises(UnsafeTargetError):
            IOSDumper().dump(target, DumpConfig())

    def test_supported_formats(self):
        fmts = IOSDumper().get_supported_formats()
        assert FileFormat.IPA in fmts and FileFormat.MACHO in fmts
        assert IOSDumper().name == "ios-dumper"
        assert "frida-ios-dump" in IOSDumper().get_device_banner()


# ─────────────────────── dump：frida 动态路径（mock） ───────────────────────


class _FakeScript:
    """frida Script 替身：exports_sync.dump_main_executable() 返回 base64 载荷。"""

    def __init__(self, payload: bytes):
        self._payload = payload
        self.loaded = False

    def load(self):
        self.loaded = True

    @property
    def exports_sync(self):
        outer = self

        class Exports:
            def dump_main_executable(self):
                if outer._payload is None:
                    return None
                return base64.b64encode(outer._payload).decode()

        return Exports()


class _FakeSession:
    def __init__(self, script):
        self._script = script
        self.detached = False

    def create_script(self, js):
        return self._script

    def detach(self):
        self.detached = True


class _FakeDevice:
    def __init__(self, script):
        self._script = script

    def attach(self, package):
        return _FakeSession(self._script)


class _FakeMgr:
    def __init__(self, device):
        self._device = device
        self.added = []

    def add_remote_device(self, host):
        self.added.append(host)
        return self._device


class _FakeFrida:
    """frida 模块替身（USB / 远程设备）。"""

    def __init__(self, device, usb_ok: bool = True):
        self._device = device
        self._usb_ok = usb_ok
        self._mgr = _FakeMgr(device)

    def get_device_manager(self):
        return self._mgr

    def get_usb_device(self, timeout=2):
        if self._usb_ok:
            return self._device
        raise Exception("no usb device")


def _install_fake_frida(monkeypatch, payload, usb_ok: bool = True):
    script = _FakeScript(payload)
    device = _FakeDevice(script)
    fake = _FakeFrida(device, usb_ok=usb_ok)
    monkeypatch.setitem(sys.modules, "frida", fake)
    return fake


class TestIosDumpFrida:
    def _target(self, ipa: Path) -> DumpTarget:
        return DumpTarget(path=str(ipa), package="com.target.app", platform_hint=Platform.IOS)

    def test_dump_success_usb(self, tmp_path, monkeypatch):
        """frida 可用 → 内存转储落盘 decrypted.bin。"""
        ipa = build_ipa(tmp_path / "enc.ipa", build_macho(1))
        payload = b"\xcf\xfa\xed\xfe-decrypted" + b"\x00" * 48
        _install_fake_frida(monkeypatch, payload)
        result = IOSDumper().dump(
            self._target(ipa),
            DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.FRIDA),
        )
        assert result.success is True
        assert result.mode == DumpMode.FRIDA
        dumped = Path(result.dumped_path)
        assert dumped.name == "decrypted.bin"
        assert dumped.read_bytes() == payload

    def test_dump_success_remote_local(self, tmp_path, monkeypatch):
        """remote_host=127.0.0.1 → 走远程设备路径。"""
        ipa = build_ipa(tmp_path / "enc.ipa", build_macho(1))
        payload = b"\xcf\xfa\xed\xfe-remote"
        fake = _install_fake_frida(monkeypatch, payload)
        target = DumpTarget(
            path=str(ipa), package="com.target.app",
            remote_host="127.0.0.1:27042", platform_hint=Platform.IOS,
        )
        result = IOSDumper().dump(
            target, DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.FRIDA)
        )
        assert result.success is True
        assert fake.get_device_manager().added == ["127.0.0.1:27042"]

    def test_dump_empty_payload(self, tmp_path, monkeypatch):
        """转储为空 → 失败并告警。"""
        ipa = build_ipa(tmp_path / "enc.ipa", build_macho(1))
        script = _FakeScript(None)  # None → exports 返回 None
        monkeypatch.setitem(sys.modules, "frida", _FakeFrida(_FakeDevice(script)))
        result = IOSDumper().dump(
            self._target(ipa),
            DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.FRIDA),
        )
        assert result.success is False
        assert any("转储为空" in w for w in result.warnings)

    def test_dump_attach_failure(self, tmp_path, monkeypatch):
        """attach 失败 → 降级检测模式。"""
        ipa = build_ipa(tmp_path / "enc.ipa", build_macho(1))

        class BadDevice:
            def attach(self, package):
                raise RuntimeError("process not found")

        monkeypatch.setitem(sys.modules, "frida", _FakeFrida(BadDevice()))
        result = IOSDumper().dump(
            self._target(ipa),
            DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.FRIDA),
        )
        assert result.success is False
        assert result.mode == DumpMode.DETECT
        assert any("frida 脱壳失败" in w for w in result.warnings)

    def test_dump_no_usb_device(self, tmp_path, monkeypatch):
        """USB 无设备 → 降级检测模式。"""
        ipa = build_ipa(tmp_path / "enc.ipa", build_macho(1))
        _install_fake_frida(monkeypatch, b"payload", usb_ok=False)
        result = IOSDumper().dump(
            self._target(ipa),
            DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.FRIDA),
        )
        assert result.success is False
        assert any("未发现可用设备" in w for w in result.warnings)

    def test_dump_frida_not_installed(self, tmp_path, monkeypatch):
        """frida SDK 未安装 → 降级检测模式。"""
        monkeypatch.setitem(sys.modules, "frida", None)  # import 即抛 ImportError
        ipa = build_ipa(tmp_path / "enc.ipa", build_macho(1))
        result = IOSDumper().dump(
            self._target(ipa),
            DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.FRIDA),
        )
        assert result.success is False
        assert any("frida SDK 未安装" in w for w in result.warnings)

    def test_dump_device_only_without_frida(self, tmp_path, monkeypatch):
        """仅包名目标（无本地 IPA）且 frida 未安装 → 检测模式。"""
        monkeypatch.setitem(sys.modules, "frida", None)
        target = DumpTarget(
            path="com.target.app", package="com.target.app", platform_hint=Platform.IOS
        )
        assert target.is_device_only is True
        result = IOSDumper().dump(
            target, DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.FRIDA)
        )
        assert result.success is False
        assert result.mode == DumpMode.DETECT
        assert result.platform == Platform.IOS

    def test_dump_device_only_with_frida(self, tmp_path, monkeypatch):
        """仅包名目标 + frida 可用 → 动态脱壳成功。"""
        payload = b"\xcf\xfa\xed\xfe-device-only"
        _install_fake_frida(monkeypatch, payload)
        target = DumpTarget(
            path="com.target.app", package="com.target.app", platform_hint=Platform.IOS
        )
        result = IOSDumper().dump(
            target, DumpConfig(output_dir=str(tmp_path / "out"), mode=DumpMode.FRIDA)
        )
        assert result.success is True
        assert Path(result.dumped_path).read_bytes() == payload
