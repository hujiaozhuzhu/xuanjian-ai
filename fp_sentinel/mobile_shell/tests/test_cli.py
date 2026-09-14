"""
test_cli —— mobile shell CLI（typer）单元测试

命令覆盖：detect / dump-android / dump-ios / batch
"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fp_sentinel.mobile_shell.cli import mobile_app
from fp_sentinel.mobile_shell.models.dump_result import (
    DumpConfig,
    DumpMode,
    DumpResult,
    DumpTarget,
)
from fp_sentinel.mobile_shell.models.protection_info import ProtectionInfo

from .conftest import build_apk, build_ipa, build_macho

runner = CliRunner()


# ─────────────────────── detect ───────────────────────


class TestDetectCommand:
    def test_detect_real_apk(self, insecure_bank_apk):
        """真实靶场 APK 检测（默认文本输出）。"""
        result = runner.invoke(mobile_app, ["shell", "detect", str(insecure_bank_apk)])
        assert result.exit_code == 0
        assert "无壳" in result.output

    def test_detect_json_output(self, insecure_bank_apk):
        result = runner.invoke(
            mobile_app, ["shell", "detect", str(insecure_bank_apk), "--json"]
        )
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["protection"] == "无壳"
        assert payload["is_packed"] is False

    def test_detect_ipa(self, tmp_path):
        ipa = build_ipa(tmp_path / "a.ipa", build_macho(1))
        result = runner.invoke(mobile_app, ["shell", "detect", str(ipa)])
        assert result.exit_code == 0
        assert "FairPlay" in result.output


# ─────────────────────── dump-android ───────────────────────


class TestDumpAndroidCommand:
    def test_dump_static_success(self, insecure_bank_apk, tmp_path):
        result = runner.invoke(mobile_app, [
            "shell", "dump-android",
            "--apk", str(insecure_bank_apk),
            "--output", str(tmp_path / "out"),
            "--mode", "static",
        ])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["success"] is True
        assert payload["protection"] == "无壳"
        assert payload["dex_count"] >= 1
        assert Path(payload["dumped"]).is_dir()

    def test_dump_static_packed_fails(self, tmp_path):
        apk = build_apk(tmp_path / "packed.apk", {
            "classes.dex": b"\x00" * 8,
            "lib/armeabi-v7a/libjiagu.so": b"x",
        })
        result = runner.invoke(mobile_app, [
            "shell", "dump-android",
            "--apk", str(apk),
            "--output", str(tmp_path / "out"),
            "--mode", "static",
        ])
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["success"] is False

    def test_dump_mode_auto_degrades(self, tmp_path):
        """auto 模式：frida-dexdump 不可用 → 静态降级仍成功。"""
        apk = build_apk(tmp_path / "plain.apk", {"classes.dex": b"\x00" * 8})
        result = runner.invoke(mobile_app, [
            "shell", "dump-android",
            "--apk", str(apk),
            "--output", str(tmp_path / "out"),
            "--mode", "auto",
            "--device", "emulator-5554",
        ])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["mode"] == "static"

    def test_dump_missing_apk(self, tmp_path):
        result = runner.invoke(mobile_app, [
            "shell", "dump-android",
            "--apk", str(tmp_path / "no.apk"),
        ])
        assert result.exit_code != 0


# ─────────────────────── dump-ios ───────────────────────


class TestDumpIosCommand:
    def test_dump_no_args_exit_2(self):
        result = runner.invoke(mobile_app, ["shell", "dump-ios"])
        assert result.exit_code == 2

    def test_dump_unencrypted_ipa(self, tmp_path):
        ipa = build_ipa(tmp_path / "plain.ipa", build_macho(0))
        result = runner.invoke(mobile_app, [
            "shell", "dump-ios",
            "--app", str(ipa),
            "--output", str(tmp_path / "out"),
        ])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["success"] is True
        assert payload["protection"] == "未加密"

    def test_dump_encrypted_detect_mode(self, tmp_path):
        """FairPlay IPA 且无越狱设备 → 检测模式，exit 1。"""
        ipa = build_ipa(tmp_path / "enc.ipa", build_macho(1))
        result = runner.invoke(mobile_app, [
            "shell", "dump-ios",
            "--app", str(ipa),
            "--output", str(tmp_path / "out"),
        ])
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["success"] is False
        assert payload["mode"] == "detect"

    def test_dump_package_only_no_device(self, tmp_path, monkeypatch):
        """仅包名 + 无 frida → 检测模式降级。"""
        monkeypatch.setitem(sys.modules, "frida", None)
        result = runner.invoke(mobile_app, [
            "shell", "dump-ios",
            "--package", "com.target.app",
            "--output", str(tmp_path / "out"),
        ])
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["mode"] == "detect"


# ─────────────────────── batch ───────────────────────


class TestBatchCommand:
    def test_batch_mixed(self, insecure_bank_apk, tmp_path):
        """目录内 APK + IPA 批量处理。"""
        src = tmp_path / "apps"
        src.mkdir()
        (src / "bank.apk").write_bytes(insecure_bank_apk.read_bytes())
        build_ipa(src / "plain.ipa", build_macho(0))
        build_ipa(src / "enc.ipa", build_macho(1))
        result = runner.invoke(mobile_app, [
            "shell", "batch", str(src),
            "--output", str(tmp_path / "results"),
            "--platform", "all",
        ])
        assert result.exit_code == 1  # enc.ipa 检测模式失败
        assert "[OK]" in result.output and "[FAIL]" in result.output
        assert "批量完成: 2/3" in result.output

    def test_batch_android_filter(self, insecure_bank_apk, tmp_path):
        src = tmp_path / "apps"
        src.mkdir()
        (src / "bank.apk").write_bytes(insecure_bank_apk.read_bytes())
        build_ipa(src / "enc.ipa", build_macho(1))
        result = runner.invoke(mobile_app, [
            "shell", "batch", str(src), "--platform", "android",
        ])
        assert result.exit_code == 0
        assert "批量完成: 1/1" in result.output

    def test_batch_ios_filter(self, tmp_path):
        src = tmp_path / "apps"
        src.mkdir()
        build_ipa(src / "plain.ipa", build_macho(0))
        result = runner.invoke(mobile_app, [
            "shell", "batch", str(src), "--platform", "ios",
        ])
        assert result.exit_code == 0
        assert "批量完成: 1/1" in result.output

    def test_batch_empty_dir(self, tmp_path):
        src = tmp_path / "empty"
        src.mkdir()
        result = runner.invoke(mobile_app, ["shell", "batch", str(src)])
        assert result.exit_code == 0
        assert "未发现" in result.output

    def test_batch_missing_dir(self, tmp_path):
        result = runner.invoke(
            mobile_app, ["shell", "batch", str(tmp_path / "nope")]
        )
        assert result.exit_code == 2

    def test_batch_single_failure_does_not_abort(self, tmp_path):
        """单文件异常（伪 APK）不中断批量。"""
        src = tmp_path / "apps"
        src.mkdir()
        (src / "bad.apk").write_text("not zip", encoding="utf-8")
        result = runner.invoke(mobile_app, ["shell", "batch", str(src)])
        assert result.exit_code == 1
        assert "[FAIL]" in result.output
        assert "处理失败" in result.output


# ─────────────────────── 数据模型边界 ───────────────────────


class TestModels:
    def test_sha256_file_missing(self):
        from fp_sentinel.mobile_shell.models.dump_result import sha256_file

        assert sha256_file("Z:/no/file.bin") == ""

    def test_dump_result_log_warn(self):
        r = DumpResult(success=False, original_path="x")
        r.log("step1")
        r.warn("w1")
        assert r.logs == ["step1"] and r.warnings == ["w1"]

    def test_dump_result_finalize(self):
        r = DumpResult(success=True, original_path="x")
        r.finalize(0.0)
        assert r.duration_sec > 0

    def test_from_target(self, insecure_bank_apk):
        from fp_sentinel.mobile_shell.models.dump_result import sha256_file

        t = DumpTarget(path=str(insecure_bank_apk))
        r = DumpResult.from_target(t, protection_type="无壳", mode=DumpMode.STATIC)
        assert r.sha256_before == sha256_file(str(insecure_bank_apk))
        assert r.protection_type == "无壳"

    def test_target_suffix_properties(self, insecure_bank_apk):
        t = DumpTarget(path=str(insecure_bank_apk))
        assert t.suffix == "apk"
        assert t.file_format.value == "apk"

    def test_protection_info_summary(self):
        info = ProtectionInfo(protection="360加固", confidence=0.75, is_packed=True)
        assert "360加固" in info.summary()
        assert "0.75" in info.summary()

    def test_base_assert_local_forms(self):
        from fp_sentinel.mobile_shell.core.base import assert_local

        assert assert_local("localhost:27042") == "localhost:27042"
        assert assert_local("::1") == "::1"
        assert assert_local("http://localhost:8080/rpc") == "http://localhost:8080/rpc"
        assert assert_local("usb") == "usb"
        # host 部分为任意回环 IP（127.0.0.2）
        assert assert_local("127.0.0.2:27042") == "127.0.0.2:27042"
        with pytest.raises(Exception):
            assert_local("")
        with pytest.raises(Exception):
            assert_local(None)
        with pytest.raises(Exception):
            assert_local("example.com:27042")

    def test_engine_format_mismatch(self, tmp_path):
        """平台匹配但格式不受支持 → ValueError（validate_target 格式分支）。"""
        from fp_sentinel.mobile_shell.models.dump_result import Platform
        from fp_sentinel.mobile_shell.models.dump_result import DumpTarget

        ipa = build_ipa(tmp_path / "x.ipa", build_macho(0))
        target = DumpTarget(path=str(ipa), platform_hint=Platform.ANDROID)
        from fp_sentinel.mobile_shell.core.android_dumper import AndroidDumper

        with pytest.raises(ValueError, match="不支持格式"):
            AndroidDumper().dump(target, DumpConfig())
