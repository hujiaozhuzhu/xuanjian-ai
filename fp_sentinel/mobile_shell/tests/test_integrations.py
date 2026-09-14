"""
test_integrations —— frida-dexdump / BlackDex CLI 封装单元测试

全部 subprocess 调用均 mock，不依赖真实设备；S1 红线用例显式覆盖。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from fp_sentinel.mobile_shell.core.base import UnsafeTargetError
from fp_sentinel.mobile_shell.integrations.blackdex import BlackDex, BlackDexNotAvailable
from fp_sentinel.mobile_shell.integrations.frida_dexdump import (
    FridaDexDump,
    FridaDexDumpNotAvailable,
)


# ─────────────────────── FridaDexDump ───────────────────────


class TestFridaDexDump:
    def test_build_command_usb(self, tmp_path):
        cmd = FridaDexDump().build_command("com.a", str(tmp_path))
        assert cmd[:2] == ["frida-dexdump", "-U"]
        assert "-d" in cmd and "-f" in cmd and cmd[cmd.index("-f") + 1] == "com.a"
        assert cmd[cmd.index("-o") + 1] == str(tmp_path)

    def test_build_command_device_id(self, tmp_path):
        cmd = FridaDexDump().build_command("com.a", str(tmp_path), device_id="emulator-5554")
        assert "-D" in cmd and "emulator-5554" in cmd

    def test_build_command_remote_local(self, tmp_path):
        cmd = FridaDexDump().build_command("com.a", str(tmp_path), remote_host="127.0.0.1:27042")
        assert "-H" in cmd and "127.0.0.1:27042" in cmd

    def test_build_command_remote_non_local_s1(self, tmp_path):
        """S1：非 localhost 远程地址必须被拒绝。"""
        with pytest.raises(UnsafeTargetError):
            FridaDexDump().build_command("com.a", str(tmp_path), remote_host="10.0.0.8:27042")

    def test_build_command_no_deep_and_extra(self, tmp_path):
        cmd = FridaDexDump().build_command(
            "com.a", str(tmp_path), deep_search=False, extra_args=["--verbose"]
        )
        assert "-d" not in cmd and "--verbose" in cmd

    def test_available_false(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda name: None)
        assert FridaDexDump().available is False

    def test_dump_not_available_raises(self, monkeypatch, tmp_path):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda name: None)
        with pytest.raises(FridaDexDumpNotAvailable):
            FridaDexDump().dump("com.a", str(tmp_path / "out"))

    def test_dump_success(self, monkeypatch, tmp_path):
        """成功执行 → 命令含正确参数且输出目录创建。"""
        import shutil

        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/frida-dexdump")
        calls = {}

        def fake_run(cmd, **kwargs):
            calls["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        out = FridaDexDump().dump("com.a", str(tmp_path / "out"), device_id="dev1")
        assert out.is_dir()
        assert calls["cmd"][0] == "frida-dexdump"
        assert calls["cmd"][calls["cmd"].index("-D") + 1] == "dev1"

    def test_dump_failure(self, monkeypatch, tmp_path):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/frida-dexdump")
        monkeypatch.setattr(
            subprocess, "run",
            lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, stdout="", stderr="no device"),
        )
        with pytest.raises(subprocess.SubprocessError, match="no device"):
            FridaDexDump().dump("com.a", str(tmp_path / "out"))

    def test_dump_timeout(self, monkeypatch, tmp_path):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/frida-dexdump")

        def timeout_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 5)

        monkeypatch.setattr(subprocess, "run", timeout_run)
        with pytest.raises(subprocess.TimeoutExpired):
            FridaDexDump().dump("com.a", str(tmp_path / "out"), timeout_sec=5)

    def test_list_dumped_dex(self, tmp_path):
        (tmp_path / "b.dex").write_bytes(b"x")
        (tmp_path / "a.dex").write_bytes(b"x")
        (tmp_path / "c.txt").write_bytes(b"x")
        files = FridaDexDump.list_dumped_dex(tmp_path)
        assert [f.name for f in files] == ["a.dex", "b.dex"]

    def test_list_dumped_dex_missing_dir(self, tmp_path):
        assert FridaDexDump.list_dumped_dex(tmp_path / "nope") == []


# ─────────────────────── BlackDex ───────────────────────


class TestBlackDex:
    def test_build_dump_command_usb(self):
        cmd = BlackDex().build_dump_command("com.a", device_id="dev1")
        assert cmd[:2] == ["adb", "-s"]
        assert "shell" in cmd and "com.a" in cmd

    def test_build_dump_command_remote_local(self):
        cmd = BlackDex().build_dump_command("com.a", remote_host="127.0.0.1:5037")
        assert cmd[1:3] == ["-H", "127.0.0.1:5037"]

    def test_build_dump_command_s1(self):
        with pytest.raises(UnsafeTargetError):
            BlackDex().build_dump_command("com.a", remote_host="172.16.0.1:5037")

    def test_build_pull_command(self):
        cmd = BlackDex().build_pull_command("/sdcard/BlackDex/", "out", device_id="dev1")
        assert cmd[-2] == "/sdcard/BlackDex/" and cmd[-1] == "out"

    def test_build_pull_command_s1(self):
        with pytest.raises(UnsafeTargetError):
            BlackDex().build_pull_command("/sdcard/", "out", remote_host="bad.host:5037")

    def test_available_false(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda name: None)
        assert BlackDex().available is False

    def test_dump_not_available(self, monkeypatch, tmp_path):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda name: None)
        with pytest.raises(BlackDexNotAvailable):
            BlackDex().dump("com.a", str(tmp_path / "out"))

    def test_dump_success(self, monkeypatch, tmp_path):
        """触发 + 拉取两步 adb 命令均执行。"""
        import shutil

        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/adb")
        cmds = []

        def fake_run(cmd, **kwargs):
            cmds.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        out = BlackDex().dump("com.a", str(tmp_path / "out"), device_id="dev1")
        assert out.is_dir()
        assert len(cmds) == 2
        assert cmds[0][0] == "adb" and cmds[1][:2] == ["adb", "-s"]

    def test_dump_trigger_failure(self, monkeypatch, tmp_path):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/adb")
        monkeypatch.setattr(
            subprocess, "run",
            lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, stdout="", stderr="device offline"),
        )
        with pytest.raises(BlackDexNotAvailable, match="device offline"):
            BlackDex().dump("com.a", str(tmp_path / "out"))

    def test_dump_pull_failure_warns_only(self, monkeypatch, tmp_path, caplog):
        """pull 失败只告警不抛异常。"""
        import shutil

        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/adb")
        state = {"n": 0}

        def fake_run(cmd, **kwargs):
            state["n"] += 1
            code = 0 if state["n"] == 1 else 1
            return subprocess.CompletedProcess(cmd, code, stdout="", stderr="pull failed")

        monkeypatch.setattr(subprocess, "run", fake_run)
        out = BlackDex().dump("com.a", str(tmp_path / "out"))
        assert out.is_dir()

    def test_list_dumped_dex(self, tmp_path):
        (tmp_path / "x.dex").write_bytes(b"x")
        assert len(BlackDex.list_dumped_dex(tmp_path)) == 1
        assert BlackDex.list_dumped_dex(tmp_path / "none") == []
