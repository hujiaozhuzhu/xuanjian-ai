"""
mobile_shell 测试夹具

- 真实 APK 靶场：C:\\Users\\lenovo\\xuanjian-ai\\test_apps\\ 下的实验 APK
  （InsecureBankv2.apk / vuls_v4.4.apk）；缺失时跳过对应用例。
- 合成 APK/IPA 构建器：用于加固特征与 Mach-O 加密标志的受控测试。
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from typing import Dict, Optional

import pytest

#: 项目根 = fp_sentinel/mobile_shell/tests/conftest.py 上溯 3 级
REPO_ROOT = Path(__file__).resolve().parents[3]
TEST_APPS = REPO_ROOT / "test_apps"

# ─────────────────────── 真实 APK 靶场 ───────────────────────


def find_apk(filename: str) -> Optional[Path]:
    """在 test_apps 目录递归查找指定 APK 文件。"""
    if not TEST_APPS.is_dir():
        return None
    for hit in TEST_APPS.rglob(filename):
        if hit.is_file():
            return hit
    return None


@pytest.fixture(scope="session")
def insecure_bank_apk() -> Path:
    """InsecureBankv2.apk（无加固靶场）。"""
    apk = find_apk("InsecureBankv2.apk")
    if apk is None:
        pytest.skip("测试靶场缺失: InsecureBankv2.apk")
    return apk


@pytest.fixture(scope="session")
def vuls_apk() -> Path:
    """vuls_v4.4.apk（无加固靶场）。"""
    apk = find_apk("vuls_v4.4.apk")
    if apk is None:
        pytest.skip("测试靶场缺失: vuls_v4.4.apk")
    return apk


# ─────────────────────── 合成 APK / IPA 构建器 ───────────────────────

#: 最小合法 DEX 头（magic + checksum 占位）
DEX_HEADER = b"dex\n035\x00" + b"\x00" * 20


def build_apk(path: Path, entries: Dict[str, bytes]) -> Path:
    """构建合成 APK（ZIP 容器）。

    Args:
        path:    输出 .apk 路径
        entries: {条目名: 内容字节}；classes.dex 默认补 DEX 头
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in entries.items():
            data = content
            if name.endswith(".dex"):
                data = DEX_HEADER + content
            zf.writestr(name, data)
    return path


# ─────────────────────── Mach-O 构建器 ───────────────────────


def build_macho(
    cryptid: int,
    is64: bool = True,
    little: bool = True,
) -> bytes:
    """构建带 LC_ENCRYPTION_INFO 的最小 Mach-O。

    Args:
        cryptid: 0=未加密 1=FairPlay 加密
        is64:    64 位（LC_ENCRYPTION_INFO_64）
        little:  字节序
    """
    if is64:
        magic = 0xFEEDFACF  # 规范魔数；字节序由 struct 的 end 决定
    else:
        magic = 0xFEEDFACE
    end = "<" if little else ">"
    lc_cmd = 0x2D if is64 else 0x2C
    cmdsize = 24 if is64 else 20
    header = struct.pack(
        end + "IiiIIII",
        magic, 1, 0, 2, 1, cmdsize, 0,  # cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags
    )
    if is64:
        header += struct.pack(end + "I", 0)  # reserved
    load_cmd = struct.pack(end + "IIIII", lc_cmd, cmdsize, 4096, 4096, cryptid)
    return header + load_cmd + b"\x00" * 16


def build_fat_macho(cryptid: int) -> bytes:
    """构建 FAT (universal) Mach-O，内含一个 64 位 thin slice。"""
    thin = build_macho(cryptid)
    align = (4 - (len(thin) % 4)) % 4
    thin_padded = thin + b"\x00" * (align + 4)  # 留出对齐空间
    header = struct.pack(">II", 0xCAFEBABE, 1)
    arch = struct.pack(">IIIII", 0x01000007, 0x80000003, 28, len(thin), 0)
    return header + arch + thin_padded


def build_ipa(path: Path, macho_blob: bytes, app_name: str = "Demo.app") -> Path:
    """构建合成 IPA（含 Payload/<app>/MacOS/ 主可执行文件）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("Payload/", "")
        zf.writestr(f"Payload/{app_name}/Info.plist", b"<plist/>")
        zf.writestr(f"Payload/{app_name}/MacOS/Demo", macho_blob)
    return path
