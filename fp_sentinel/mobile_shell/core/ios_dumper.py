"""
iOS 脱壳引擎 —— frida-ios-dump 思路 + 检测模式降级

对齐《v4.0.0-mobile-reverse-engineering-plan.md》2.1.1：
- App Store 加密 IPA → frida-ios-dump（需越狱设备）
- 设备不可用时降级为"检测模式"：解析 Mach-O LC_ENCRYPTION_INFO，
  报告 FairPlay 加密状态（cryptid）。

frida-ios-dump 核心逻辑（内存解密转储）：
1. 通过 frida 连接越狱设备（USB 或仅限 localhost 的远程端口）
2. attach 目标进程，读取主可执行文件的加载命令
3. 定位 cryptid 对应的 __TEXT 段，从内存中转储已解密的 Mach-O
4. 重打包为 decrypted.ipa

安全红线：
- S1: 远程设备地址必须经 assert_local 守卫（仅 127.0.0.1/localhost）
"""

from __future__ import annotations

import logging
import struct
import time
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple

from fp_sentinel.mobile_shell.core.base import ShellEngine, assert_local
from fp_sentinel.mobile_shell.models.dump_result import (
    DumpConfig,
    DumpMode,
    DumpResult,
    DumpTarget,
    FileFormat,
)
from fp_sentinel.mobile_shell.models.protection_info import (
    PROTECTION_UNKNOWN,
    ProtectionInfo,
)

logger = logging.getLogger(__name__)

#: Mach-O 魔数
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
MH_MAGIC_32 = 0xFEEDFACE
MH_CIGAM_32 = 0xCEFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

#: LC_ENCRYPTION_INFO (32/64位)
LC_ENCRYPTION_INFO = 0x2C
LC_ENCRYPTION_INFO_64 = 0x2D

PROTECTION_FAIRPLAY = "FairPlay加密"
PROTECTION_UNENCRYPTED = "未加密"


def parse_macho_cryptid(blob: bytes) -> Optional[int]:
    """解析 Mach-O 的 LC_ENCRYPTION_INFO.cryptid。

    支持 32/64 位与 FAT (universal) 二进制；取第一个架构的 cryptid。

    Args:
        blob: Mach-O 文件字节流

    Returns:
        cryptid（0=未加密 1=FairPlay 加密）；无法解析返回 None
    """
    if len(blob) < 32:
        return None
    magic = struct.unpack_from("<I", blob, 0)[0]

    # FAT：遍历架构表，取第一个 thin slice
    if magic in (FAT_MAGIC, FAT_CIGAM):
        nfat = struct.unpack_from(">I", blob, 4)[0]
        for i in range(min(nfat, 16)):
            # fat_arch: cputype(4) cpusubtype(4) offset(4) → offset 位于 8+i*20+8
            offset = struct.unpack_from(">I", blob, 8 + i * 20 + 8)[0]
            if offset + 32 <= len(blob):
                sub = parse_macho_cryptid(blob[offset:])
                if sub is not None:
                    return sub
        return None

    if magic == MH_MAGIC_64:
        little, is64 = True, True
    elif magic == MH_CIGAM_64:
        little, is64 = False, True
    elif magic == MH_MAGIC_32:
        little, is64 = True, False
    elif magic == MH_CIGAM_32:
        little, is64 = False, False
    else:
        return None

    end = "<" if little else ">"
    ncmds, sizeofcmds = struct.unpack_from(end + "II", blob, 16)
    off = 32 if is64 else 28
    lc_magic_size = 8
    limit = min(ncmds, 128)
    for _ in range(limit):
        if off + lc_magic_size > len(blob):
            break
        cmd, cmdsize = struct.unpack_from(end + "II", blob, off)
        target = LC_ENCRYPTION_INFO_64 if is64 else LC_ENCRYPTION_INFO
        if cmd == target:
            cryptoff, cryptsize, cryptid = struct.unpack_from(end + "III", blob, off + 8)
            return cryptid
        if cmdsize <= 0:
            break
        off += cmdsize
    return None


class IOSDumper(ShellEngine):
    """iOS 脱壳引擎（frida-ios-dump 集成 + 检测降级）。"""

    name = "ios-dumper"
    platform = "ios"

    def __init__(self) -> None:
        """初始化引擎；frida 模块按需延迟导入。"""

    # ── ShellEngine 接口 ──

    def get_supported_formats(self) -> List[FileFormat]:
        """支持 IPA 与 Mach-O。"""
        return [FileFormat.IPA, FileFormat.MACHO]

    def detect_protection(self, target_path: str) -> ProtectionInfo:
        """检测 iOS 二进制加密状态（FairPlay / 未加密 / 未知）。"""
        path = Path(target_path)
        if not path.is_file():
            raise FileNotFoundError(f"目标文件不存在: {target_path}")
        info = ProtectionInfo(protection=PROTECTION_UNKNOWN, details={"file": path.name})
        cryptid = self._probe_cryptid(path)
        info.details["cryptid"] = cryptid
        if cryptid == 1:
            info.protection = PROTECTION_FAIRPLAY
            info.confidence = 0.9
            info.is_packed = True
        elif cryptid == 0:
            info.protection = PROTECTION_UNENCRYPTED
            info.confidence = 0.9
            info.is_packed = False
        else:
            info.confidence = 0.2
            info.details["reason"] = "未找到 LC_ENCRYPTION_INFO 或非 Mach-O"
        logger.info("iOS 加密检测 → %s", info.summary())
        return info

    def dump(self, target: DumpTarget, config: DumpConfig) -> DumpResult:
        """执行 iOS 脱壳。

        优先 frida-ios-dump 动态脱壳（需越狱设备 + frida）；
        设备不可用时降级为检测模式（仅报告加密状态）。
        """
        self.guard_remote(target)
        self.validate_target(target)
        started = time.time()

        if target.is_device_only:
            # 仅设备目标：无本地文件可检测，直接走 frida 路径
            info = ProtectionInfo(protection=PROTECTION_FAIRPLAY, confidence=0.5)
            info.details["cryptid"] = None
            info.details["mode"] = "device-only"
        else:
            info = self.detect_protection(target.path)
        result = DumpResult.from_target(target, info.protection, DumpMode.FRIDA)
        result.log(f"加密检测: {info.summary()}")

        if not target.is_device_only and info.protection == PROTECTION_UNENCRYPTED:
            result.mode = DumpMode.STATIC
            result.success = True
            result.log("二进制未加密，无需脱壳；直接复制到输出目录")
            self._export_unencrypted(target, config, result)
            return result.finalize(started)

        # 需要越狱设备
        if config.mode == DumpMode.FRIDA and target.package:
            dumped = self._try_frida_dump(target, config, result)
            if dumped:
                return result.finalize(started)

        # 降级：检测模式
        result.mode = DumpMode.DETECT
        result.warn(
            "越狱设备/frida 不可用，降级为检测模式（不产出解密二进制）"
        )
        result.log(f"检测结论: {info.protection} cryptid={info.details.get('cryptid')}")
        return result.finalize(started)

    # ── frida-ios-dump 动态路径 ──

    def _try_frida_dump(
        self, target: DumpTarget, config: DumpConfig, result: DumpResult
    ) -> bool:
        """连接越狱设备执行内存解密转储。成功返回 True 并回填 result。"""
        remote = target.remote_host
        if remote:
            # S1 守卫：仅允许 localhost 远程 frida 端口
            assert_local(remote)
        try:
            import frida  # noqa: PLC0415 - 延迟导入，未安装时走降级
        except ImportError:
            result.warn("frida SDK 未安装，无法连接越狱设备")
            return False

        try:
            device = self._find_device(frida, target)
            if device is None:
                result.warn("未发现可用设备（USB 或本地 frida-server）")
                return False
            session = device.attach(target.package)  # type: ignore[arg-type]
            # frida-ios-dump 核心逻辑：读取主模块解密内存并转储
            script = session.create_script(self._DUMP_JS)
            script.load()
            payload = script.exports_sync.dump_main_executable()  # type: ignore[attr-defined]
            if not payload:
                result.warn("内存转储为空")
                return False
            out_dir = self._prepare_output(config.output_dir)
            out_file = out_dir / "decrypted.bin"
            import base64

            out_file.write_bytes(base64.b64decode(payload))
            session.detach()
            result.mode = DumpMode.FRIDA
            result.success = True
            result.dumped_path = str(out_file)
            result.dex_count = 0
            result.sha256_after = self._file_digest(out_file)
            result.log(f"frida-ios-dump 脱壳成功: {out_file}")
            return True
        except Exception as exc:  # noqa: BLE001 - 降级路径必须兜底
            result.warn(f"frida 脱壳失败: {exc}")
            logger.warning("frida-ios-dump 执行失败: %s", exc)
            return False

    @staticmethod
    def _find_device(frida_module: object, target: DumpTarget) -> object:
        """定位 frida 设备：remote_host(仅 localhost) → USB → local。"""
        mgr = frida_module.get_device_manager()  # type: ignore[attr-defined]
        if target.remote_host:
            return mgr.add_remote_device(target.remote_host)
        try:
            return frida_module.get_usb_device(timeout=2)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return None

    #: frida-ios-dump 思路的内存解密脚本（简化版）
    _DUMP_JS = """
rpc.exports = {
  dumpMainExecutable: function () {
    var modules = Process.enumerateModules();
    if (modules.length === 0) return null;
    var main = modules[0];
    var base = main.base;
    var size = main.size;
    var bytes = Memory.readByteArray(ptr(base), size);
    // 将 ArrayBuffer 转 base64 由 Python 端落盘
    var u8 = new Uint8Array(bytes);
    var chunk = 0x8000;
    var parts = [];
    for (var i = 0; i < u8.length; i += chunk) {
      parts.push(String.fromCharCode.apply(null, u8.subarray(i, i + chunk)));
    }
    return btoa(parts.join(''));
  }
};
"""

    # ── 检测/导出工具 ──

    def _probe_cryptid(self, path: Path) -> Optional[int]:
        """从 IPA(zip) 或裸 Mach-O 中探测 cryptid。"""
        if path.suffix.lower() == ".ipa":
            blob = self._read_main_binary_from_ipa(path)
        else:
            blob = path.read_bytes()
        if not blob:
            return None
        return parse_macho_cryptid(blob)

    @staticmethod
    def _read_main_binary_from_ipa(ipa: Path) -> Optional[bytes]:
        """从 IPA 中提取 Payload/*.app/ 主可执行文件字节。"""
        try:
            with zipfile.ZipFile(ipa) as zf:
                candidates = [
                    n
                    for n in zf.namelist()
                    if n.startswith("Payload/") and "/MacOS/" in n
                ]
                if not candidates:
                    return None
                # 取最短路径（主可执行文件通常最深但唯一）
                return zf.read(min(candidates, key=len))
        except (zipfile.BadZipFile, OSError) as exc:
            logger.debug("IPA 读取失败: %s", exc)
            return None

    def _export_unencrypted(
        self, target: DumpTarget, config: DumpConfig, result: DumpResult
    ) -> None:
        """未加密二进制：复制到输出目录并计算哈希。"""
        import shutil

        out_dir = self._prepare_output(config.output_dir)
        dest = out_dir / Path(target.path).name
        shutil.copyfile(target.path, dest)
        result.dumped_path = str(dest)
        result.sha256_after = self._file_digest(dest)

    @staticmethod
    def _prepare_output(output_dir: str) -> Path:
        """构建并创建输出目录。"""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        return out

    @staticmethod
    def _file_digest(path: Path) -> str:
        """计算单文件 SHA256。"""
        import hashlib

        return hashlib.sha256(path.read_bytes()).hexdigest()

    def get_device_banner(self) -> str:
        """返回引擎信息（CLI help 用）。"""
        return f"{self.name}: iOS 脱壳 (frida-ios-dump 思路, 检测模式降级)"
