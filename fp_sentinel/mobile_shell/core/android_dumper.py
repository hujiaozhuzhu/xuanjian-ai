"""
Android 脱壳引擎 —— FRIDA-DEXDump 思路 + androguard 静态降级

对齐《v4.0.0-mobile-reverse-engineering-plan.md》2.1.1：
- Android 加固APK(360/腾讯/梆梆) → FRIDA-DEXDump 全自动
- 降级路径：frida-dexdump 不可用 / 无 root 设备时，
  基于 androguard 做静态检测；无壳 APK 直接提取明文 dex。

执行模式：
- DumpMode.FRIDA : 优先 frida-dexdump 动态脱壳，失败自动降级静态
- DumpMode.STATIC: 纯静态（检测 + 明文 dex 提取）

安全红线：
- S1: 远程设备地址必须经 assert_local 守卫
- subprocess 一律 shell=False，仅调用本地白名单 CLI
"""

from __future__ import annotations

import logging
import shutil
import time
import zipfile
from pathlib import Path
from typing import List, Optional

from fp_sentinel.mobile_shell.core.base import ShellEngine
from fp_sentinel.mobile_shell.core.detection import ProtectionDetector
from fp_sentinel.mobile_shell.models.dump_result import (
    DumpConfig,
    DumpMode,
    DumpResult,
    DumpTarget,
    FileFormat,
)
from fp_sentinel.mobile_shell.models.protection_info import (
    PROTECTION_NONE,
    ProtectionInfo,
)

logger = logging.getLogger(__name__)


class AndroidDumper(ShellEngine):
    """Android 脱壳引擎。

    策略：
    1. 先做加固识别（三路特征融合）
    2. mode=FRIDA 且 frida-dexdump 可用 → 动态脱壳（需已连接 root 设备）
    3. 否则降级静态：无壳 APK 直接从 ZIP 提取明文 dex；加固 APK
       标记为"需动态脱壳"并给出告警，同时输出静态检测报告。
    """

    name = "android-dumper"
    platform = "android"

    def __init__(self, use_androguard: bool = True) -> None:
        """初始化引擎。

        Args:
            use_androguard: 是否启用 androguard 静态分析（未安装自动降级）
        """
        self.detector = ProtectionDetector(use_androguard=use_androguard)

    # ── ShellEngine 接口 ──

    def get_supported_formats(self) -> List[FileFormat]:
        """支持 APK 与裸 DEX。"""
        return [FileFormat.APK, FileFormat.DEX]

    def detect_protection(self, target_path: str) -> ProtectionInfo:
        """识别加固类型（360/腾讯/梆梆/爱加密/娜迦/百度/阿里/无壳）。"""
        return self.detector.detect(target_path)

    def dump(self, target: DumpTarget, config: DumpConfig) -> DumpResult:
        """执行脱壳。

        Args:
            target: 脱壳目标（APK/DEX）
            config: 脱壳配置（mode=FRIDA 时优先动态脱壳）

        Returns:
            DumpResult: 结果；静态降级模式下无壳 APK 仍可提取明文 dex
        """
        self.guard_remote(target)
        self.validate_target(target)
        started = time.time()

        if target.file_format == FileFormat.DEX:
            info = ProtectionInfo(protection=PROTECTION_NONE)
        else:
            info = self.detect_protection(target.path)
        result = DumpResult.from_target(target, info.protection, config.mode)
        if target.file_format == FileFormat.DEX:
            result.log("裸 DEX 跳过加固识别")
        result.log(f"加固识别: {info.summary()}")

        # 动态路径：frida-dexdump（失败自动降级）
        if config.mode == DumpMode.FRIDA:
            result = self._try_frida_dump(target, config, result)

        # 静态路径：androguard 分析 + 明文 dex 提取
        if not result.success:
            result = self._static_dump(target, config, info, result)

        return result.finalize(started)

    # ── 动态脱壳 ──

    def _try_frida_dump(
        self,
        target: DumpTarget,
        config: DumpConfig,
        result: DumpResult,
    ) -> DumpResult:
        """尝试 frida-dexdump 动态脱壳，任何失败都降级为静态。"""
        if target.file_format == FileFormat.DEX:
            result.warn("裸 DEX 无需动态脱壳，直接走静态路径")
            return result
        package = target.package or self._read_package(target.path)
        if not package:
            result.warn("无法确定包名，跳过 frida-dexdump")
            return result

        try:
            from fp_sentinel.mobile_shell.integrations.frida_dexdump import (
                FridaDexDump,
            )

            wrapper = FridaDexDump()
            if not wrapper.available:
                result.warn("frida-dexdump 不可用（未安装 CLI/SDK），降级为静态模式")
                return result
            dumped_dir = wrapper.dump(
                package=package,
                output_dir=config.output_dir,
                device_id=target.device_id,
                remote_host=target.remote_host,
                timeout_sec=config.timeout_sec,
            )
            dex_files = wrapper.list_dumped_dex(dumped_dir)
            result.mode = DumpMode.FRIDA
            result.success = True
            result.dumped_path = str(dumped_dir)
            result.dex_count = len(dex_files)
            result.sha256_after = self._dir_digest(dex_files)
            result.log(f"frida-dexdump 脱壳成功: {len(dex_files)} 个 dex")
        except Exception as exc:  # noqa: BLE001 - 降级路径必须兜底
            result.warn(f"frida-dexdump 失败: {exc}，降级为静态模式")
            logger.warning("frida-dexdump 执行失败: %s", exc)
        return result

    # ── 静态降级 ──

    def _static_dump(
        self,
        target: DumpTarget,
        config: DumpConfig,
        info: ProtectionInfo,
        result: DumpResult,
    ) -> DumpResult:
        """静态模式：androguard 分析 + 明文 dex 提取。"""
        result.mode = DumpMode.STATIC
        if target.file_format == FileFormat.DEX:
            out = self._copy_dex(target.path, config)
            result.success = True
            result.dumped_path = str(out)
            result.dex_count = 1
            result.sha256_after = result.sha256_before
            result.log("裸 DEX 直接复制到输出目录")
            return result

        if info.protection != PROTECTION_NONE:
            result.warn(
                f"检测到加固({info.protection})，静态模式无法解密 dex；"
                f"请在已 root 设备上使用 --mode frida 执行动态脱壳"
            )
            result.log("输出静态检测报告(不产出 dex)")
            return result

        # 无壳：直接提取明文 dex
        out_dir = self._prepare_output(config.output_dir, Path(target.path).stem)
        dex_names = self._list_dex_entries(target.path)
        if not dex_names:
            result.warn("APK 内未找到 dex 条目")
            return result
        extracted: List[Path] = []
        try:
            with zipfile.ZipFile(target.path) as zf:
                for name in dex_names[: config.max_dex_count]:
                    dest = out_dir / Path(name).name
                    dest.write_bytes(zf.read(name))
                    extracted.append(dest)
        except (zipfile.BadZipFile, OSError) as exc:
            result.warn(f"dex 提取失败: {exc}")
            return result
        result.success = True
        result.dumped_path = str(out_dir)
        result.dex_count = len(extracted)
        result.sha256_after = self._dir_digest(extracted)
        result.log(f"静态提取明文 dex 成功: {len(extracted)} 个")
        return result

    # ── 工具方法 ──

    def _read_package(self, apk_path: str) -> Optional[str]:
        """androguard 读取包名（不可用或为空时返回 None）。"""
        try:
            from androguard.core.apk import APK

            return APK(apk_path).get_package() or None
        except Exception as exc:  # noqa: BLE001 - 依赖环境相关
            logger.debug("androguard 读取包名失败: %s", exc)
            return None

    @staticmethod
    def _list_dex_entries(apk_path: str) -> List[str]:
        """列出 APK 内的 dex 条目名（按名称排序，classes 优先）。"""
        with zipfile.ZipFile(apk_path) as zf:
            dexes = [n for n in zf.namelist() if n.endswith(".dex")]
        return sorted(dexes, key=lambda n: (n != "classes.dex", n))

    @staticmethod
    def _prepare_output(output_dir: str, stem: str) -> Path:
        """构建并创建输出目录（白名单根：./reports/ 与用户指定目录）。"""
        out = Path(output_dir) / stem / "dumped"
        out.mkdir(parents=True, exist_ok=True)
        return out

    @staticmethod
    def _copy_dex(dex_path: str, config: DumpConfig) -> Path:
        """复制裸 DEX 到输出目录。"""
        out_dir = AndroidDumper._prepare_output(config.output_dir, Path(dex_path).stem)
        dest = out_dir / Path(dex_path).name
        shutil.copyfile(dex_path, dest)
        return dest

    @staticmethod
    def _dir_digest(files: List[Path]) -> str:
        """对多个产出文件计算聚合 SHA256（按文件名排序后串联）。"""
        import hashlib

        digest = hashlib.sha256()
        for f in sorted(files, key=lambda p: p.name):
            digest.update(f.name.encode("utf-8", "replace"))
            digest.update(f.read_bytes() if f.stat().st_size < 32 * 1024 * 1024 else b"")
        return digest.hexdigest()
