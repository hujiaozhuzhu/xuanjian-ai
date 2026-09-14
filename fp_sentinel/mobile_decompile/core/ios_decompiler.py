"""iOS 反编译（class-dump / IDA / Ghidra 集成桩）。

规划文档 2.2.1 节定义：Mach-O/IPA -> class-dump(OC 头文件) / IDA·Ghidra(伪代码)。
当前版本提供：
- class-dump 可用性探测；
- Mach-O 头部轻量解析（魔数/架构/加载命令数）；
- 反编译动作降级实现：工具不可用时返回失败结果与安装指引。

安全约束：只读解析，不修改原始 IPA/Mach-O 文件。
"""

from __future__ import annotations

import os
import shutil
import struct
import zipfile
from typing import Optional

from ..models.class_info import ClassHierarchy
from ..models.decompile_result import DecompileConfig, DecompileResult
from .base import PLATFORM_IOS, Decompiler

MACHO_MAGICS = (0xFEEDFACE, 0xCFFAEDFE, 0xFEEDFACF, 0xCFFAEDF)


def parse_macho_header(path: str) -> dict:
    """解析 Mach-O 头（fat 二进制取第一个架构前的魔数检查会失败，仅支持单架构）。"""
    with open(path, "rb") as fh:
        head = fh.read(32)
    if len(head) < 28:
        raise ValueError(f"文件过小，不是 Mach-O: {path}")
    magic = struct.unpack_from("<I", head, 0)[0]
    if magic not in MACHO_MAGICS:
        raise ValueError(f"不是有效的 Mach-O 文件: {path}")
    little = magic in (0xFEEDFACE, 0xFEEDFACF)
    endian = "<" if little else ">"
    cputype, cpusub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
        endian + "IIIIII", head, 4
    )
    return {
        "bits": 64 if magic in (0xCFFAEDFE, 0xFEEDFACF) else 32,
        "little_endian": little,
        "cputype": cputype,
        "cpusubtype": cpusub,
        "filetype": filetype,
        "ncmds": ncmds,
    }


class IosDecompiler(Decompiler):
    """iOS Mach-O/IPA 反编译器 —— class-dump/IDA 集成桩。"""

    name = "ios-decompiler"
    platform = PLATFORM_IOS

    @staticmethod
    def find_class_dump() -> Optional[str]:
        """探测 class-dump / class-dump-z。"""
        for exe in ("class-dump", "class-dump-z", "class_dump"):
            path = shutil.which(exe)
            if path:
                return path
        return None

    @staticmethod
    def supports(target_path: str) -> bool:
        if not os.path.exists(target_path):
            return False
        if target_path.lower().endswith(".ipa"):
            return True
        try:
            with open(target_path, "rb") as fh:
                head = fh.read(4)
            magic = struct.unpack("<I", head)[0]
            return magic in MACHO_MAGICS
        except (OSError, struct.error):
            return False

    async def decompile(
        self, target: str, config: Optional[DecompileConfig] = None
    ) -> DecompileResult:
        result = self.new_result(target)
        if not os.path.exists(target):
            result.add_error(f"目标文件不存在: {target}")
            return result
        if not self.supports(target):
            result.add_error(f"不是有效的 IPA/Mach-O 文件: {target}")
            return result

        # IPA 容器：校验内含 Payload/*.app/Mach-O，然后走与裸 Mach-O 相同的降级路径
        if target.lower().endswith(".ipa"):
            try:
                result.add_warning(
                    f"IPA 容器校验通过（{self._count_macho_in_ipa(target)} 个可执行文件）"
                )
            except (ValueError, zipfile.BadZipFile) as exc:
                result.add_error(f"IPA 容器校验失败: {exc}")
                return result

        if self.find_class_dump() is None:
            result.add_error(
                "class-dump 不可用。Objective-C 头文件导出需要安装 class-dump"
                "（macOS 环境）。当前降级为仅 Mach-O 头信息解析。"
            )
            try:
                result.cross_references["macho_header"] = [
                    f"{k}={v}" for k, v in parse_macho_header(target).items()
                ]
                result.add_warning("已降级输出 Mach-O 头信息（无 OC 头文件）")
            except ValueError as exc:
                result.add_error(str(exc))
                return result
            result.engine_used = "macho-header"
            result.quality_score = 0.1
            result.success = True
            return result

        raise NotImplementedError(
            "iOS 反编译引擎(class-dump/IDA) 尚未接入，将在后续里程碑交付"
        )

    @staticmethod
    def _count_macho_in_ipa(ipa_path: str) -> int:
        """统计 IPA 内 Payload 下的可执行文件数量（只读校验）。"""
        with zipfile.ZipFile(ipa_path) as zf:
            names = [
                n
                for n in zf.namelist()
                if "/Payload/" in n and n.endswith(".app") is False
                and "." not in os.path.basename(n)
            ]
        if not names:
            raise ValueError(f"IPA 中未找到 Payload 内的可执行文件: {ipa_path}")
        return len(names)

    def search_keyword(
        self,
        keyword: str,
        match_types=None,
        scope: Optional[str] = None,
        limit: int = 200,
    ) -> list:
        """iOS 层暂无反编译产物可搜索；显式返回空结果。"""
        return []

    def get_class_hierarchy(self) -> ClassHierarchy:
        """iOS 层暂无类层次结构。"""
        return ClassHierarchy()
