"""Android Native 层反编译（Ghidra / IDA 集成桩）。

规划文档 2.2.1 节定义：SO/ELF -> Ghidra(C 伪代码) / IDA(汇编+伪代码)。
当前版本提供：
- Ghidra/IDA 可用性探测；
- ELF 头部轻量解析（位数/入口点/机器类型）；
- 反编译动作的降级实现：工具不可用时返回失败结果并给出安装指引，
  工具可用时预留 headless 调用接口（后续里程碑接入 pyghidra/analyzeHeadless）。

安全约束：只读解析，不修改原始 SO 文件。
"""

from __future__ import annotations

import os
import shutil
import struct
from typing import Optional

from ..models.class_info import ClassHierarchy
from ..models.decompile_result import DecompileConfig, DecompileResult
from .base import PLATFORM_ANDROID, Decompiler

_ELF_MAGIC = b"\x7fELF"


def parse_elf_header(path: str) -> dict:
    """解析 ELF 头（64/32 位通用字段）。仅读取文件头部，不做任何修改。"""
    with open(path, "rb") as fh:
        head = fh.read(64)
    if len(head) < 20 or head[:4] != _ELF_MAGIC:
        raise ValueError(f"不是有效的 ELF 文件: {path}")
    ei_class, ei_data = head[4], head[5]
    if ei_class == 2:  # ELF64
        _type, machine, _version, entry = struct.unpack_from("<HHIQ", head, 16)
    else:  # ELF32
        (_type, machine, _version, entry) = struct.unpack_from("<HHII", head, 16)
    return {
        "bits": 64 if ei_class == 2 else 32,
        "little_endian": ei_data == 1,
        "machine": machine,
        "entry_point": entry,
    }


class AndroidNativeDecompiler(Decompiler):
    """Android Native(SO/ELF) 反编译器 —— Ghidra/IDA 集成桩。"""

    name = "android-native"
    platform = PLATFORM_ANDROID

    @staticmethod
    def find_ghidra() -> Optional[str]:
        """探测 Ghidra headless（analyzeHeadless）或 GHIDRA_HOME 环境变量。"""
        path = shutil.which("analyzeHeadless")
        if path:
            return path
        home = os.environ.get("GHIDRA_HOME")
        if home:
            for sub in (
                os.path.join(home, "support", "analyzeHeadless.bat"),
                os.path.join(home, "support", "analyzeHeadless"),
            ):
                if os.path.exists(sub):
                    return sub
        return None

    @staticmethod
    def find_ida() -> Optional[str]:
        """探测 IDA Pro 命令行（ida / ida64）。"""
        for exe in ("ida64", "ida", "ida64.exe", "ida.exe"):
            path = shutil.which(exe)
            if path:
                return path
        return None

    @staticmethod
    def supports(target_path: str) -> bool:
        if not os.path.exists(target_path):
            return False
        if target_path.lower().endswith((".so", ".elf")):
            return True
        try:
            with open(target_path, "rb") as fh:
                return fh.read(4) == _ELF_MAGIC
        except OSError:
            return False

    async def decompile(
        self, target: str, config: Optional[DecompileConfig] = None
    ) -> DecompileResult:
        result = self.new_result(target)
        if not os.path.exists(target):
            result.add_error(f"目标文件不存在: {target}")
            return result
        if not self.supports(target):
            result.add_error(f"不是有效的 ELF/SO 文件: {target}")
            return result

        ghidra = self.find_ghidra()
        ida = self.find_ida()
        if ghidra is None and ida is None:
            result.add_error(
                "Ghidra/IDA 均不可用。Native 反编译需要安装 Ghidra"
                "（设置 GHIDRA_HOME 或将 analyzeHeadless 加入 PATH）。"
                "当前降级为仅 ELF 头信息解析。"
            )
            try:
                result.cross_references["elf_header"] = [
                    f"{k}={v}" for k, v in parse_elf_header(target).items()
                ]
                result.add_warning("已降级输出 ELF 头信息（无伪代码）")
            except ValueError as exc:
                result.add_error(str(exc))
                return result
            result.engine_used = "elf-header"
            result.quality_score = 0.1
            result.success = True
            return result

        # Ghidra/IDA headless 集成为后续里程碑工作：此处明确拒绝而非静默输出空结果
        raise NotImplementedError(
            f"Native 反编译引擎({self.name}) 尚未接入 headless 工具链"
            f" (ghidra={ghidra}, ida={ida})"
        )

    def search_keyword(
        self,
        keyword: str,
        match_types=None,
        scope: Optional[str] = None,
        limit: int = 200,
    ) -> list:
        """Native 层暂无反编译产物可搜索；显式返回空结果。"""
        return []

    def get_class_hierarchy(self) -> ClassHierarchy:
        """Native 层无类层次概念。"""
        return ClassHierarchy()
