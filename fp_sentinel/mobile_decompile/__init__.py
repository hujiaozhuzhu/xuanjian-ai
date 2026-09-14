"""玄鉴 v4.0 能力② —— mobile_decompile 反编译引擎。

将脱壳后的 DEX/APK/Mach-O/SO 反编译为可读源码，并提供关键字搜索、
交叉引用、字符串提取等逆向基础能力。全程只读，不修改原始文件。
"""

from .models.class_info import ClassHierarchy, ClassInfo, FieldInfo, MethodInfo
from .models.decompile_result import (
    CallGraph,
    ComponentInfo,
    DecompileConfig,
    DecompileResult,
    ManifestInfo,
    SourceFile,
    StringEntry,
)
from .models.search_result import MatchType, SearchResult, compute_critical_score

__version__ = "4.0.0"

__all__ = [
    "ClassHierarchy",
    "ClassInfo",
    "FieldInfo",
    "MethodInfo",
    "CallGraph",
    "ComponentInfo",
    "DecompileConfig",
    "DecompileResult",
    "ManifestInfo",
    "SourceFile",
    "StringEntry",
    "MatchType",
    "SearchResult",
    "compute_critical_score",
    "__version__",
]
