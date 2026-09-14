"""反编译结果数据模型。

玄鉴 v4.0 能力② 反编译引擎。
对应规划文档 2.2.3 节 DecompileResult / DecompileConfig 定义。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class SourceFile:
    """反编译产出的单个源码文件。"""

    path: str                 # 绝对/输出路径
    relative_path: str = ""   # 相对输出目录
    content: str = ""
    language: str = "java"    # java / smali / pseudo-c / objc / outline

    @property
    def size_bytes(self) -> int:
        return len(self.content.encode("utf-8", errors="replace"))

    def to_dict(self) -> Dict[str, object]:
        return {
            "path": self.path,
            "relative_path": self.relative_path,
            "language": self.language,
            "size_bytes": self.size_bytes,
        }


@dataclass
class StringEntry:
    """字符串表条目。"""

    value: str
    source_file: Optional[str] = None
    class_name: Optional[str] = None
    category: str = "plain"

    def to_dict(self) -> Dict[str, object]:
        return {
            "value": self.value,
            "source_file": self.source_file,
            "class_name": self.class_name,
            "category": self.category,
        }


@dataclass
class ComponentInfo:
    """Manifest 组件信息（Activity/Service/Receiver/Provider）。"""

    type: str                  # activity / service / receiver / provider
    name: str
    exported: bool = False
    intent_filters: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "type": self.type,
            "name": self.name,
            "exported": self.exported,
            "intent_filters": self.intent_filters,
        }


@dataclass
class ManifestInfo:
    """AndroidManifest 解析信息。"""

    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    app_name: str = ""
    permissions: List[str] = field(default_factory=list)
    components: List[ComponentInfo] = field(default_factory=list)
    # NEW-05: application 节点属性（None = 未声明; bool = 显式声明值）
    debuggable: bool = False
    allow_backup: Optional[bool] = None
    network_security_config: str = ""
    uses_cleartext_traffic: Optional[bool] = None

    @property
    def exported_components(self) -> List[ComponentInfo]:
        return [c for c in self.components if c.exported]

    @property
    def activities(self) -> List[ComponentInfo]:
        return [c for c in self.components if c.type == "activity"]

    @property
    def application_flags(self) -> Dict[str, object]:
        """application 节点安全相关属性视图（NEW-05）。"""
        return {
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "network_security_config": self.network_security_config,
            "uses_cleartext_traffic": self.uses_cleartext_traffic,
        }

    def to_dict(self) -> Dict[str, object]:
        return {
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "app_name": self.app_name,
            "permissions": list(self.permissions),
            "components": [c.to_dict() for c in self.components],
            "exported_components": [c.name for c in self.exported_components],
            "application_flags": self.application_flags,
        }


@dataclass
class CallGraph:
    """方法间调用图。节点/边均为完整方法签名。"""

    edges: Dict[str, List[str]] = field(default_factory=dict)

    def add_edge(self, caller: str, callee: str) -> None:
        if caller == callee:
            return
        targets = self.edges.setdefault(caller, [])
        if callee not in targets:
            targets.append(callee)

    def callees(self, caller: str) -> List[str]:
        return list(self.edges.get(caller, []))

    def callers(self, callee: str) -> List[str]:
        return [c for c, ts in self.edges.items() if callee in ts]

    @property
    def node_count(self) -> int:
        nodes = set(self.edges)
        for ts in self.edges.values():
            nodes.update(ts)
        return len(nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(ts) for ts in self.edges.values())

    def to_dict(self) -> Dict[str, List[str]]:
        return {k: list(v) for k, v in self.edges.items()}

    def to_dot(self) -> str:
        """导出 Graphviz DOT 格式。"""
        lines = ["digraph callgraph {", "  rankdir=LR;"]
        for caller, targets in sorted(self.edges.items()):
            src = caller.replace('"', "'")
            for t in targets:
                lines.append(f'  "{src}" -> "{t.replace(chr(34), chr(39))}";')
        lines.append("}")
        return "\n".join(lines)


@dataclass
class DecompileConfig:
    """反编译配置。"""

    output_dir: Optional[str] = None       # None 时不落盘，仅内存分析
    engine: str = "auto"                   # auto / jadx / androguard
    format: str = "java"                   # java / smali / outline
    include_strings: bool = True
    include_manifest: bool = True
    include_call_graph: bool = False       # 生成调用图较慢，默认关闭
    max_strings: int = 20000
    max_source_files: int = 5000
    timeout_sec: int = 300                 # 外部工具（jadx）超时


@dataclass
class DecompileResult:
    """反编译结果。"""

    success: bool
    target_path: str = ""
    engine_used: str = ""                  # jadx / androguard / ghidra / ida / class-dump
    source_files: List[SourceFile] = field(default_factory=list)
    class_count: int = 0
    method_count: int = 0
    string_table: List[StringEntry] = field(default_factory=list)
    manifest_info: Optional[ManifestInfo] = None
    call_graph: Optional[CallGraph] = None
    cross_references: Dict[str, List[str]] = field(default_factory=dict)
    quality_score: float = 0.0             # 反编译质量评分 0-1
    duration_sec: float = 0.0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def summary(self) -> Dict[str, object]:
        if self.engine_used == "jadx":
            quality_label = "full-source"
        elif self.source_files and any(
            sf.language == "outline" for sf in self.source_files
        ):
            quality_label = "outline-only (jadx unavailable)"
        else:
            quality_label = "unknown"
        return {
            "success": self.success,
            "target_path": self.target_path,
            "engine_used": self.engine_used,
            "source_file_count": len(self.source_files),
            "class_count": self.class_count,
            "method_count": self.method_count,
            "string_count": len(self.string_table),
            "has_manifest": self.manifest_info is not None,
            "call_graph_edges": self.call_graph.edge_count if self.call_graph else 0,
            "quality_score": self.quality_score,
            "quality_label": quality_label,
            "degrade_warning": quality_label.startswith("outline-only"),
            "duration_sec": round(self.duration_sec, 2),
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
        }
