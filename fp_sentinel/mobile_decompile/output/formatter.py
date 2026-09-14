"""输出格式化（text / json / markdown 统一出口）。"""

from __future__ import annotations

import json
from typing import List, Sequence

from ..models.class_info import ClassHierarchy
from ..models.decompile_result import DecompileResult, ManifestInfo
from ..models.search_result import SearchResult

SUPPORTED_FORMATS = ("text", "json", "markdown")


def _ensure_format(fmt: str) -> str:
    fmt = (fmt or "text").lower()
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"不支持的输出格式: {fmt} (可选: {', '.join(SUPPORTED_FORMATS)})")
    return fmt


def format_result(result: DecompileResult, fmt: str = "text") -> str:
    """格式化 DecompileResult。"""
    fmt = _ensure_format(fmt)
    if fmt == "json":
        return json.dumps(result.summary(), ensure_ascii=False, indent=2)
    if fmt == "markdown":
        return _result_markdown(result)
    return _result_text(result)


def _result_text(result: DecompileResult) -> str:
    s = result.summary()
    degraded = bool(s["degrade_warning"])
    status = "完成（大纲模式）" if (result.success and degraded) else (
        "成功" if result.success else "失败")
    lines = [
        f"反编译结果: {status}",
        f"  目标: {s['target_path']}",
        f"  引擎: {s['engine_used']}",
        f"  源码文件: {s['source_file_count']}  类: {s['class_count']}  方法: {s['method_count']}",
        f"  字符串: {s['string_count']}  质量评分: {s['quality_score']}  耗时: {s['duration_sec']}s",
        f"  反编译质量: {s['quality_label']}",
    ]
    if degraded:
        lines.append(
            "  [WARN] jadx 未安装，当前为方法签名大纲，不可用于代码审计")
    if result.manifest_info:
        lines.append(f"  包名: {result.manifest_info.package_name} v{result.manifest_info.version_name}")
    for err in result.errors:
        lines.append(f"  [ERROR] {err}")
    for warn in result.warnings:
        lines.append(f"  [WARN] {warn}")
    return "\n".join(lines)


def _result_markdown(result: DecompileResult) -> str:
    s = result.summary()
    lines = [
        "# 反编译报告",
        "",
        f"- **状态**: {'成功' if result.success else '失败'}",
        f"- **目标**: `{s['target_path']}`",
        f"- **引擎**: {s['engine_used']}",
        f"- **源码文件数**: {s['source_file_count']}",
        f"- **类/方法数**: {s['class_count']} / {s['method_count']}",
        f"- **质量评分**: {s['quality_score']} ({s['quality_label']})",
        f"- **耗时**: {s['duration_sec']}s",
    ]
    if result.errors:
        lines += ["", "## 错误", *[f"- {e}" for e in result.errors]]
    if result.warnings:
        lines += ["", "## 警告", *[f"- {w}" for w in result.warnings]]
    return "\n".join(lines)


def format_search_results(results: Sequence[SearchResult], fmt: str = "text") -> str:
    """格式化搜索结果列表。"""
    fmt = _ensure_format(fmt)
    if fmt == "json":
        return json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=2)
    rows = [
        (
            r.keyword,
            r.match_type.value,
            r.class_name,
            r.method_name,
            str(r.line_number),
            f"{r.relevance_score:.2f}",
            f"{r.critical_score:.2f}",
        )
        for r in results
    ]
    header = ("KEYWORD", "TYPE", "CLASS", "METHOD", "LINE", "RELEV", "CRIT")
    widths = [
        max(len(header[i]), *(len(row[i]) for row in rows)) if rows else len(header[i])
        for i in range(len(header))
    ]
    if fmt == "markdown":
        sep = " | "
        head = sep.join(header)
        line2 = sep.join("---" for _ in header)
        body = [sep.join(row) for row in rows]
        return "\n".join([head, line2] + body)

    def fmt_row(cells) -> str:
        return "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells)).rstrip()

    out = [fmt_row(header), fmt_row(tuple("-" * w for w in widths))]
    out.extend(fmt_row(row) for row in rows)
    return "\n".join(out)


def format_manifest(info: ManifestInfo, fmt: str = "text") -> str:
    """格式化 Manifest 信息。"""
    fmt = _ensure_format(fmt)
    if fmt == "json":
        return json.dumps(info.to_dict(), ensure_ascii=False, indent=2)
    exported = [c for c in info.components if c.exported]
    lines = [
        f"包名: {info.package_name}",
        f"版本: {info.version_name} ({info.version_code})",
        f"SDK: min={info.min_sdk} target={info.target_sdk}",
        f"权限 ({len(info.permissions)}):",
        *[f"  - {p}" for p in info.permissions],
        f"组件 ({len(info.components)}):",
        *[
            f"  - [{c.type}] {c.name}{' (exported)' if c.exported else ''}"
            for c in info.components
        ],
        f"导出组件 ({len(exported)}): {[c.name for c in exported]}",
    ]
    return "\n".join(lines)


def format_class_hierarchy(hierarchy: ClassHierarchy, root: str = "", fmt: str = "text") -> str:
    """格式化类层次结构（markdown/json；text 为树形缩进）。"""
    fmt = _ensure_format(fmt)
    if fmt == "json":
        return json.dumps(hierarchy.to_dict(), ensure_ascii=False, indent=2)

    lines: List[str] = []
    if fmt == "markdown":
        lines.append("# 类层次结构")

    def walk(name: str, depth: int) -> None:
        if depth == 0:
            lines.append(f"{'## ' if fmt == 'markdown' else ''}{name}")
        else:
            lines.append(f"{'  ' * (depth - 1)}- {name}")
        for child in hierarchy.get_children(name):
            walk(child, depth + 1)

    if root and root in hierarchy.nodes:
        walk(root, 0)
    else:
        emitted = set()
        for name in hierarchy.nodes:
            # 只从根（父类不在图中的节点）开始遍历
            parent = hierarchy.nodes[name].parent
            if parent not in hierarchy.nodes and name not in emitted:
                walk(name, 0)
                emitted.add(name)
    return "\n".join(lines) if lines else "(empty hierarchy)"
