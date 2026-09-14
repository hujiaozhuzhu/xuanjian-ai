"""fp-sentinel mobile decompile 命令行入口（typer）。

命令结构::

    fp-sentinel mobile decompile run <target>       # 完整反编译
    fp-sentinel mobile decompile search <target> <keyword>
    fp-sentinel mobile decompile strings <target>
    fp-sentinel mobile decompile manifest <target>
    fp-sentinel mobile decompile hierarchy <target>

所有子命令只读分析目标 APK/DEX，不修改原始文件。
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import List, Optional

import typer

from fp_sentinel.mobile_common import configure_logging

from .core.android_java import AndroidJavaDecompiler
from .models.decompile_result import DecompileConfig
from .models.search_result import MatchType
from .output.formatter import (
    format_class_hierarchy,
    format_manifest,
    format_result,
    format_search_results,
)
from .output.string_extractor import StringExtractor

decompile_app = typer.Typer(
    name="decompile",
    help="能力② 反编译引擎：APK/DEX -> 源码 + 搜索 + 字符串提取",
    add_completion=False,
    no_args_is_help=True,
)

mobile_app = typer.Typer(
    name="mobile",
    help="玄鉴 v4.0 移动端安全分析引擎",
    add_completion=False,
    no_args_is_help=True,
)
mobile_app.add_typer(decompile_app, name="decompile")

_MATCH_TYPES = {t.value.lower(): t for t in MatchType}


def _try_build_attribution(target_path: str):
    """NEW-04: 尝试构建归因索引; 失败/非 APK 返回 None（不阻断主流程）。"""
    if not target_path.lower().endswith(".apk"):
        return None
    try:
        from .parsers.attribution import get_attribution_index

        index = get_attribution_index(target_path)
        return index if index.method_count > 0 else None
    except Exception:
        return None


def _detect_package_name(apk_path: str) -> str:
    """从 Manifest 提取真实包名（失败返回空串）。"""
    try:
        from .parsers.manifest_parser import ManifestParser

        return ManifestParser(apk_path).parse().package_name or ""
    except Exception:
        return ""


def _parse_match_types(values: Optional[str]) -> Optional[List[MatchType]]:
    if not values:
        return None
    out: List[MatchType] = []
    for raw in values.split(","):
        key = raw.strip().lower()
        if key not in _MATCH_TYPES:
            raise typer.BadParameter(
                f"未知匹配类型: {raw} (可选: {', '.join(_MATCH_TYPES)})",
                param_hint="--type",
            )
        out.append(_MATCH_TYPES[key])
    return out


def _check_target(target: str) -> Path:
    path = Path(target)
    if not path.exists():
        typer.secho(f"目标文件不存在: {target}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    return path


@decompile_app.command("run")
def run(
    target: str = typer.Argument(..., help="APK/DEX 文件路径"),
    engine: str = typer.Option("auto", "--engine", help="引擎: auto / jadx / androguard"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="源码输出目录"),
    fmt: str = typer.Option("text", "--format", help="输出格式: text / json / markdown"),
    call_graph: bool = typer.Option(False, "--call-graph", help="同时构建调用图"),
) -> None:
    """执行完整反编译。"""
    configure_logging()
    path = _check_target(target)
    config = DecompileConfig(
        output_dir=output,
        engine=engine,
        include_call_graph=call_graph,
    )
    decompiler = AndroidJavaDecompiler(config=config)
    result = asyncio.run(decompiler.decompile(str(path), config))
    typer.echo(format_result(result, fmt))


@decompile_app.command("search")
def search(
    target: str = typer.Argument(..., help="APK/DEX 文件路径"),
    keyword: str = typer.Argument(..., help="搜索关键字"),
    match_type: Optional[str] = typer.Option(
        None, "--type", "-t", help="匹配类型: text,string,call,xref (默认全部)"
    ),
    scope: Optional[str] = typer.Option(None, "--scope", help="类名前缀过滤"),
    limit: int = typer.Option(50, "--limit", min=1, help="结果数量上限"),
    fmt: str = typer.Option("text", "--format", help="输出格式: text / json / markdown"),
) -> None:
    """关键字搜索（TEXT/STRING/CALL/XREF 四种匹配）。"""
    configure_logging()
    path = _check_target(target)
    decompiler = AndroidJavaDecompiler(target_path=str(path))
    results = decompiler.search_keyword(
        keyword,
        match_types=_parse_match_types(match_type),
        scope=scope,
        limit=limit,
    )
    typer.echo(format_search_results(results, fmt))


@decompile_app.command("strings")
def strings(
    target: str = typer.Argument(..., help="APK/DEX 文件路径"),
    pattern: Optional[str] = typer.Option(None, "--pattern", help="过滤关键字"),
    sensitive: bool = typer.Option(False, "--sensitive", help="仅输出凭证/密钥类高敏结果"),
    limit: int = typer.Option(100, "--limit", min=1, help="结果数量上限"),
    fmt: str = typer.Option("text", "--format", help="输出格式: text / json"),
) -> None:
    """字符串提取：URL/Token/密钥/API endpoint/包名/手机号/邮箱。"""
    configure_logging()
    path = _check_target(target)
    decompiler = AndroidJavaDecompiler(target_path=str(path))
    table = decompiler.string_table(limit=1000000)
    extractor = StringExtractor(source=str(path))
    candidates = [entry.value for entry in table]
    extracted = extractor.extract(candidates)
    if pattern:
        # RD-002: --pattern 对提取后的 value 做大小写不敏感正则匹配
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error:
            rx = re.compile(re.escape(pattern), re.IGNORECASE)
        extracted = [e for e in extracted if rx.search(e.value)]
    if sensitive:
        extracted = StringExtractor.sensitive_only(extracted)
        # NEW-04: 敏感字符串回填代码归因位置（仅 APK 目标可构建归因索引）
        index = _try_build_attribution(str(path))
        if index is not None:
            pkg = _detect_package_name(str(path))
            for e in extracted:
                hit = index.locate(e.value, pkg)
                if hit:
                    e.location = f"{hit[0]}#{hit[1]}"
    extracted = extracted[:limit]
    if fmt == "json":
        typer.echo(json.dumps([e.to_dict() for e in extracted], ensure_ascii=False, indent=2))
        return
    if not extracted:
        typer.echo("(no matches)")
        return
    for e in extracted:
        tag = "" if e.evidence_level == "confirmed" else " [candidate]"
        loc = f" @ {e.location}" if e.location else ""
        typer.echo(f"[{e.category.value:<12}] ({e.confidence:.2f}){tag} {e.value[:120]}{loc}")


@decompile_app.command("manifest")
def manifest(
    target: str = typer.Argument(..., help="APK 文件路径"),
    fmt: str = typer.Option("text", "--format", help="输出格式: text / json"),
) -> None:
    """Manifest 解析：包名/版本/权限/组件/导出组件/Intent Filter。"""
    configure_logging()
    from .parsers.manifest_parser import ManifestParser

    path = _check_target(target)
    try:
        info = ManifestParser(str(path)).parse()
    except (ValueError, FileNotFoundError) as exc:
        typer.secho(f"Manifest 解析失败: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    typer.echo(format_manifest(info, fmt))


@decompile_app.command("hierarchy")
def hierarchy(
    target: str = typer.Argument(..., help="APK/DEX 文件路径"),
    root: Optional[str] = typer.Option(None, "--root", help="从指定类开始展示子树"),
    fmt: str = typer.Option("text", "--format", help="输出格式: text / json / markdown"),
) -> None:
    """获取类层次结构（继承树）。"""
    configure_logging()
    path = _check_target(target)
    decompiler = AndroidJavaDecompiler(target_path=str(path))
    tree = decompiler.get_class_hierarchy()
    typer.echo(format_class_hierarchy(tree, root or "", fmt))


if __name__ == "__main__":  # pragma: no cover
    decompile_app()
