"""mobile_insight CLI —— fp-sentinel mobile insight <subcommand>。

子命令:
    scan     对 APK/反编译目录/信号 JSON 输出技术提示
    rules    列出全部内置规则
    filter   对既有报告 JSON 按类别/严重度过滤

示例::

    python -m fp_sentinel.mobile_insight.cli scan ./app.apk
    python -m fp_sentinel.mobile_insight.cli scan ./app.apk --category crypto,network --min-severity HIGH
    python -m fp_sentinel.mobile_insight.cli scan ./app.apk --output ./insights.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from fp_sentinel.mobile_common import configure_logging

from .core.context import AnalysisContext
from .core.engine import InsightEngine
from .core.priority import filter_insights
from .models.insight import InsightCategory, Severity

__all__ = ["main", "build_parser"]


def _log_debug(exc: BaseException) -> None:
    """RD-012: 错误细节只进日志，不进 stdout（保持 JSON 纯净）。"""
    import logging
    logging.getLogger("fp_sentinel.mobile_insight").debug(
        "scan failed", exc_info=exc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fp-sentinel mobile insight",
        description="玄鉴 v4.0 能力④: 关键性技术提示引擎",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="扫描并输出技术提示")
    p_scan.add_argument("target", help="APK 路径 / 反编译源码目录 / 信号 JSON")
    p_scan.add_argument("--category", default=None,
                        help="逗号分隔类别: crypto,network,storage,component,anti,privacy")
    p_scan.add_argument("--min-severity", default=None,
                        choices=[s.name for s in Severity], help="最低严重度")
    p_scan.add_argument("--output", default=None, help="结果 JSON 输出路径")
    p_scan.add_argument("--format", default="json", choices=["json", "summary"])
    p_scan.add_argument("--max-insights", type=int, default=0,
                        help="仅展示前 N 条(0=全部)")

    sub.add_parser("rules", help="列出全部内置规则")

    return parser


def build_context(target: str) -> AnalysisContext:
    """按目标类型构建分析上下文。"""
    path = Path(target)
    if path.is_file() and path.suffix.lower() == ".apk":
        return AnalysisContext.from_apk(str(path))
    if path.is_file() and path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        ctx = AnalysisContext()
        ctx.package_name = data.get("package_name", path.stem)
        ctx.platform = data.get("platform", "android")
        for field in ("strings", "classes", "methods", "permissions"):
            getattr(ctx, f"add_{field}")(data.get(field, []))
        ctx.add_exported_components(data.get("exported_components", []))
        ctx.set_manifest_flags(data.get("manifest_flags", {}))
        return ctx
    if path.is_dir():
        return build_context_from_source_dir(path)
    raise FileNotFoundError(f"target not found or unsupported: {target}")


def build_context_from_source_dir(root: Path) -> AnalysisContext:
    """从反编译源码目录(jadx 输出)提取信号。"""
    ctx = AnalysisContext()
    for f in root.rglob("*.java"):
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(f.relative_to(root))
        cls = rel[:-5].replace("/", ".").replace("\\", ".")
        ctx.add_classes([cls])
        for line in text.splitlines():
            stripped = line.strip()
            if stripped:
                ctx.add_strings([stripped[:500]])
    return ctx


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging()

    if args.command == "rules":
        engine = InsightEngine()
        payload = {
            "total": len(engine.rules),
            "rules": [
                {
                    "id": r.id,
                    "title": r.title,
                    "category": r.category.value,
                    "severity": r.severity.name,
                    "cwe": r.cwe_ids,
                    "masvs": r.masvs_refs,
                }
                for r in engine.rules
            ],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if args.command == "scan":
        try:
            ctx = build_context(args.target)
        except FileNotFoundError as exc:
            # RD-012: 友好错误提示（无堆栈）
            print(json.dumps({"success": False, "error":
                f"目标不存在或类型不支持: {args.target}。支持 .apk / .json 信号 / 反编译目录"},
                ensure_ascii=False))
            _log_debug(exc)
            return 2
        except json.JSONDecodeError as exc:
            print(json.dumps({"success": False, "error":
                f"信号 JSON 解析失败（行 {exc.lineno} 列 {exc.colno}）: {exc.msg}。"
                "请检查文件是否为合法 JSON，形如 {\"strings\": [...]}"},
                ensure_ascii=False))
            _log_debug(exc)
            return 2
        except Exception as exc:  # noqa: BLE001 —— RD-012: 任何异常都不裸吐堆栈
            print(json.dumps({"success": False, "error":
                f"扫描失败: {type(exc).__name__}: {exc}。"
                "可设置 FP_SENTINEL_QUIET=0 查看详细日志，或确认 APK 未损坏。"},
                ensure_ascii=False))
            _log_debug(exc)
            return 2

        engine = InsightEngine()
        category = None
        if args.category:
            categories = [InsightCategory.parse(c.strip()) for c in args.category.split(",")]
            # 多类别时先全扫, 再由 priority 过滤交集
            report = engine.run(ctx, target=str(args.target))
            report.insights = [i for i in report.insights if i.category in categories]
        else:
            report = engine.run(ctx, target=str(args.target))

        min_sev = Severity.parse(args.min_severity) if args.min_severity else None
        if min_sev is not None:
            report.insights = filter_insights(report.insights, min_severity=min_sev)
        if args.max_insights > 0:
            report.insights = report.insights[: args.max_insights]

        if args.format == "summary":
            # NEW-06: 按来源分类分组展示
            lines = [f"target: {report.target}",
                     f"insights: {len(report.insights)} (rules {report.rules_matched}/{report.rules_total})"]
            for group_name, items in report.grouped_by_classification().items():
                lines.append(f"  [{group_name}] ({len(items)})")
                for i in items:
                    lines.append(
                        f"    [{i.severity.name:<8}] {i.id} {i.title} "
                        f"(CWE: {','.join(i.cwe_ids) or '-'})")
            text = "\n".join(lines)
            if args.output:
                Path(args.output).write_text(text, encoding="utf-8")
            print(text)
            return 0

        payload = report.to_dict()
        if args.output:
            Path(args.output).write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    parser.error(f"unknown command: {args.command}")  # pragma: no cover
    return 2


if __name__ == "__main__":
    sys.exit(main())


# ---------------------------------------------------------------------------
# typer 集成入口: 供 fp-sentinel/cli/__init__.py 聚合为
#   fp-sentinel mobile insight <subcommand>
# ---------------------------------------------------------------------------
try:
    import typer

    insight_app = typer.Typer(help="关键性技术提示引擎 (v4.0 能力④)", no_args_is_help=True)

    @insight_app.command("scan")
    def insight_scan(
        target: str = typer.Argument(..., help="APK / 信号 JSON / 反编译目录"),
        category: Optional[str] = typer.Option(None, "--category"),
        min_severity: Optional[str] = typer.Option(None, "--min-severity"),
        output: Optional[str] = typer.Option(None, "--output"),
        summary: bool = typer.Option(False, "--summary", help="摘要输出"),
        max_insights: int = typer.Option(0, "--max-insights"),
    ) -> None:
        argv = ["scan", target]
        if category:
            argv += ["--category", category]
        if min_severity:
            argv += ["--min-severity", min_severity]
        if output:
            argv += ["--output", output]
        if summary:
            argv += ["--format", "summary"]
        if max_insights:
            argv += ["--max-insights", str(max_insights)]
        raise typer.Exit(main(argv))

    @insight_app.command("rules")
    def insight_rules() -> None:
        raise typer.Exit(main(["rules"]))
except ImportError:  # pragma: no cover
    insight_app = None  # type: ignore[assignment]
