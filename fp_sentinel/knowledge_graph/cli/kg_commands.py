"""
fp-sentinel kg 子命令 —— 知识图谱查询与自动归档检索 CLI

命令：
    fp-sentinel kg archive --project ... --path ... --findings-file ... [--version ...]
    fp-sentinel kg search  --project ... [--version ...] [--category ...] [--cwe ...]
                           [--language ...] [--severity ...] [--since ...] [--until ...]
    fp-sentinel kg stats
    fp-sentinel kg purge   [--days 90]

可与 `scan --kg` 配合：scan 完成后由归档钩子把数据写入 KG；检索/统计再用本命令。
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

import typer

from ..features.auto_archive import AutoArchiver
from ..features.query_plugin import KnowledgeQueryPlugin, fallback
from ..models import ArchiveQuery
from ..store import default_kg_db_path, open_store
from .terminal import create_console


kg_app = typer.Typer(
    name="kg",
    help="知识图谱查询与自动归档 (Knowledge Graph) — 按项目 / 版本 / 类型 / 时间检索历史记录",
    add_completion=False,
)
console = create_console()
logger = logging.getLogger(__name__)


def _load_findings(path: str) -> list:
    p = Path(path)
    if not p.is_file():
        raise typer.BadParameter(f"findings 文件不存在: {path}")
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise typer.BadParameter("findings 文件应是 JSON 数组")
    return data


@kg_app.command("archive")
def archive_cmd(
    project_name: str = typer.Option(..., "--project", "-p", help="项目名称"),
    project_path: str = typer.Option(..., "--path", help="项目路径"),
    findings_file: str = typer.Option(None, "--findings-file", help="findings JSON（已扫描后保存）"),
    findings: Optional[str] = typer.Option(None, "--findings", help="JSON 字符串或 @file 路径"),
    report_file: Optional[str] = typer.Option(None, "--report-file", help="Markdown 报告路径"),
    report_md: str = typer.Option("", "--report", help="Markdown 报告字符串"),
    version: str = typer.Option("unversioned", "--version"),
    language: Optional[str] = typer.Option(None, "--lang"),
    scanner: str = typer.Option("", "--scanner"),
    report_kind: str = typer.Option("compliance", "--report-kind"),
    duration_seconds: float = typer.Option(0.0, "--duration"),
    db_path: Optional[str] = typer.Option(None, "--db"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """手动触发归档：把一次扫描结果写入 KG。"""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)

    finds = []
    if findings:
        if findings.startswith("@"):
            finds = _load_findings(findings[1:])
        else:
            try:
                finds = json.loads(findings)
            except json.JSONDecodeError:
                raise typer.BadParameter("findings 不是合法 JSON")
    if findings_file:
        finds = _load_findings(findings_file)

    report = report_md
    if report_file:
        report = Path(report_file).read_text(encoding="utf-8")

    async def _run():
        async with AutoArchiver(db_path=db_path) as a:
            return await a.archive_scan(
                project_name=project_name,
                project_path=project_path,
                findings=finds,
                report_md=report,
                version=version,
                language=language,
                scanner=scanner,
                report_kind=report_kind,
                duration_seconds=duration_seconds,
            )

    result = asyncio.run(_run())
    console.print_json(json.dumps(result, ensure_ascii=False, indent=2))


@kg_app.command("match")
def match_cmd(
    rule_id: str = typer.Option(..., "--rule", help="规则 ID"),
    category: Optional[str] = typer.Option(None, "--category"),
    cwe: Optional[str] = typer.Option(None, "--cwe"),
    severity: Optional[str] = typer.Option(None, "--severity"),
    language: Optional[str] = typer.Option(None, "--lang"),
    project_path: Optional[str] = typer.Option(None, "--path"),
    db_path: Optional[str] = typer.Option(None, "--db"),
    top_k: int = typer.Option(5, "--top-k"),
):
    """单条规则匹配：查找历史同类漏洞/修复/CVE。"""

    async def _run():
        store = open_store(db_path or default_kg_db_path())
        await store.connect()
        await store.initialize()
        plugin = KnowledgeQueryPlugin(
            archive_fn=lambda category, cwe, language, limit: _candidate_adapter(store, category, cwe, language, limit),
        )
        try:
            matches = await plugin.match(
                rule_id=rule_id,
                category=category,
                cwe=cwe,
                severity=severity,
                language=language,
            )
        finally:
            await store.close()
        return [m.model_dump() for m in matches]

    async def _candidate_adapter(store, category, cwe, language, limit):  # type: ignore[no-untyped-def]
        q = ArchiveQuery(category=category, cwe=cwe, language=language, limit=limit, offset=0)
        recs = await store.search_records(q)
        return [
            {
                "id": r.id, "rule_id": r.rule_id, "severity": r.severity,
                "file_path": r.file_path, "line_start": r.line_start,
                "fix_title": r.fix_title, "fix_diff": r.fix_diff,
                "reference_cve": r.reference_cve, "incident_note": r.incident_note,
                "archived_at": r.archived_at, "category": r.category,
                "language": r.language,
            }
            for r in recs
        ]

    matches = asyncio.run(_run())
    if not matches:
        console.print("[dim]无匹配历史记录；内置 fallback 将自动使用。[/dim]")
        fb = fallback(category or "")
        if fb:
            console.print_json(json.dumps(fb, ensure_ascii=False, indent=2))
        return
    console.print_json(json.dumps(matches, ensure_ascii=False, indent=2))


@kg_app.command("search")
def search_cmd(
    project_name: Optional[str] = typer.Option(None, "--project"),
    project_path: Optional[str] = typer.Option(None, "--path"),
    version: Optional[str] = typer.Option(None, "--version"),
    category: Optional[str] = typer.Option(None, "--category"),
    cwe: Optional[str] = typer.Option(None, "--cwe"),
    language: Optional[str] = typer.Option(None, "--lang"),
    severity: Optional[str] = typer.Option(None, "--severity"),
    rule_id: Optional[str] = typer.Option(None, "--rule"),
    since: Optional[str] = typer.Option(None, "--since"),
    until: Optional[str] = typer.Option(None, "--until"),
    limit: int = typer.Option(50, "--limit"),
    offset: int = typer.Option(0, "--offset"),
    scope: str = typer.Option("snapshots", "--scope", help="snapshots|records"),
    db_path: Optional[str] = typer.Option(None, "--db"),
):
    """按项目 / 版本 / 漏洞类型 / 时间范围快速检索历史记录。"""

    async def _run():
        store = open_store(db_path or default_kg_db_path())
        await store.connect()
        await store.initialize()
        try:
            q = ArchiveQuery(
                project_name=project_name, project_path=project_path, version=version,
                category=category, cwe=cwe, language=language, severity=severity,
                rule_id=rule_id, since=since, until=until,
                limit=min(max(limit, 1), 500), offset=max(offset, 0),
            )
            if scope == "records":
                items = await store.search_records(q)
                total = await store.count_records(q)
            else:
                items = await store.search_snapshots(q)
                total = await store.count_snapshots(q)
        finally:
            await store.close()
        return total, [item.to_row() for item in items]

    total, items = asyncio.run(_run())
    console.print(f"[dim]命中 {total} 条，本页 {len(items)}。[/dim]")
    console.print_json(json.dumps(items, ensure_ascii=False, indent=2, default=str))


@kg_app.command("stats")
def stats_cmd(
    db_path: Optional[str] = typer.Option(None, "--db"),
):
    """知识图谱归档库统计。"""

    async def _run():
        store = open_store(db_path or default_kg_db_path())
        await store.connect()
        await store.initialize()
        try:
            return await store.stats()
        finally:
            await store.close()

    console.print_json(json.dumps(asyncio.run(_run()), ensure_ascii=False, indent=2))


@kg_app.command("purge")
def purge_cmd(
    days: int = typer.Option(90, "--days", "-d"),
    db_path: Optional[str] = typer.Option(None, "--db"),
):
    """清理超过 N 天的归档数据 (S5 红线语义，默认 90 天)。"""

    async def _run():
        store = open_store(db_path or default_kg_db_path())
        await store.connect()
        await store.initialize()
        try:
            return await store.purge(days=days)
        finally:
            await store.close()

    removed = asyncio.run(_run())
    console.print(f"[green]✓ 已清理 {removed} 条 {days} 天前的快照及其记录。[/green]")
