"""
玄鉴 CLI 入口

命令行工具，支持扫描、查询、标记、统计等操作
使用 typer 构建，异步命令通过 asyncio.run 执行
"""

import asyncio
import json
import sys
import time
import logging
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from .. import __version__
from ..config import load_config, expand_db_path
from ..models import ScanResult, ScanTool, Finding, Severity
from ..scanners import ScannerManager, ResultNormalizer
from ..database import get_database, ProjectRepo, FindingRepo, FPMarkRepo, ScanHistoryRepo

app = typer.Typer(
    name="xuanjian",
    help="玄鉴 (xuanjian-ai) — 代码审计误报排查 MCP 工具",
    add_completion=False,
)
console = Console()

# ─────────────────────── 辅助 ───────────────────────

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _severity_style(severity: str) -> str:
    return {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }.get(severity, "white")


# ─────────────────────── scan 命令 ───────────────────────

@app.command()
def scan(
    project_path: str = typer.Argument(..., help="要扫描的项目路径"),
    language: str = typer.Option("auto", "--lang", "-l", help="项目语言 (java/python/go/auto)"),
    scanners: Optional[str] = typer.Option(None, "--scanner", "-s", help="指定扫描器 (逗号分隔: semgrep,bandit,findsecbugs)"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="YAML 配置文件路径"),
    output_format: str = typer.Option("table", "--format", "-f", help="输出格式 (table/json)"),
    save_to_db: bool = typer.Option(True, "--save/--no-save", help="是否保存到数据库"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="详细输出"),
):
    """扫描项目，发现安全问题"""

    async def _run():
        _setup_logging(verbose)

        # 加载配置
        config = load_config(config_file)

        # 解析扫描器列表
        scanner_list = None
        if scanners:
            scanner_list = []
            for s in scanners.split(","):
                s = s.strip().lower()
                try:
                    scanner_list.append(ScanTool(s))
                except ValueError:
                    console.print(f"[red]未知扫描器: {s}[/red]")
                    raise typer.Exit(1)

        # 初始化扫描器管理器
        manager = ScannerManager(config.scanners)
        normalizer = ResultNormalizer()

        console.print(f"\n[bold]🔍 正在扫描: {project_path}[/bold]")
        console.print(f"   语言: {language}  可用扫描器: {manager.get_available_scanners()}\n")

        # 执行扫描
        start = time.time()
        scan_results = await manager.scan(
            target_path=project_path,
            language=language,
            scanners=scanner_list,
        )
        duration = time.time() - start

        # 归一化
        findings = normalizer.normalize_many(scan_results)
        findings = normalizer.deduplicate(findings)

        console.print(f"[green]✓ 扫描完成[/green]  耗时 {duration:.1f}s  发现 {len(findings)} 个问题\n")

        # 输出
        if output_format == "json":
            _output_json(findings)
        else:
            _output_table(findings)

        # 保存到数据库
        if save_to_db and findings:
            await _save_findings(
                findings=findings,
                project_path=project_path,
                scanner_name=",".join(s.value for s in (scanner_list or [ScanTool.SEMGREP])),
                language=language,
                duration=duration,
                config=config,
            )

    asyncio.run(_run())


def _output_table(findings: List[Finding]) -> None:
    """表格输出"""
    table = Table(
        title="扫描结果",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Severity", justify="center")
    table.add_column("Scanner", style="cyan")
    table.add_column("Rule", style="magenta", max_width=30)
    table.add_column("File", max_width=50)
    table.add_column("Line", justify="right")
    table.add_column("Message", max_width=50)

    for i, f in enumerate(findings[:100], 1):
        sev_style = _severity_style(f.severity.value)
        table.add_row(
            str(i),
            f"[{sev_style}]{f.severity.value}[/{sev_style}]",
            f.scanner,
            f.rule_id,
            _truncate(f.file_path, 50),
            str(f.line_start),
            _truncate(f.message, 50),
        )

    console.print(table)
    if len(findings) > 100:
        console.print(f"[dim]... 以及另外 {len(findings) - 100} 条结果[/dim]")


def _output_json(findings: List[Finding]) -> None:
    """JSON 输出"""
    data = [f.model_dump(mode="json") for f in findings]
    console.print_json(json.dumps(data, ensure_ascii=False, default=str))


def _truncate(s: str, max_len: int) -> str:
    return s if len(s) <= max_len else s[:max_len - 3] + "..."


async def _save_findings(
    findings: List[Finding],
    project_path: str,
    scanner_name: str,
    language: str,
    duration: float,
    config,
) -> None:
    """保存扫描结果到数据库"""
    db_path = expand_db_path(config.database.path)
    async with get_database(db_path, config.database.wal_mode) as db:
        project_repo = ProjectRepo(db)
        finding_repo = FindingRepo(db)
        history_repo = ScanHistoryRepo(db)

        # 确保项目存在
        project = await project_repo.get_or_create(
            name=Path(project_path).name,
            path=project_path,
            language=language,
        )

        # 记录扫描历史
        history = await history_repo.create(
            project_path=project_path,
            scanner=scanner_name,
            project_id=project.id,
            language=language,
            total_findings=len(findings),
            duration_seconds=duration,
        )

        # 保存 findings
        count = await finding_repo.bulk_create(findings, scan_id=history.scan_id)
        console.print(f"[dim]已保存 {count} 条结果到数据库 ({db_path})[/dim]")


# ─────────────────────── list 命令 ───────────────────────

@app.command("list")
def list_findings(
    scanner: Optional[str] = typer.Option(None, "--scanner", "-s", help="按扫描器过滤"),
    severity: Optional[str] = typer.Option(None, "--severity", help="按严重程度过滤"),
    file_path: Optional[str] = typer.Option(None, "--file", help="按文件路径模糊匹配"),
    language: Optional[str] = typer.Option(None, "--lang", "-l", help="按语言过滤"),
    limit: int = typer.Option(50, "--limit", "-n", help="显示数量"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="配置文件"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """列出数据库中的安全发现"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        async with get_database(db_path, config.database.wal_mode) as db:
            repo = FindingRepo(db)
            findings = await repo.list_findings(
                scanner=scanner,
                severity=severity,
                file_path=file_path,
                language=language,
                limit=limit,
            )

            if not findings:
                console.print("[yellow]未找到匹配的发现[/yellow]")
                return

            _output_table(findings)

    asyncio.run(_run())


# ─────────────────────── mark 命令 ───────────────────────

@app.command()
def mark(
    finding_id: str = typer.Argument(..., help="Finding ID"),
    reason: str = typer.Option("manual review", "--reason", "-r", help="标记原因"),
    marked_by: str = typer.Option("manual", "--by", help="标记来源 (manual/auto)"),
    scope: str = typer.Option("instance", "--scope", help="作用域 (instance/rule/global)"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="配置文件"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """将一个 Finding 标记为误报"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        async with get_database(db_path, config.database.wal_mode) as db:
            finding_repo = FindingRepo(db)
            fp_repo = FPMarkRepo(db)

            # 检查 finding 是否存在
            finding = await finding_repo.get_by_id(finding_id)
            if not finding:
                console.print(f"[red]未找到 Finding: {finding_id}[/red]")
                raise typer.Exit(1)

            # 创建标记
            mark_obj = await fp_repo.create(
                finding_id=finding_id,
                reason=reason,
                marked_by=marked_by,
                scope=scope,
            )

            console.print(
                f"[green]✓ 已标记为误报[/green]\n"
                f"  Finding : {finding_id}\n"
                f"  规则    : {finding.rule_id}\n"
                f"  文件    : {finding.file_path}:{finding.line_start}\n"
                f"  原因    : {reason}\n"
                f"  作用域  : {scope}"
            )

    asyncio.run(_run())


# ─────────────────────── stats 命令 ───────────────────────

@app.command()
def stats(
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="配置文件"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """显示统计信息"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        async with get_database(db_path, config.database.wal_mode) as db:
            finding_repo = FindingRepo(db)
            history_repo = ScanHistoryRepo(db)
            project_repo = ProjectRepo(db)
            fp_repo = FPMarkRepo(db)

            # 统计数据
            total_findings = await finding_repo.count()
            severity_stats = await finding_repo.get_severity_stats()
            projects = await project_repo.list_all()
            histories = await history_repo.list_history(limit=1000)
            fp_marks = await fp_repo.list_all(limit=10000)

            # 构建面板
            lines = [
                f"[bold]项目总数[/bold]:     {len(projects)}",
                f"[bold]扫描次数[/bold]:     {len(histories)}",
                f"[bold]发现总数[/bold]:     {total_findings}",
                f"[bold]误报标记[/bold]:     {len(fp_marks)}",
                "",
                "[bold]按严重程度:[/bold]",
            ]

            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                count = severity_stats.get(sev, 0)
                style = _severity_style(sev)
                lines.append(f"  [{style}]{sev:<10}[/{style}] {count}")

            if total_findings > 0:
                fp_rate = len(fp_marks) / total_findings * 100
                lines.append(f"\n[bold]误报率[/bold]:       {fp_rate:.1f}%")

            panel = Panel(
                "\n".join(lines),
                title="📊 玄鉴统计",
                border_style="cyan",
            )
            console.print(panel)

    asyncio.run(_run())


# ─────────────────────── version 命令 ───────────────────────

@app.command()
def version():
    """显示版本信息"""
    console.print(f"玄鉴 (xuanjian-ai) fp_sentinel v{__version__}")


# ─────────────────────── 入口 ───────────────────────

def main():
    """CLI 入口点"""
    app()


if __name__ == "__main__":
    main()
