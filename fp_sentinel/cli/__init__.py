"""
玄鉴 CLI 入口

命令行工具，支持扫描、查询、标记、统计等操作
使用 typer 构建，异步命令通过 asyncio.run 执行
"""

import asyncio
import json
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
from ..models import ScanTool, Finding
from ..scanners import ScannerManager, ResultNormalizer
from ..database import get_database, ProjectRepo, FindingRepo, FPMarkRepo, ScanHistoryRepo

app = typer.Typer(
    name="xuanjian",
    help="玄鉴 (xuanjian-ai) — 代码审计误报排查 MCP 工具",
    add_completion=False,
)

# 注册浏览器子命令
try:
    from .browser_commands import app as browser_app
    app.add_typer(browser_app, name="browser", help="浏览器自动化 (JSRPC)")
except ImportError:
    pass  # 未安装 aiohttp 时跳过

# 注册攻防数据子命令（Agent-Attack, v2.2.0）
try:
    from .attack_commands import attack_app, attack_purge_entry
    app.add_typer(attack_app, name="attack", help="攻防数据管理 (PoC 30 天清理)")
    app.command("attack-purge", help="清理超过保留期的攻防 PoC 数据 (S5)")(attack_purge_entry)
except ImportError:
    pass

# 注册开发者画像子命令（Agent-Profile 领地，由 Agent-Attack 统一注册；
# 模块未就绪或内部异常时静默降级，不影响其余命令——对方修复后自动生效）
try:
    from .profile_commands import profile_app
    app.add_typer(profile_app, name="profile", help="开发者画像")
except ImportError:  # noqa: BLE001 — 可选模块缺失时静默降级
    pass

console = Console()
logger = logging.getLogger(__name__)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"玄鉴 (xuanjian-ai) fp_sentinel v{__version__}")
        raise typer.Exit()


@app.callback()
def _root_callback(
    version: bool = typer.Option(
        False, "--version", "-V",
        callback=_version_callback,
        is_eager=True,
        help="显示版本号并退出",
    ),
):
    """玄鉴 (xuanjian-ai) — 代码审计误报排查 MCP 工具"""


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
    output_format: str = typer.Option("table", "--format", "-f", help="输出格式 (table/json/sarif)"),
    results_file: Optional[str] = typer.Option(
        None, "--results-file", help="JSON 或 SARIF 结构化结果文件路径"
    ),
    report: str = typer.Option(
        "compliance", "--report",
        help="生成报告类型 (compliance/attack/all/none)，默认 compliance 向后兼容",
    ),
    output: str = typer.Option("./reports/", "--output", help="报告输出目录 (S7 白名单)"),
    save_to_db: bool = typer.Option(True, "--save/--no-save", help="是否保存到数据库"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="详细输出"),
):
    """扫描项目，发现安全问题"""

    if report not in ("compliance", "attack", "all", "none"):
        console.print(f"[red]未知报告类型: {report}（可选 compliance/attack/all/none）[/red]")
        raise typer.Exit(1)

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
        elif output_format == "sarif":
            _output_sarif(findings)
        else:
            _output_table(findings)

        if results_file:
            _write_structured_results(findings, output_format, results_file)

        # 保存到数据库
        scan_id = None
        if save_to_db and findings:
            scan_id = await _save_findings(
                findings=findings,
                project_path=project_path,
                scanner_name=",".join(s.value for s in (scanner_list or [ScanTool.SEMGREP])),
                language=language,
                duration=duration,
                config=config,
            )

        # 生成报告（S7：只写入 --output 白名单目录）
        if report != "none" and findings:
            await _generate_reports(
                report_kind=report,
                output_dir=output,
                project_path=project_path,
                language=language,
                findings=findings,
                config=config,
                scan_id=scan_id,
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


def _output_sarif(findings: List[Finding]) -> None:
    """SARIF 2.1.0 输出"""
    from ..reporting.sarif import to_sarif

    sarif = to_sarif(findings)
    console.print_json(json.dumps(sarif, ensure_ascii=False, default=str))


def _write_structured_results(
    findings: List[Finding], output_format: str, results_file: str
) -> None:
    """将 JSON/SARIF 结果写入显式指定的文件，不复用报告目录参数。"""
    if output_format not in ("json", "sarif"):
        raise typer.BadParameter("--results-file 仅支持 --format json 或 sarif")

    path = Path(results_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: object
    if output_format == "sarif":
        from ..reporting.sarif import to_sarif

        payload = to_sarif(findings)
    else:
        payload = [finding.model_dump(mode="json") for finding in findings]
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    console.print(f"[dim]结构化结果已写入: {path}[/dim]")


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
        return history.scan_id


async def _generate_reports(
    report_kind: str,
    output_dir: str,
    project_path: str,
    language: str,
    findings: List[Finding],
    config,
    scan_id: Optional[str],
) -> None:
    """生成合规/攻防 Markdown 报告（v2.2.0 核一 + 核二）"""
    from pathlib import Path as _Path

    from ..cli.attack_commands import build_attack_data, save_attack_records
    from ..reporting.compliance_report import compute_trend, generate_compliance_report
    from ..reporting.attack_report import generate_attack_report, write_report

    project_name = _Path(project_path).name
    out = _Path(output_dir).resolve()

    async with get_database(
        expand_db_path(config.database.path), config.database.wal_mode
    ) as db:
        finding_repo = FindingRepo(db)
        history_repo = ScanHistoryRepo(db)

        if report_kind in ("compliance", "all"):
            trend = await compute_trend(
                finding_repo,
                history_repo,
                project_path,
                current_scan_id=scan_id,
                current_findings=findings,
            )
            content = generate_compliance_report(
                project=project_name,
                project_path=project_path,
                trend=trend,
                findings=findings,
            )
            path = write_report(content, str(out), "compliance_report.md")
            console.print(f"[green]✓ 合规报告已生成: {path}[/green]")

        if report_kind in ("attack", "all"):
            chain_report, exploit_results, verify_results, poc_map = build_attack_data(
                project_path, findings,
            )
            content = generate_attack_report(
                project=project_name,
                findings=findings,
                chain_report=chain_report,
                verify_results=verify_results,
                exploit_results=exploit_results,
                poc_map=poc_map,
            )
            path = write_report(content, str(out), "attack_report.md")
            console.print(f"[green]✓ 攻防报告已生成: {path}[/green]")

            # S5：攻防 PoC 数据落库记录 created_at（供 attack-purge 清理）
            try:
                n = await save_attack_records(
                    db, project_path, findings,
                    exploit_results, verify_results, poc_map,
                )
                console.print(f"[dim]已记录 {n} 条攻防数据（30 天保留，attack-purge 可清理）[/dim]")
            except Exception as e:  # noqa: BLE001
                logger.warning(f"攻防数据落库失败: {e}")


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
            await fp_repo.create(
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
