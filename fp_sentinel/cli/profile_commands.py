"""
profile 子命令组（核三：开发者画像 CLI）

注意：本模块只暴露 profile_app = typer.Typer()，由 Agent-Attack 在
fp_sentinel/cli/__init__.py 中统一注册（本模块不得修改该文件）。

安全红线：
- git 命令只读（见 attribution 模块白名单），禁止任何 git 写操作；
- 画像数据仅本地 SQLite，禁止任何网络上传；
- 默认 SHA256 别名化；--reveal 需 FP_SENTINEL_REVEAL=1 环境变量
  + --i-am-security-officer 双条件才生效；
- profile forget 仅删除画像库数据，不触碰用户代码与 findings；
- 本命令组不提供任何"画像评分导出为绩效格式"的接口。
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from ..config import expand_db_path, load_config
from ..database import FindingRepo, ScanHistoryRepo, ProjectRepo, get_database
from ..models import ScanTool
from ..profile.attribution import attribute_and_store
from ..profile.analyzer import build_team_profile
from ..profile.models import (
    ProfileRepo,
    alias_hash,
    ensure_profile_tables,
    get_profile_key,
    decrypt_name,
)
from ..reporting.profile_report import (
    DEFAULT_OUTPUT_DIR,
    check_reveal_allowed,
    generate_personal_report,
    generate_team_report,
    save_report,
)
from ..scanners import ScannerManager, ResultNormalizer

profile_app = typer.Typer(
    name="profile",
    help="开发者画像（本地匿名分析，仅用于培训与能力提升）",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


def _resolve_reveal(reveal: bool, i_am_security_officer: bool) -> bool:
    """
    reveal 三重校验：--reveal 旗标 + --i-am-security-officer 旗标
    + FP_SENTINEL_REVEAL=1 环境变量，缺一不可。
    """
    if not check_reveal_allowed(reveal):
        return False
    if not i_am_security_officer:
        console.print("[red]--reveal 需同时指定 --i-am-security-officer[/red]")
        return False
    return True


@profile_app.command("team")
def profile_team(
    month: Optional[str] = typer.Option(None, "--month", help="统计周期（YYYY-MM，默认全部）"),
    kloc: Optional[float] = typer.Option(None, "--kloc", help="项目千行代码数（用于漏洞密度）"),
    output: str = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="报告输出目录"),
    reveal: bool = typer.Option(False, "--reveal", help="显示解密姓名（需安全官双条件）"),
    i_am_security_officer: bool = typer.Option(False, "--i-am-security-officer", hidden=True),
    top: int = typer.Option(5, "--top", help="Top N 个人画像数量"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="配置文件"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """生成团队画像报告（Markdown，匿名别名）"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        async with get_database(db_path, config.database.wal_mode) as db:
            await ensure_profile_tables(db)
            finding_repo = FindingRepo(db)
            profile_repo = ProfileRepo(db)

            findings = await finding_repo.list_findings(limit=100000)
            attributions = await profile_repo.list_attribution()
            fixes = await profile_repo.list_fixes()

            # 解密显示名（仅 reveal 通过时使用）
            display_names = {}
            reveal_ok = _resolve_reveal(reveal, i_am_security_officer)
            if reveal_ok:
                key = get_profile_key(db_path)
                for ah in await profile_repo.list_alias_hashes():
                    row = await profile_repo.get_alias(ah)
                    name = decrypt_name(row.get("display_name_encrypted"), key) if row else None
                    if name:
                        display_names[ah] = name

            team = build_team_profile(
                findings=findings,
                attributions=attributions,
                period=month,
                fix_events=fixes,
                kloc=kloc,
                display_names=display_names,
            )
            markdown = generate_team_report(team, reveal=reveal_ok, top_n=top)

            filename = f"profile-team-{month or 'all'}.md"
            saved = save_report(markdown, filename, base_dir=output)
            console.print(f"[green]✓ 团队画像报告已生成[/green] 健康度 {team.health_score:.1f}/100")
            console.print(f"  归因覆盖率: {team.coverage * 100:.1f}%  成员(含unknown): {len(team.members)}")
            console.print(f"  报告文件: {saved}")

    asyncio.run(_run())


@profile_app.command("me")
def profile_me(
    alias: Optional[str] = typer.Option(None, "--alias", help="别名（别名哈希或 email）"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="可选：报告输出目录"),
    reveal: bool = typer.Option(False, "--reveal", help="显示解密姓名（需安全官双条件）"),
    i_am_security_officer: bool = typer.Option(False, "--i-am-security-officer", hidden=True),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="配置文件"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """查看本人画像（个人视角，含团队匿名平均对比）"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        async with get_database(db_path, config.database.wal_mode) as db:
            await ensure_profile_tables(db)
            finding_repo = FindingRepo(db)
            profile_repo = ProfileRepo(db)

            if not alias:
                # 未指定别名：列出全部匿名别名及发现数
                hashes = await profile_repo.list_alias_hashes()
                if not hashes:
                    console.print("[yellow]画像库为空，请先运行 profile scan <path>[/yellow]")
                    return
                table = Table(title="画像库别名（匿名）", show_lines=False)
                table.add_column("别名")
                table.add_column("发现数", justify="right")
                attrs = await profile_repo.list_attribution()
                counts = {}
                for a in attrs:
                    counts[a.alias_hash] = counts.get(a.alias_hash, 0) + 1
                for ah in hashes:
                    table.add_row(ah, str(counts.get(ah, 0)))
                console.print(table)
                console.print("[dim]使用 --alias <别名或email> 查看个人画像[/dim]")
                return

            ah = alias if len(alias) == 16 and all(c in "0123456789abcdef" for c in alias) else alias_hash(alias)
            attrs = await profile_repo.list_attribution(fingerprints=None)
            own_fps = {a.finding_fingerprint for a in attrs if a.alias_hash == ah}
            findings = await finding_repo.list_findings(limit=100000)
            own = [f for f in findings if (f.fingerprint or "") in own_fps]
            if not own:
                console.print(f"[yellow]别名 {ah} 无画像数据[/yellow]")
                return

            fixes = await profile_repo.list_fixes()
            reveal_ok = _resolve_reveal(reveal, i_am_security_officer)
            display_name = None
            if reveal_ok:
                key = get_profile_key(db_path)
                row = await profile_repo.get_alias(ah)
                display_name = decrypt_name(row.get("display_name_encrypted"), key) if row else None

            from ..profile.analyzer import analyze_developer, compute_team_health

            profile_obj = analyze_developer(
                alias=ah, findings=own, fix_events=fixes, period="all", display_name=display_name
            )
            _, team_metrics = compute_team_health(findings, fix_events=fixes)
            markdown = generate_personal_report(profile_obj, team_metrics=team_metrics, reveal=reveal_ok)

            if output:
                saved = save_report(markdown, f"profile-me-{ah}.md", base_dir=output)
                console.print(f"[green]✓ 个人画像报告已生成[/green] {saved}")
            else:
                console.print(markdown)

    asyncio.run(_run())


@profile_app.command("forget")
def profile_forget(
    alias: str = typer.Argument(..., help="要删除的别名（别名哈希或 email）"),
    yes: bool = typer.Option(False, "--yes", "-y", help="跳过确认"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="配置文件"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """
    删除某别名在画像库中的全部数据（仅画像库；不触碰代码与 findings）。
    """

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        ah = (
            alias
            if len(alias) == 16 and all(c in "0123456789abcdef" for c in alias)
            else alias_hash(alias)
        )

        if not yes:
            confirm = typer.confirm(f"确认删除画像库中别名 {ah} 的全部数据？（不影响代码与 findings）")
            if not confirm:
                console.print("[yellow]已取消[/yellow]")
                return

        async with get_database(db_path, config.database.wal_mode) as db:
            await ensure_profile_tables(db)
            profile_repo = ProfileRepo(db)
            deleted = await profile_repo.forget_alias(ah)
            total = sum(deleted.values())
            if total == 0:
                console.print(f"[yellow]别名 {ah} 无画像数据[/yellow]")
            else:
                console.print(f"[green]✓ 已删除别名 {ah} 的画像数据[/green]")
                for table, n in deleted.items():
                    console.print(f"  {table}: {n} 行")

    asyncio.run(_run())


@profile_app.command("scan")
def profile_scan(
    project_path: str = typer.Argument(..., help="要扫描并归因的项目路径"),
    language: str = typer.Option("auto", "--lang", "-l", help="项目语言"),
    max_records: int = typer.Option(5000, "--max-records", help="归因记录上限（默认 5000）"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="配置文件"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """扫描项目 + 只读 git 归因入库（扫描结果同时保存到数据库）"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)

        manager = ScannerManager(config.scanners)
        normalizer = ResultNormalizer()
        console.print(f"\n[bold]🔍 正在扫描: {project_path}[/bold]")
        start = time.time()
        scan_results = await manager.scan(
            target_path=project_path, language=language, scanners=None
        )
        findings = normalizer.normalize_many(scan_results)
        findings = normalizer.deduplicate(findings)
        duration = time.time() - start
        console.print(f"[green]✓ 扫描完成[/green] 耗时 {duration:.1f}s 发现 {len(findings)} 个问题")

        db_path = expand_db_path(config.database.path)
        async with get_database(db_path, config.database.wal_mode) as db:
            await ensure_profile_tables(db)
            project_repo = ProjectRepo(db)
            finding_repo = FindingRepo(db)
            history_repo = ScanHistoryRepo(db)
            project = await project_repo.get_or_create(
                name=Path(project_path).name, path=project_path, language=language
            )
            history = await history_repo.create(
                project_path=project_path,
                scanner=",".join(s.value for s in manager.scanners.keys() or [ScanTool.SEMGREP]),
                project_id=project.id,
                language=language,
                total_findings=len(findings),
                duration_seconds=duration,
            )
            if findings:
                await finding_repo.bulk_create(findings, scan_id=history.scan_id)
                result = await attribute_and_store(
                    db, project_path, findings, max_records=max_records
                )
                s = result.summary()
                console.print(
                    f"[green]✓ 归因完成[/green] 覆盖率 {s['coverage'] * 100:.1f}% "
                    f"({s['attributed']}/{s['total']}，unknown {s['unknown']}"
                    f"{'，已达上限截断' if s['truncated'] else ''})"
                )
                if not s["is_git_repo"]:
                    console.print("[yellow]非 git 目录：全部降级为 unknown，报告将标注覆盖率[/yellow]")
            else:
                console.print("[yellow]无发现，跳过归因[/yellow]")

    asyncio.run(_run())


@profile_app.command("build")
def profile_build(
    max_records: int = typer.Option(5000, "--max-records", help="归因记录上限（默认 5000）"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="配置文件"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """
    对数据库中已有 findings 补做归因入库（适合先跑 xuanjian scan 再 profile build 的流程）。
    """

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        async with get_database(db_path, config.database.wal_mode) as db:
            await ensure_profile_tables(db)
            finding_repo = FindingRepo(db)
            profile_repo = ProfileRepo(db)

            findings = await finding_repo.list_findings(limit=100000)
            existing = await profile_repo.list_attribution()
            done_fps = {a.finding_fingerprint for a in existing}
            todo = [
                f for f in findings
                if (f.fingerprint or "") not in done_fps
            ]
            if not todo:
                console.print("[yellow]没有待归因的 findings（可先运行 xuanjian scan）[/yellow]")
                return
            # 归因需要项目根目录：优先取数据库中最近一次扫描的项目路径
            histories = await ScanHistoryRepo(db).list_history(limit=1)
            if not histories:
                console.print("[red]数据库无扫描历史，无法确定项目根目录[/red]")
                raise typer.Exit(1)
            project_path = histories[0].project_path

            result = await attribute_and_store(db, project_path, todo, max_records=max_records)
            s = result.summary()
            console.print(
                f"[green]✓ 补做归因完成[/green] 项目 {project_path}\n"
                f"  覆盖率 {s['coverage'] * 100:.1f}% ({s['attributed']}/{s['total']})"
            )

    asyncio.run(_run())


@profile_app.command("mark-fixed")
def profile_mark_fixed(
    finding_id: str = typer.Argument(..., help="Finding ID"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="配置文件"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """将某 finding 标记为已修复（记录修复时间，用于修复速度维度）"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        async with get_database(db_path, config.database.wal_mode) as db:
            await ensure_profile_tables(db)
            finding_repo = FindingRepo(db)
            profile_repo = ProfileRepo(db)

            finding = await finding_repo.get_by_id(finding_id)
            if not finding:
                console.print(f"[red]未找到 Finding: {finding_id}[/red]")
                raise typer.Exit(1)
            if not finding.fingerprint:
                console.print("[red]该 Finding 无 fingerprint，无法记录修复状态[/red]")
                raise typer.Exit(1)
            await profile_repo.record_fix(finding.fingerprint, datetime.now(timezone.utc))
            console.print(
                f"[green]✓ 已记录修复[/green] {finding.rule_id} @ {finding.file_path}:{finding.line_start}"
            )

    asyncio.run(_run())
