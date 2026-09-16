"""
玄鉴 CLI 入口

命令行工具，支持扫描、查询、标记、统计等操作
使用 typer 构建，异步命令通过 asyncio.run 执行
"""

import asyncio
import json
import os
import time
import logging
from pathlib import Path
from typing import Optional, List

import typer
from rich.table import Table
from rich.panel import Panel
from rich import box

from .. import __version__
from ..config import load_config, expand_db_path
from ..models import ScanTool, Finding
from ..scanners import ScannerManager, ResultNormalizer
from ..database import get_database, ProjectRepo, FindingRepo, FPMarkRepo, ScanHistoryRepo
from .terminal import create_console


app = typer.Typer(
    name="xuanjian",
    help="玄鉴 (xuanjian-ai) — 代码审计误报排查 MCP 工具",
    add_completion=False,
)

# ── mobile 能力组（玄鉴 v4.0：mobile hook / shell / decompile 统一聚合） ──
# 注：v4.0 各子引擎（hook/shell/decompile）的子命令统一挂载到同一个 "mobile"
# 组下；若各自重复 add_typer(name="mobile")，typer 构建 commands dict 时会
# 后者覆盖前者，导致先注册的子命令（如 mobile hook）不可达。故此处聚合。
_v4_mobile_app = typer.Typer(name="mobile", help="移动端安全分析 (v4.0): 砸壳/反编译/Hook定位", no_args_is_help=True)

try:  # 可选依赖缺失时不影响主 CLI 其它命令
    from ..mobile_hook.cli import hook_app as _mobile_hook_app

    _v4_mobile_app.add_typer(_mobile_hook_app, name="hook")
except Exception as _mobile_err:  # pragma: no cover - 防御性
    import logging as _logging

    _logging.getLogger(__name__).debug("mobile_hook CLI 注册失败: %s", _mobile_err)

try:
    from ..mobile_shell.cli import shell_app as _mobile_shell_app

    _v4_mobile_app.add_typer(_mobile_shell_app, name="shell")
except Exception as _mobile_err:  # pragma: no cover - 防御性
    import logging as _logging

    _logging.getLogger(__name__).debug("mobile_shell CLI 注册失败: %s", _mobile_err)

try:
    from ..mobile_decompile.cli import decompile_app as _mobile_decompile_app

    _v4_mobile_app.add_typer(_mobile_decompile_app, name="decompile")
except Exception as _mobile_err:  # pragma: no cover - 防御性
    import logging as _logging

    _logging.getLogger(__name__).debug("mobile_decompile CLI 注册失败: %s", _mobile_err)

try:
    from ..mobile_poc.cli import poc_app as _mobile_poc_app

    _v4_mobile_app.add_typer(_mobile_poc_app, name="poc")
except Exception as _mobile_err:  # pragma: no cover - 防御性
    import logging as _logging

    _logging.getLogger(__name__).debug("mobile_poc CLI 注册失败: %s", _mobile_err)

try:
    from ..mobile_insight.cli import insight_app as _mobile_insight_app

    _v4_mobile_app.add_typer(_mobile_insight_app, name="insight")
except Exception as _mobile_err:  # pragma: no cover - 防御性
    import logging as _logging

    _logging.getLogger(__name__).debug("mobile_insight CLI 注册失败: %s", _mobile_err)

# ---- mobile audit（一体化：insight → 报告）----
try:
    from ..mobile_audit import mobile_audit_app as _mobile_audit_app

    if _mobile_audit_app is not None:
        _v4_mobile_app.add_typer(_mobile_audit_app, name="audit")
except Exception as _audit_err:  # pragma: no cover - 防御性
    import logging as _logging

    _logging.getLogger(__name__).debug("mobile_audit CLI 注册失败: %s", _audit_err)

app.add_typer(_v4_mobile_app, name="mobile")

@app.command("mcp")
def mcp(
    transport: str = typer.Option("stdio", "--transport", help="传输方式 (stdio/sse)"),
    host: str = typer.Option("127.0.0.1", "--host", help="SSE 监听地址（默认仅本机）"),
    port: int = typer.Option(8000, "--port", min=1, max=65535, help="SSE 监听端口"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="JSON/YAML 配置文件路径"),
):
    """启动 MCP 代码审计服务器。"""
    if transport not in {"stdio", "sse"}:
        raise typer.BadParameter("必须是 stdio 或 sse", param_hint="--transport")
    if transport == "sse" and host not in {"127.0.0.1", "localhost", "::1"}:
        console.print("[yellow]警告：SSE 将监听非本机地址，请确保由反向代理或 ACL 提供认证。[/yellow]")

    from ..mcp_server import run_mcp_server
    asyncio.run(run_mcp_server(transport, host, port, config_file))


# 注册浏览器子命令
try:
    from .browser_commands import app as browser_app
    app.add_typer(browser_app, name="browser", help="浏览器自动化 (JSRPC)")
except ImportError:
    pass

# 注册 Web 一体化审计子命令 (discover / full)
try:
    from ..web_audit import web_audit_app as _web_audit_app

    if _web_audit_app is not None:
        app.add_typer(_web_audit_app, name="web-audit", help="Web 一体化审计 (API 发现→证据→报告)")
except Exception:  # pragma: no cover - 防御性
    pass

# 注册知识图谱子命令 (v2.5.1 —— 查询插件 + 自动归档)
try:
    from ..knowledge_graph.cli.kg_commands import kg_app
    app.add_typer(kg_app, name="kg", help="知识图谱查询与自动归档 (Knowledge Graph)")
except Exception:  # noqa: BLE001 —— 模块/依赖不可用时静默降级
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

# 注册企业通知子命令 (v2.5.0 —— IM Webhook 推送)
try:
    from ..notify.cli import notify_app
    app.add_typer(notify_app, name="notify", help="企业通知管理 (飞书/钉钉/企业微信 Webhook)")
except Exception:  # noqa: BLE001 — 可选模块缺失时静默降级
    pass

# 注册企业权限管理子命令（v2.5.0 —— 三级角色权限体系）
try:
    from .perm_commands import perm_app
    app.add_typer(perm_app, name="perm", help="企业权限管理（角色/项目访问控制/审计）")
except ImportError:  # noqa: BLE001 — 可选模块缺失时静默降级
    pass

# 注册 DevSecOps 对接子命令（v3.0 —— GitLab/Jira/GitHub 同步 + Pipeline 卡点 + 工单联动）
try:
    from ..devops.cli import devops_app
    app.add_typer(devops_app, name="devops", help="DevSecOps 对接（GitLab/Jira/GitHub + Pipeline 卡点）")
except Exception:  # noqa: BLE001 — 可选模块缺失时静默降级
    pass

# 注册隐私计算协同审计子命令（v3.0 — 联邦学习 / 规则共享 / 隐私验证 / 协同任务）
try:
    from ..privacy.cli_commands import privacy_app
    app.add_typer(privacy_app, name="privacy", help="隐私计算协同审计 (v3.0): 联邦学习 / 规则共享 / 隐私验证 / 协同任务")
except ImportError:  # noqa: BLE001 — 模块不可用时静默降级
    pass

# 注册自适应误报优化引擎 v3.0 子命令
# 注：fp_optimize_commands 是纯 click.Group；typer>=0.12 构建 Group 树时无法
# 遍历 click.Group 子应用（AttributeError: 'Group' object has no attribute
# 'registered_commands'），导致整个主 CLI 崩溃。这里用 typer shim 转发参数。
try:
    from .fp_optimize_commands import fp_optimize as _fp_optimize_group

    _fp_shim = typer.Typer(
        name="fp",
        help="自适应误报引擎 (v3.0): 反馈收集 / 自动优化 / 代码风格画像 / 误报统计",
        invoke_without_command=True,
        add_completion=False,
        context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    )

    @_fp_shim.callback(invoke_without_command=True)
    def _fp_shim_callback(ctx: typer.Context) -> None:
        """转发到 fp-optimize (click) 引擎。"""
        _fp_optimize_group.main(
            args=list(ctx.args or []), prog_name="fp-sentinel fp", standalone_mode=True
        )

    app.add_typer(_fp_shim, name="fp")
except ImportError:  # noqa: BLE001 — 模块不可用时静默降级
    pass

# 注册自动化修复子命令（v3.0 — 修复代码生成 / Diff预览 / 验证 / PR提交）
try:
    from ..auto_pr.cli import auto_pr_app
    app.add_typer(auto_pr_app, name="auto-pr", help="自动化修复 (v3.0): 修复代码生成 / Diff预览 / 验证 / PR提交")
except ImportError:  # noqa: BLE001 — 模块不可用时静默降级
    pass

console = create_console()

# ── v2.5.1: enterprise-init 命令（开箱即用一键初始化） ──

@app.command("enterprise-init")
def enterprise_init_cmd(
    db_path: str = typer.Option("~/.xuanjian/data.db", "--db", help="主数据库路径"),
    notify_db: str = typer.Option("~/.xuanjian/notify.db", "--notify-db", help="通知数据库路径"),
    no_admin: bool = typer.Option(False, "--no-admin", help="不创建默认管理员账号"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="详细输出"),
):
    """一键初始化企业级功能（权限/任务/通知数据库 + 默认管理员账号）"""
    async def _run():
        _setup_logging(verbose)
        from ..database import initialize_all_enterprise_dbs

        console.print("[bold]🔧 正在初始化企业级功能数据库...[/bold]")
        try:
            result = await initialize_all_enterprise_dbs(
                main_db_path=db_path,
                notify_db_path=notify_db,
            )

            main = result["main"]
            notify = result["notify"]

            if main.get("admin_created"):
                console.print(
                    f"\n[green]✅ 默认管理员账号已创建[/green]\n"
                    f"   用户名: [cyan]admin[/cyan]\n"
                    f"   ID: {main.get('admin_id', '')[:8]}...\n\n"
                    f"[bold yellow]⚠️ 请立即登录并修改默认密码！[/bold yellow]"
                )

            if main.get("tables_created"):
                console.print(f"\n[dim]新建表: {', '.join(main['tables_created'][:10])}[/dim]")
            else:
                console.print("[dim]所有表已存在，无需重复创建[/dim]")

            console.print(f"\n[green]✓ 主数据库:[/green] {main['db_path']}")
            console.print(f"[green]✓ 通知数据库:[/green] {notify['db_path']}")
            console.print(
                f"\n[bold]✅ 企业功能已就绪！[/bold] 现在可以直接使用:\n"
                f"  [cyan]xuanjian perm user-add[/cyan]    — 创建用户\n"
                f"  [cyan]xuanjian perm roles[/cyan]    — 查看权限矩阵\n"
                f"  [cyan]xuanjian task list[/cyan]    — 查看任务\n"
            )
        except Exception as e:
            console.print(f"[red]❌ 初始化失败: {e}[/red]")
            raise typer.Exit(1)

    asyncio.run(_run())


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
    kg: bool = typer.Option(
        False, "--kg/--no-kg",
        help="启用知识图谱：扫描后自动归档 + 在报告内嵌入「⑦ 知识图谱参考」章节",
    ),
    kg_version: str = typer.Option("unversioned", "--kg-version", help="归档到知识图谱的项目版本标识"),
    kg_top_k: int = typer.Option(5, "--kg-top-k", min=1, max=20, help="知识图谱参考章节最多展示的命中数"),
    install_deps: bool = typer.Option(
        False, "--install-deps",
        help="检测到 semgrep/bandit 等缺失时交互询问是否自动安装（仍需用户确认）",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="仅打印将要执行的安装命令（与 --install-deps 搭配）"),
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

        # --install-deps：检测缺失扫描器并给出安装命令
        if install_deps:
            _handle_install_deps(scanners, dry_run)

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
        for message in manager.get_unavailable_scanner_messages():
            console.print(f"[yellow][WARN] {message}[/yellow]")
        for message in manager.get_runtime_warnings():
            console.print(f"[yellow][WARN] {message}[/yellow]")

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

        # 生成报告（S7：只写入 --output 白名单目录；--kg 启用知识图谱参考 + 自动归档）
        if report != "none" and findings:
            await _generate_reports(
                report_kind=report,
                output_dir=output,
                project_path=project_path,
                language=language,
                findings=findings,
                config=config,
                scan_id=scan_id,
                kg_enabled=kg,
                kg_version=kg_version,
                kg_top_k=kg_top_k,
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
            _format_location(f),
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


def _format_location(finding: Finding) -> str:
    """Display original bundle location and optional static prettified position."""
    metadata = finding.metadata or {}
    beautified_line = metadata.get("beautified_line")
    if beautified_line:
        return f"{finding.line_start} (fmt:{beautified_line})"
    return str(finding.line_start)


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
    kg_enabled: bool = False,
    kg_version: str = "unversioned",
    kg_top_k: int = 5,
) -> None:
    """生成合规/攻防 Markdown 报告（v2.2.0 核一 + 核二 + v2.5.1 知识图谱参考）"""
    from pathlib import Path as _Path

    from ..cli.attack_commands import build_attack_data, save_attack_records
    from ..reporting.compliance_report import compute_trend, generate_compliance_report
    from ..reporting.attack_report import generate_attack_report, write_report

    project_name = _Path(project_path).name
    out = _Path(output_dir).resolve()

    kg_report_text = ""

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
            if kg_enabled:
                try:
                    from ..knowledge_graph.features.query_plugin import KnowledgeQueryPlugin
                    from ..knowledge_graph.features.report_enricher import (
                        append_reference_to_report,
                        build_reference_section,
                        inject_finding_metadata,
                    )
                    from ..knowledge_graph.store import open_store

                    store = open_store()
                    await store.connect(); await store.initialize()
                    try:
                        qb = KnowledgeQueryPlugin(archive_fn=_kg_archive_cb(store), top_k=kg_top_k)
                        kg_matches = await qb.batch_match(findings)
                        for f in findings:
                            fid = _fid(f)
                            if fid in kg_matches:
                                d = f.metadata or {}
                                inject_finding_metadata(d, kg_matches[fid])
                                f.metadata = d
                        reference = build_reference_section(kg_matches, top_k=kg_top_k)
                        content = append_reference_to_report(content, reference)
                    finally:
                        await store.close()
                except Exception as e:  # noqa: BLE001
                    logger.warning(f"知识图谱增强失败(仅参考章节): {e}")
            path = write_report(content, str(out), "compliance_report.md")
            console.print(f"[green]✓ 合规报告已生成: {path}[/green]")
            kg_report_text = content

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

    # —— 自动归档钩子 (v2.5.1 知识图谱) ——
    if kg_enabled and (kg_report_text or findings):
        try:
            from ..knowledge_graph.features.auto_archive import AutoArchiver

            async with AutoArchiver() as a:
                result = await a.archive_scan(
                    project_name=project_name,
                    project_path=project_path,
                    findings=findings,
                    report_md=kg_report_text,
                    version=kg_version,
                    language=language,
                    scanner=scan_id or "",
                    report_kind=report_kind,
                    duration_seconds=0.0,
                )
                console.print(
                    f"[dim]✓ 知识图谱归档: snapshot={result.get('snapshot_id')}  "
                    f"知识命中={result.get('knowledge_hits', 0)} CVE命中={result.get('cve_hits', 0)}[/dim]"
                )
        except Exception as e:  # noqa: BLE001
            logger.warning(f"知识图谱归档失败: {e}")


def _fid(finding) -> Optional[str]:
    for k in ("id", "fingerprint", "finding_id"):
        if isinstance(finding, dict):
            v = finding.get(k)
        else:
            v = getattr(finding, k, None)
        if v is not None and str(v):
            return str(v)
    return None


async def _kg_archive_cb(store):
    from ..knowledge_graph.models import ArchiveQuery

    async def _fn(category=None, cwe=None, language=None, limit=200):
        q = ArchiveQuery(category=category, cwe=cwe, language=language, limit=limit, offset=0)
        recs = await store.search_records(q)
        return [
            {"id": r.id, "rule_id": r.rule_id, "severity": r.severity,
             "fix_title": r.fix_title, "fix_diff": r.fix_diff,
             "reference_cve": r.reference_cve, "incident_note": r.incident_note,
             "archived_at": r.archived_at, "category": r.category,
             "language": r.language, "file_path": r.file_path, "line_start": r.line_start}
            for r in recs
        ]
    return _fn


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


# ─────────────────────── setup 命令 (C-002) ───────────────────────

@app.command("setup")
def setup_cmd(
    audit: bool = typer.Option(False, "--audit", help="仅检查并输出依赖报告（不改变环境）"),
    scan_dir: str = typer.Option(".", "--scan-dir", help="项目目录（默认当前目录）"),
    auto: bool = typer.Option(False, "--auto", help="自动探测项目语言并输出推荐"),
    install: bool = typer.Option(False, "--install", help="真正安装（三层确认：I_HAVE_ENV_AUTH=1 或交互确认）"),
    dry_run: bool = typer.Option(False, "--dry-run", help="只打印将要执行的命令（默认行为）"),
    index_url: Optional[str] = typer.Option(None, "--index-url", help="pip 镜像（写入临时 PIP_INDEX_URL）"),
    only: Optional[str] = typer.Option(None, "--only", help="限定只安装指定扫描器（逗号分隔，如 semgrep,bandit）"),
    generate_script: Optional[str] = typer.Option(
        None, "--generate-script",
        help="写出一一键脚本，格式 ps1 或 sh（如 --generate-script ps1 C:/setup.ps1）",
    ),
):
    """扫描器一键安装向导（C-002）。"""
    _setup_logging(verbose=False)

    from fp_sentinel.scanner_setup import (
        SCANNERS,
        SCANNER_INSTALL_CMD,
        ScannerInstaller,
        ProjectScannerAdvisor,
        env_token_agreed,
        interactive_agreement,
    )

    installer = ScannerInstaller()

    # --audit：仅检查
    if audit:
        _run_setup_audit(installer, scan_dir, auto)
        return

    # --generate-script
    if generate_script:
        ext = generate_script.lower()
        if ext not in ("ps1", "sh"):
            console.print(f"[red]不支持的脚本格式: {ext}（仅 ps1/sh）[/red]")
            raise typer.Exit(1)
        advisor = ProjectScannerAdvisor()
        recs = advisor.recommend(scan_dir)
        names = [r["name"] for r in recs]
        if only:
            names = [n.strip() for n in only.split(",") if n.strip() in SCANNERS]
        script = installer.generate_one_click_script(names, shell=ext)
        console.print(f"[green]一键脚本内容[/green]:\n{script}")
        raise typer.Exit(0)

    # 确定要安装的扫描器
    target_scanners: List[str] = []
    if only:
        target_scanners = [n.strip() for n in only.split(",") if n.strip() in SCANNERS]
        if not target_scanners:
            console.print("[red]--only 未匹配到任何受管扫描器[/red]")
            raise typer.Exit(1)
    elif auto:
        advisor = ProjectScannerAdvisor()
        recs = advisor.recommend(scan_dir)
        target_scanners = [r["name"] for r in recs]
    else:
        target_scanners = list(SCANNERS.keys())

    # dry_run（默认行为）只打印命令
    dry = dry_run or not install
    if dry:
        console.print("[yellow]dry-run 模式，仅打印命令：[/yellow]")
        result = installer.install(target_scanners, index_url=index_url, dry_run=True)
        for cmd in result["commands"]:
            console.print(f"  [cyan]{cmd}[/cyan]")
        console.print("\n[dim]使用 --install 真正安装（仍需确认）[/dim]")
        console.print(f"[dim]或使用: {SCANNER_INSTALL_CMD}[/dim]")
        raise typer.Exit(0)

    # 真正安装：三层确认
    if not (env_token_agreed() or interactive_agreement()):
        console.print("[yellow]未获得安装授权，已取消。[/yellow]")
        raise typer.Exit(0)

    if index_url:
        os.environ["PIP_INDEX_URL"] = index_url
    result = installer.install(target_scanners, index_url=index_url, dry_run=False)
    for r in result["results"]:
        if r["ok"]:
            console.print(f"[green]✓ {r["name"]} 安装成功[/green]")
        else:
            console.print(f"[red]✗ {r["name"]} 安装失败 (rc={r["returncode"]})[/red]")
    if result.get("suggestions"):
        console.print(f"\n{result['suggestions']}")


# ─────────────────────── render 命令 (D-002) ───────────────────────

@app.command("render")
def render_cmd(
    docx: str = typer.Argument(..., help="要渲染的 docx 文件路径"),
    fmt: str = typer.Option("auto", "--fmt", help="输出格式 auto/html/pdf/png"),
    scale: float = typer.Option(1.5, "--scale", help="浏览器 headless 缩放系数"),
    output: Optional[str] = typer.Option(None, "--output", help="输出文件路径（白名单内）"),
):
    """DOCX 预览渲染（D-002）：自动降级 LibreOffice → 浏览器 → 原生 HTML。"""
    _setup_logging(verbose=False)

    from fp_sentinel.web_rendering import DocxPreview

    preview = DocxPreview()
    result = preview.render(docx, out_path=output, fmt=fmt, scale=scale)

    console.print("[green]渲染完成[/green]")
    console.print(f"  格式: {result['format']}")
    console.print(f"  后端: {result['backend']}")
    console.print(f"  输出: {result['path']}")
    if result["warnings"]:
        console.print("[yellow]警告:[/yellow]")
        for w in result["warnings"]:
            console.print(f"  - {w}")


# ─────────────────────── 辅助函数 ───────────────────────

def _handle_install_deps(scanners: Optional[str], dry_run_flag: bool) -> None:
    """--install-deps 逻辑：检测缺失扫描器并给出安装命令或交互安装。"""
    from fp_sentinel.scanner_setup import (
        SCANNERS,
        ScannerInstaller,
        env_token_agreed,
        interactive_agreement,
    )

    installer = ScannerInstaller()
    if scanners:
        names_to_check = [s.strip() for s in scanners.split(",")]
    else:
        names_to_check = ["semgrep", "bandit"]

    missing: List[str] = []
    for name in names_to_check:
        info = installer.check(name)
        if not info["installed"]:
            missing.append(name)

    if not missing:
        console.print("[green]所需扫描器均已就绪。[/green]")
        return

    console.print(f"[yellow]缺失扫描器: {', '.join(missing)}[/yellow]")
    for name in missing:
        meta = SCANNERS.get(name, {})
        pkg = meta.get("pip_package", name)
        console.print(f"  pip install {pkg}")

    if dry_run_flag:
        console.print("[dim]--dry-run：以上命令未执行。[/dim]")
        return

    if env_token_agreed() or interactive_agreement():
        result = installer.install(missing, dry_run=False)
        for r in result["results"]:
            if r["ok"]:
                console.print(f"[green]✓ {r['name']} 安装成功[/green]")
            else:
                console.print(f"[red]✗ {r['name']} 安装失败[/red]")


def _run_setup_audit(
    installer: object,
    scan_dir: str,
    auto: bool,
) -> None:
    """运行依赖审计报告。"""
    from fp_sentinel.mobile_common.env_check import ScannerChecker

    checker = ScannerChecker()
    console.print("[bold]扫描器可用性审计[/bold]")
    for name in checker.scanner_names:
        result = checker.check(name)
        status = "[green]✓[/green]" if result.available else "[red]✗[/red]"
        console.print(f"  {status} {result.name}: {result.version or '未安装'}")

    if auto:
        from fp_sentinel.scanner_setup import ProjectScannerAdvisor

        advisor = ProjectScannerAdvisor()
        report = advisor.format_report(scan_dir)
        console.print(f"\n{report}")


# ─────────────────────── 入口 ───────────────────────

def main():
    """CLI 入口点"""
    app()


if __name__ == "__main__":
    main()
