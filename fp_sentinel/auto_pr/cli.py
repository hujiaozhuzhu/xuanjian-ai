"""
玄鉴 v3.0 — 自动化修复 CLI 命令

Subcommands:
- preview: 生成修复预览（Diff格式）
- verify:  验证修复代码
- submit:  提交修复PR
- status:  查看PR状态
- list:    列出PR记录
- stats:   修复统计
- history: 修复历史
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

from .auto_fix_generator import AutoFixGenerator
from .fix_validator import FixValidator
from .models import (
    AutoPRConfig,
    GenerateFixRequest,
    VerifyFixRequest,
    VulnerabilityType,
)
from .pr_manager import create_pr_adapter
from .service import AutoPRService

logger = logging.getLogger(__name__)
console = Console()

auto_pr_app = typer.Typer(
    name="auto-pr",
    help="自动化修复 (v3.0): 修复代码生成 / Diff预览 / 验证 / PR提交",
    add_completion=False,
)


def _load_config() -> AutoPRConfig:
    import os
    return AutoPRConfig(
        provider=os.environ.get("XUANJIAN_AUTOPR_PROVIDER", "gitlab"),
        base_url=os.environ.get("XUANJIAN_AUTOPR_BASE_URL", ""),
        api_token=os.environ.get("XUANJIAN_AUTOPR_API_TOKEN", ""),
        project_id=os.environ.get("XUANJIAN_AUTOPR_PROJECT_ID", ""),
        default_branch=os.environ.get("XUANJIAN_AUTOPR_DEFAULT_BRANCH", "main"),
        dry_run=os.environ.get("XUANJIAN_AUTOPR_DRY_RUN", "false").lower() == "true",
    )


def _get_service() -> AutoPRService:
    return AutoPRService(
        generator=AutoFixGenerator(),
        validator=FixValidator(),
    )


# ─────────────────────── preview 命令 ───────────────────────

@auto_pr_app.command("preview")
def preview_fix(
    rule_id: str = typer.Option(..., "--rule-id", "-r", help="规则ID"),
    severity: str = typer.Option("HIGH", "--severity", "-s", help="严重度"),
    file_path: str = typer.Option(..., "--file", "-f", help="文件路径"),
    code_snippet: str = typer.Option("", "--code", "-c", help="漏洞代码片段"),
    finding_id: str = typer.Option("", "--finding-id", help="Finding ID"),
    message: str = typer.Option("", "--message", "-m", help="漏洞描述"),
    language: str = typer.Option("", "--lang", help="编程语言"),
):
    """生成修复Diff预览"""
    request = GenerateFixRequest(
        finding_id=finding_id or f"preview-{rule_id}",
        rule_id=rule_id,
        severity=severity,
        file_path=file_path,
        code_snippet=code_snippet,
        message=message,
        language=language,
    )
    generator = AutoFixGenerator()
    preview = generator.generate_fix_preview(request)

    console.print(Panel(
        f"[bold]{preview.title}[/bold]\n"
        f"漏洞类型: [cyan]{preview.vuln_type.value}[/cyan]  "
        f"文件: [yellow]{preview.file_path}[/yellow]\n"
        f"预计工时: {preview.effort_minutes}分钟  "
        f"参考CVE: {preview.reference_cve or 'N/A'}",
        title="修复预览",
        border_style="green",
    ))

    if preview.unified_diff:
        syntax = Syntax(preview.unified_diff, "diff", theme="monokai")
        console.print(syntax)


# ─────────────────────── verify 命令 ───────────────────────

@auto_pr_app.command("verify")
def verify_fix(
    patch_id: str = typer.Option(..., "--patch-id", help="补丁ID"),
    finding_id: str = typer.Option(..., "--finding-id", help="Finding ID"),
    fixed_code: str = typer.Option(..., "--fixed-code", help="修复后代码"),
    original_code: str = typer.Option("", "--original-code", help="原始代码"),
    vuln_type: str = typer.Option("generic", "--vuln-type", help="漏洞类型"),
    rule_id: str = typer.Option("", "--rule-id", help="规则ID"),
):
    """验证修复代码的有效性"""
    def _run():
        vtype = VulnerabilityType.GENERIC
        try:
            vtype = VulnerabilityType(vuln_type)
        except ValueError:
            console.print(f"[yellow]未知漏洞类型 '{vuln_type}'，使用 generic[/yellow]")

        request = VerifyFixRequest(
            patch_id=patch_id,
            finding_id=finding_id,
            original_code=original_code,
            fixed_code=fixed_code,
            rule_id=rule_id,
            vuln_type=vtype,
        )
        validator = FixValidator()
        result = validator.verify_fix(request)

        status_color = {
            "pass": "green",
            "warn": "yellow",
            "fail": "red",
        }.get(result.status.value, "white")

        console.print(Panel(
            f"验证状态: [bold {status_color}]{result.status.value.upper()}[/bold {status_color}]\n"
            f"语法有效: {'✅' if result.syntax_valid else '❌'}\n"
            f"原漏洞已修复: {'✅' if result.original_vuln_resolved else '❌'}\n"
            f"引入新漏洞: {result.new_vulns_introduced}\n"
            f"安全检查: {'✅' if result.security_check_passed else '❌'}",
            title="修复验证结果",
            border_style=status_color,
        ))

        if result.details:
            console.print("[bold]验证详情:[/bold]")
            for d in result.details:
                console.print(f"  • {d}")

        if result.warnings:
            console.print("[bold yellow]警告:[/bold yellow]")
            for w in result.warnings:
                console.print(f"  ⚠ {w}")

        # 如果验证通过，返回0；否则返回1
        if result.status.value == "fail":
            raise typer.Exit(1)

    _run()


# ─────────────────────── submit 命令 ───────────────────────

@auto_pr_app.command("submit")
def submit_pr(
    title: str = typer.Option("", "--title", "-t", help="PR标题"),
    description: str = typer.Option("", "--description", "-d", help="PR描述"),
    finding_ids: str = typer.Option(..., "--finding-ids", help="Finding IDs (逗号分隔)"),
    ticket_ids: str = typer.Option("", "--ticket-ids", help="关联工单IDs (逗号分隔)"),
    labels: str = typer.Option("security,auto-fix", "--labels", help="PR标签 (逗号分隔)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="仅模拟不提交"),
    provider: str = typer.Option("", "--provider", "-p", help="Git平台: gitlab/github"),
    project_id: str = typer.Option("", "--project-id", help="项目ID"),
):
    """提交修复PR"""
    async def _run():
        config = _load_config()
        if dry_run:
            config.dry_run = True
        if provider:
            config.provider = provider
        if project_id:
            config.project_id = project_id

        fid_list = [f.strip() for f in finding_ids.split(",") if f.strip()]
        tid_list = [t.strip() for t in ticket_ids.split(",") if t.strip()] if ticket_ids else []
        label_list = [l.strip() for l in labels.split(",") if l.strip()]

        service = _get_service()

        # 先为所有finding生成修复补丁
        requests = [
            GenerateFixRequest(
                finding_id=fid,
                rule_id="manual-submit",
                severity="HIGH",
                file_path="unknown",
                code_snippet="",
            )
            for fid in fid_list
        ]
        await service.generate_and_preview(requests)

        # 提交PR
        result = await service.submit_fix_pr(
            config=config,
            finding_ids=fid_list,
            title=title,
            description=description,
            ticket_ids=tid_list,
            labels=label_list,
            skip_verification=True,
        )

        if result.get("status") == "error":
            console.print(f"[red]提交失败: {'; '.join(result.get('errors', []))}[/red]")
            raise typer.Exit(1)

        console.print(Panel(
            f"[green]✅ PR 已创建[/green]\n"
            f"PR ID: {result.get('pr_id', 'N/A')}\n"
            f"PR URL: {result.get('pr_url', 'N/A')}\n"
            f"分支: {result.get('branch', 'N/A')}\n"
            f"提交补丁数: {result.get('patches_submitted', 0)}",
            title="PR提交成功",
            border_style="green",
        ))

    asyncio.run(_run())


# ─────────────────────── status 命令 ───────────────────────

@auto_pr_app.command("status")
def pr_status(
    pr_id: str = typer.Option(..., "--pr-id", help="PR ID"),
):
    """查看PR状态"""
    async def _run():
        service = _get_service()
        status_info = await service.get_pr_status(pr_id)

        if status_info.get("status") == "not_found":
            console.print(f"[yellow]未找到PR: {pr_id}[/yellow]")
            return

        table = Table(title=f"PR Status: {pr_id}")
        table.add_column("字段", style="cyan")
        table.add_column("值", style="bold")
        for k, v in status_info.items():
            table.add_row(k, str(v))
        console.print(table)

    asyncio.run(_run())


# ─────────────────────── list 命令 ───────────────────────

@auto_pr_app.command("list")
def list_prs(
    status_filter: Optional[str] = typer.Option(None, "--status", help="按状态过滤: open/merged/closed/draft"),
):
    """列出PR记录"""
    async def _run():
        service = _get_service()
        prs = await service.list_prs(status_filter=status_filter)
        if not prs:
            console.print("[dim]暂无PR记录[/dim]")
            return

        table = Table(title="自动修复PR列表")
        table.add_column("PR ID", style="cyan")
        table.add_column("标题", max_width=40)
        table.add_column("状态", style="bold")
        table.add_column("分支", style="yellow")
        table.add_column("创建时间", max_width=20)
        for pr in prs:
            table.add_row(
                pr.get("pr_id", "")[:12],
                pr.get("pr_title", "")[:40],
                pr.get("status", ""),
                pr.get("branch", ""),
                pr.get("created_at", "")[:19],
            )
        console.print(table)

    asyncio.run(_run())


# ─────────────────────── stats 命令 ───────────────────────

@auto_pr_app.command("stats")
def show_stats():
    """修复模块统计"""
    async def _run():
        service = _get_service()
        stats = await service.get_pr_stats()

        table = Table(title="自动修复统计 (v3.0)")
        table.add_column("指标", style="cyan")
        table.add_column("数值", style="bold")

        table.add_row("总修复数", str(stats.total_fixes))
        table.add_row("待处理", str(stats.pending_fixes))
        table.add_row("验证通过", str(stats.verified_fixes))
        table.add_row("验证失败", str(stats.failed_verifications))
        table.add_row("已提交PR", str(stats.submitted_prs))
        table.add_row("已合并", str(stats.merged_prs))
        table.add_row("已关闭", str(stats.closed_prs))
        table.add_row("平均工时(分钟)", f"{stats.avg_effort_minutes:.1f}")

        console.print(table)

        if stats.by_vuln_type:
            t2 = Table(title="按漏洞类型")
            t2.add_column("类型", style="cyan")
            t2.add_column("数量", style="bold")
            for k, v in stats.by_vuln_type.items():
                t2.add_row(k, str(v))
            console.print(t2)

    asyncio.run(_run())


# ─────────────────────── test-connection 命令 ───────────────────────

@auto_pr_app.command("test-connection")
def test_connection(
    provider: str = typer.Option("gitlab", "--provider", "-p", help="Git平台: gitlab/github"),
):
    """测试Git平台连通性"""
    async def _run():
        config = _load_config()
        config.provider = provider
        adapter = create_pr_adapter(provider, config)
        try:
            ok, msg = await adapter.test_connection()
            if ok:
                console.print(f"[green]✅ {msg}[/green]")
            else:
                console.print(f"[red]❌ {msg}[/red]")
                raise typer.Exit(1)
        finally:
            await adapter.close()

    asyncio.run(_run())
