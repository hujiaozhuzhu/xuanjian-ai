"""
企业任务管理 - CLI 命令

提供 fp-sentinel task 子命令组，支持：
- task create    : 创建任务
- task list      : 查询任务列表
- task show      : 查看任务详情 + 流转记录
- task assign    : 分配任务
- task start     : 开始处理
- task submit    : 提交修复
- task review    : 评审修复
- task cancel    : 取消任务
- task stats     : 任务进度统计
- task comment   : 添加评论

安全红线：S2 不修改代码（fix_diff 仅展示），S7 数据落 ~/.xuanjian/
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional, List

import typer
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.console import Console

from ..config import load_config, expand_db_path
from ..database import get_database
from .models import (
    BulkCreateRequest,
    ReviewVerdict,
    TaskPriority,
    TaskQueryParams,
    TaskReviewRequest,
    TaskStatus,
    TaskType,
)
from .repository import TaskCommentRepo, TaskRepo, TaskTransitionRepo
from .service import (
    InvalidTransitionError,
    PermissionDeniedError,
    TaskError,
    TaskNotFoundError,
    TaskService,
)

logger = logging.getLogger(__name__)
console = Console()

task_app = typer.Typer(
    name="task",
    help="企业任务管理 — 扫描任务分配、漏洞修复跟踪、修复结果评审",
    add_completion=False,
)


def _build_service(config_file: Optional[str] = None) -> tuple:
    """构建 TaskService 并加载配置（同步辅助）"""
    config = load_config(config_file)
    db_path = expand_db_path(config.database.path)
    return config, db_path


# ─────────────────────── create ───────────────────────

@task_app.command("create")
def task_create(
    project_id: str = typer.Argument(..., help="项目 ID"),
    title: str = typer.Argument(..., help="任务标题"),
    task_type: str = typer.Option("scan", "--type", "-t", help="任务类型 (scan/vuln_fix/fix_review/retest)"),
    description: str = typer.Option("", "--desc", help="任务描述"),
    priority: str = typer.Option("P2", "--priority", "-p", help="优先级 (P0/P1/P2/P3)"),
    assigned_to: Optional[str] = typer.Option(None, "--assign-to", help="被指派人"),
    assigned_by: Optional[str] = typer.Option(None, "--assign-by", help="分配人"),
    finding_id: Optional[str] = typer.Option(None, "--finding-id", help="关联 Finding ID"),
    finding_rule_id: Optional[str] = typer.Option(None, "--rule-id", help="关联规则 ID"),
    finding_severity: Optional[str] = typer.Option(None, "--severity", help="关联 Finding 严重度"),
    finding_file_path: Optional[str] = typer.Option(None, "--file", help="关联文件路径"),
    finding_line: Optional[int] = typer.Option(None, "--line", help="关联行号"),
    due_date: Optional[str] = typer.Option(None, "--due", help="截止日期 ISO8601"),
    tags: Optional[str] = typer.Option(None, "--tags", help="标签 (逗号分隔)"),
    project_name: str = typer.Option("", "--project-name", help="项目名称"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """创建扫描/修复任务"""
    async def _run():
        _, db_path = _build_service(config_file)
        async with get_database(db_path) as db:
            repo = TaskRepo(db.conn)
            repo.initialize_schema()
            service = TaskService(repo, TaskTransitionRepo(db.conn), TaskCommentRepo(db.conn))

            try:
                tt = TaskType(task_type)
            except ValueError:
                console.print(f"[red]未知任务类型: {task_type}（可选 scan/vuln_fix/fix_review/retest）[/red]")
                raise typer.Exit(1)

            try:
                pri = TaskPriority(priority)
            except ValueError:
                console.print(f"[red]未知优先级: {priority}（可选 P0/P1/P2/P3）[/red]")
                raise typer.Exit(1)

            tag_list = [t.strip() for t in tags.split(",")] if tags else []

            task = await service.create_task(
                project_id=project_id,
                title=title,
                task_type=tt,
                description=description,
                priority=pri,
                finding_id=finding_id,
                finding_rule_id=finding_rule_id,
                finding_severity=finding_severity,
                finding_file_path=finding_file_path,
                finding_line_start=finding_line,
                assigned_to=assigned_to,
                assigned_by=assigned_by,
                due_date=due_date,
                tags=tag_list,
                project_name=project_name,
            )
            console.print(
                f"[green]✓ 任务已创建[/green]\n"
                f"  ID       : {task.id}\n"
                f"  类型     : {task.task_type.value}\n"
                f"  状态     : {task.status.value}\n"
                f"  优先级   : {task.priority.value}\n"
                f"  指派人   : {task.assigned_to or '未分配'}"
            )
    asyncio.run(_run())


# ─────────────────────── bulk-create ───────────────────────

@task_app.command("bulk-create")
def task_bulk_create(
    project_id: str = typer.Argument(..., help="项目 ID"),
    finding_ids: str = typer.Argument(..., help="Finding ID 列表 (逗号分隔)"),
    priority: str = typer.Option("P2", "--priority", "-p", help="优先级 (P0/P1/P2/P3)"),
    assigned_to: Optional[str] = typer.Option(None, "--assign-to", help="初始指派人"),
    assigned_by: Optional[str] = typer.Option(None, "--assign-by", help="分配人"),
    due_date: Optional[str] = typer.Option(None, "--due", help="截止日期 ISO8601"),
    tags: Optional[str] = typer.Option(None, "--tags", help="标签 (逗号分隔)"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """从扫描发现批量创建修复任务"""
    async def _run():
        _, db_path = _build_service(config_file)
        async with get_database(db_path) as db:
            repo = TaskRepo(db.conn)
            repo.initialize_schema()
            service = TaskService(repo, TaskTransitionRepo(db.conn), TaskCommentRepo(db.conn))

            try:
                pri = TaskPriority(priority)
            except ValueError:
                console.print(f"[red]未知优先级: {priority}[/red]")
                raise typer.Exit(1)

            fid_list = [f.strip() for f in finding_ids.split(",") if f.strip()]
            tag_list = [t.strip() for t in tags.split(",")] if tags else []
            request = BulkCreateRequest(
                project_id=project_id,
                finding_ids=fid_list,
                priority=pri,
                assigned_to=assigned_to,
                assigned_by=assigned_by,
                due_date=due_date,
                tags=tag_list,
            )

            count, tasks = await service.bulk_create_from_findings(request)
            skipped = len(fid_list) - count
            console.print(
                f"[green]✓ 批量创建完成[/green]\n"
                f"  创建     : {count}\n"
                f"  跳过     : {skipped}（已有未完成任务）"
            )
    asyncio.run(_run())


# ─────────────────────── list ───────────────────────

@task_app.command("list")
def task_list(
    project_id: Optional[str] = typer.Option(None, "--project", help="按项目过滤"),
    status: Optional[str] = typer.Option(None, "--status", help="按状态过滤"),
    task_type: Optional[str] = typer.Option(None, "--type", "-t", help="按类型过滤"),
    priority: Optional[str] = typer.Option(None, "--priority", "-p", help="按优先级过滤"),
    assigned_to: Optional[str] = typer.Option(None, "--assignee", help="按指派人过滤"),
    severity: Optional[str] = typer.Option(None, "--severity", help="按严重度过滤"),
    limit: int = typer.Option(50, "--limit", "-n", help="显示数量"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """查询任务列表"""
    async def _run():
        _, db_path = _build_service(config_file)
        async with get_database(db_path) as db:
            repo = TaskRepo(db.conn)
            repo.initialize_schema()
            service = TaskService(repo, TaskTransitionRepo(db.conn), TaskCommentRepo(db.conn))

            params = TaskQueryParams(limit=limit, offset=0)
            if project_id:
                params.project_id = project_id
            if status:
                try:
                    params.status = TaskStatus(status)
                except ValueError:
                    console.print(f"[red]未知状态: {status}[/red]")
                    raise typer.Exit(1)
            if task_type:
                try:
                    params.task_type = TaskType(task_type)
                except ValueError:
                    console.print(f"[red]未知类型: {task_type}[/red]")
                    raise typer.Exit(1)
            if priority:
                try:
                    params.priority = TaskPriority(priority)
                except ValueError:
                    console.print(f"[red]未知优先级: {priority}[/red]")
                    raise typer.Exit(1)
            if assigned_to:
                params.assigned_to = assigned_to
            if severity:
                params.finding_severity = severity

            tasks = await service.list_tasks(params)
            if not tasks:
                console.print("[yellow]未找到匹配的任务[/yellow]")
                return

            table = Table(title="任务列表", box=box.ROUNDED, show_lines=True)
            table.add_column("ID", style="dim", max_width=12)
            table.add_column("类型", max_width=10)
            table.add_column("状态", max_width=12)
            table.add_column("优先级", justify="center")
            table.add_column("指派人", max_width=15)
            table.add_column("标题", max_width=40)
            table.add_column("创建时间", max_width=20)

            for t in tasks:
                table.add_row(
                    t.id[:8],
                    t.task_type.value,
                    t.status.value,
                    t.priority.value,
                    t.assigned_to or "-",
                    t.title[:38],
                    t.created_at[:19],
                )
            console.print(table)

    asyncio.run(_run())


# ─────────────────────── show ───────────────────────

@task_app.command("show")
def task_show(
    task_id: str = typer.Argument(..., help="任务 ID"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """查看任务详情 + 流转时间线"""
    async def _run():
        _, db_path = _build_service(config_file)
        async with get_database(db_path) as db:
            repo = TaskRepo(db.conn)
            repo.initialize_schema()
            service = TaskService(repo, TaskTransitionRepo(db.conn), TaskCommentRepo(db.conn))

            try:
                timeline = await service.get_task_timeline(task_id)
            except TaskNotFoundError:
                console.print(f"[red]任务不存在: {task_id}[/red]")
                raise typer.Exit(1)

            task_data = timeline["task"]
            transitions_data = timeline["transitions"]
            comments_data = timeline["comments"]

            # 详情面板
            lines = [
                f"[bold]ID[/bold]         : {task_data['id']}",
                f"[bold]项目[/bold]       : {task_data.get('project_name', '')} ({task_data['project_id'][:8]})",
                f"[bold]类型[/bold]       : {task_data['task_type']}",
                f"[bold]状态[/bold]       : {task_data['status']}",
                f"[bold]优先级[/bold]     : {task_data['priority']}",
                f"[bold]指派人[/bold]     : {task_data.get('assigned_to', '未分配')}",
                f"[bold]标题[/bold]       : {task_data['title']}",
            ]
            if task_data.get('description'):
                lines.append(f"[bold]描述[/bold]       : {task_data['description']}")
            if task_data.get('finding_id'):
                lines.append(f"[bold]关联 Finding[/bold]: {task_data['finding_id']}")
            if task_data.get('fix_diff'):
                lines.append(f"[bold]修复 Diff[/bold]  : [dim]{task_data['fix_diff'][:200]}...[/dim]")
            if task_data.get('review_verdict'):
                lines.append(f"[bold]评审结论[/bold]   : {task_data['review_verdict']}")
            if task_data.get('review_comment'):
                lines.append(f"[bold]评审意见[/bold]   : {task_data['review_comment']}")

            panel = Panel("\n".join(lines), title="任务详情", border_style="cyan")
            console.print(panel)

            # 流转记录
            if transitions_data:
                t_table = Table(title="状态流转", box.ROUNDED, show_lines=False)
                t_table.add_column("时间", max_width=20)
                t_table.add_column("变更", max_width=30)
                t_table.add_column("操作人", max_width=15)
                t_table.add_column("备注", max_width=30)
                for tr in transitions_data:
                    f = tr.get("from_status") or "(创建)"
                    tg = tr["to_status"]
                    t_table.add_row(
                        tr["created_at"][:19],
                        f"{f} -> {tg}",
                        tr.get("operator", "-"),
                        tr.get("comment") or "",
                    )
                console.print(t_table)

            # 评论
            if comments_data:
                c_table = Table(title="评论", box.ROUNDED, show_lines=False)
                c_table.add_column("时间", max_width=20)
                c_table.add_column("作者", max_width=15)
                c_table.add_column("内容", max_width=60)
                for c in comments_data:
                    c_table.add_row(c["created_at"][:19], c.get("author", "-"), c["content"])
                console.print(c_table)

    asyncio.run(_run())


# ─────────────────────── assign ───────────────────────

@task_app.command("assign")
def task_assign(
    task_id: str = typer.Argument(..., help="任务 ID"),
    assignee: str = typer.Argument(..., help="被指派人"),
    assigner: str = typer.Option("", "--by", help="分配人"),
    comment: Optional[str] = typer.Option(None, "--comment", "-m", help="备注"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """分配任务"""
    async def _run():
        _, db_path = _build_service(config_file)
        async with get_database(db_path) as db:
            repo = TaskRepo(db.conn)
            repo.initialize_schema()
            service = TaskService(repo, TaskTransitionRepo(db.conn), TaskCommentRepo(db.conn))

            from .models import TaskAssignmentRequest
            req = TaskAssignmentRequest(
                task_id=task_id,
                assigned_to=assignee,
                assigned_by=assigner,
                comment=comment,
            )
            try:
                task = await service.assign_task(req)
            except TaskNotFoundError:
                console.print(f"[red]任务不存在: {task_id}[/red]")
                raise typer.Exit(1)
            except TaskError as e:
                console.print(f"[red]{e.message}[/red]")
                raise typer.Exit(1)

            console.print(f"[green]✓ 任务已分配给 {assignee}[/green]  当前状态: {task.status.value}")
    asyncio.run(_run())


# ─────────────────────── start ───────────────────────

@task_app.command("start")
def task_start(
    task_id: str = typer.Argument(..., help="任务 ID"),
    operator: str = typer.Option("", "--by", help="操作人"),
    comment: Optional[str] = typer.Option(None, "--comment", "-m"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """开始处理任务"""
    async def _run():
        _, db_path = _build_service(config_file)
        async with get_database(db_path) as db:
            repo = TaskRepo(db.conn)
            repo.initialize_schema()
            service = TaskService(repo, TaskTransitionRepo(db.conn), TaskCommentRepo(db.conn))

            try:
                task = await service.start_progress(task_id, operator, comment)
            except (TaskNotFoundError, InvalidTransitionError, PermissionDeniedError, TaskError) as e:
                console.print(f"[red]{e.message if hasattr(e, 'message') else str(e)}[/red]")
                raise typer.Exit(1)
            console.print(f"[green]✓ 任务已开始处理[/green]  当前状态: {task.status.value}")
    asyncio.run(_run())


# ─────────────────────── submit ───────────────────────

@task_app.command("submit")
def task_submit(
    task_id: str = typer.Argument(..., help="任务 ID"),
    fix_diff: str = typer.Option(..., "--diff", help="修复 diff 字符串（仅展示，不修改代码）"),
    operator: str = typer.Option("", "--by", help="操作人"),
    commit_hash: Optional[str] = typer.Option(None, "--commit", help="修复提交 hash"),
    notes: Optional[str] = typer.Option(None, "--notes", help="修复备注"),
    comment: Optional[str] = typer.Option(None, "--comment", "-m"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """提交修复"""
    async def _run():
        _, db_path = _build_service(config_file)
        async with get_database(db_path) as db:
            repo = TaskRepo(db.conn)
            repo.initialize_schema()
            service = TaskService(repo, TaskTransitionRepo(db.conn), TaskCommentRepo(db.conn))

            try:
                task = await service.submit_fix(
                    task_id=task_id,
                    fix_diff=fix_diff,
                    operator=operator,
                    fix_commit_hash=commit_hash,
                    fix_notes=notes,
                    comment=comment,
                )
            except (TaskNotFoundError, InvalidTransitionError, PermissionDeniedError, TaskError) as e:
                console.print(f"[red]{e.message if hasattr(e, 'message') else str(e)}[/red]")
                raise typer.Exit(1)
            console.print(f"[green]✓ 修复已提交[/green]  当前状态: {task.status.value}")
    asyncio.run(_run())


# ─────────────────────── review ───────────────────────

@task_app.command("review")
def task_review(
    task_id: str = typer.Argument(..., help="任务 ID"),
    verdict: str = typer.Argument(..., help="评审结论 (pass/needs_work/reject)"),
    reviewer: str = typer.Option("", "--by", help="评审人"),
    comment: Optional[str] = typer.Option(None, "--comment", "-m", help="评审意见"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """评审修复结果"""
    async def _run():
        _, db_path = _build_service(config_file)
        async with get_database(db_path) as db:
            repo = TaskRepo(db.conn)
            repo.initialize_schema()
            service = TaskService(repo, TaskTransitionRepo(db.conn), TaskCommentRepo(db.conn))

            try:
                rv = ReviewVerdict(verdict)
            except ValueError:
                console.print(f"[red]未知评审结论: {verdict}（可选 pass/needs_work/reject）[/red]")
                raise typer.Exit(1)

            req = TaskReviewRequest(
                task_id=task_id,
                verdict=rv,
                reviewer=reviewer,
                comment=comment,
            )
            try:
                task = await service.review_task(req)
            except (TaskNotFoundError, TaskError) as e:
                console.print(f"[red]{e.message}[/red]")
                raise typer.Exit(1)

            status_label = "通过" if task.status == TaskStatus.DONE else "需修改"
            console.print(f"[green]✓ 评审完成[/green]  结论: {verdict} → {status_label}  当前状态: {task.status.value}")
    asyncio.run(_run())


# ─────────────────────── cancel ───────────────────────

@task_app.command("cancel")
def task_cancel(
    task_id: str = typer.Argument(..., help="任务 ID"),
    operator: str = typer.Option("", "--by", help="操作人"),
    operator_role: str = typer.Option("manager", "--role", help="操作人角色"),
    comment: Optional[str] = typer.Option(None, "--comment", "-m"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """取消任务"""
    async def _run():
        _, db_path = _build_service(config_file)
        async with get_database(db_path) as db:
            repo = TaskRepo(db.conn)
            repo.initialize_schema()
            service = TaskService(repo, TaskTransitionRepo(db.conn), TaskCommentRepo(db.conn))

            try:
                task = await service.cancel_task(task_id, operator, operator_role, comment)
            except (TaskNotFoundError, InvalidTransitionError, PermissionDeniedError, TaskError) as e:
                console.print(f"[red]{e.message if hasattr(e, 'message') else str(e)}[/red]")
                raise typer.Exit(1)
            console.print(f"[yellow]✓ 任务已取消[/yellow]  当前状态: {task.status.value}")
    asyncio.run(_run())


# ─────────────────────── comment ───────────────────────

@task_app.command("comment")
def task_comment(
    task_id: str = typer.Argument(..., help="任务 ID"),
    content: str = typer.Argument(..., help="评论内容"),
    author: Optional[str] = typer.Option(None, "--by", help="评论人"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """添加任务评论"""
    async def _run():
        _, db_path = _build_service(config_file)
        async with get_database(db_path) as db:
            repo = TaskRepo(db.conn)
            repo.initialize_schema()
            service = TaskService(repo, TaskTransitionRepo(db.conn), TaskCommentRepo(db.conn))

            try:
                cmt = await service.add_comment(task_id, content, author)
            except TaskNotFoundError:
                console.print(f"[red]任务不存在: {task_id}[/red]")
                raise typer.Exit(1)
            console.print(f"[green]✓ 评论已添加[/green]  时间: {cmt.created_at[:19]}")
    asyncio.run(_run())


# ─────────────────────── stats ───────────────────────

@task_app.command("stats")
def task_stats(
    project_id: Optional[str] = typer.Option(None, "--project", help="项目 ID (不填则全局)"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """任务进度统计"""
    async def _run():
        _, db_path = _build_service(config_file)
        async with get_database(db_path) as db:
            repo = TaskRepo(db.conn)
            repo.initialize_schema()
            service = TaskService(repo, TaskTransitionRepo(db.conn), TaskCommentRepo(db.conn))

            stats = await service.get_stats(project_id)

            lines = [
                f"[bold]总任务数[/bold]     : {stats.total_tasks}",
                f"[bold]已完成[/bold]       : {stats.done_count}",
                f"[bold]已取消[/bold]       : {stats.cancelled_count}",
                f"[bold]逾期[/bold]         : {stats.overdue_count}",
                f"[bold]完成率[/bold]       : {stats.completion_rate * 100:.1f}%",
                f"[bold]平均解决耗时[/bold] : {stats.avg_resolution_hours:.1f}h",
                "",
                "[bold]按状态:[/bold]",
            ]
            for s in ("pending", "assigned", "in_progress", "fix_submitted", "under_review", "done", "cancelled"):
                cnt = stats.by_status.get(s, 0)
                lines.append(f"  {s:<15} {cnt}")

            if stats.by_priority:
                lines.append("\n[bold]按优先级:[/bold]")
                for p in ("P0", "P1", "P2", "P3"):
                    cnt = stats.by_priority.get(p, 0)
                    lines.append(f"  {p:<5} {cnt}")

            if stats.by_assignee:
                lines.append("\n[bold]按指派人:[/bold]")
                for a, cnt in sorted(stats.by_assignee.items(), key=lambda x: -x[1]):
                    lines.append(f"  {a:<20} {cnt}")

            panel = Panel(
                "\n".join(lines),
                title=f"📊 任务统计 ({stats.project_name or '全局'})",
                border_style="cyan",
            )
            console.print(panel)

    asyncio.run(_run())


# ─────────────────────── transitions ───────────────────────

@task_app.command("transitions")
def task_transitions(
    task_id: str = typer.Argument(..., help="任务 ID"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """查看任务状态流转记录"""
    async def _run():
        _, db_path = _build_service(config_file)
        async with get_database(db_path) as db:
            repo = TaskRepo(db.conn)
            repo.initialize_schema()
            service = TaskService(repo, TaskTransitionRepo(db.conn), TaskCommentRepo(db.conn))

            transitions = await service.get_task_transitions(task_id)
            if not transitions:
                console.print("[yellow]暂无流转记录[/yellow]")
                return

            table = Table(title=f"状态流转 — {task_id[:8]}", box=box.ROUNDED, show_lines=True)
            table.add_column("#", justify="right", max_width=5)
            table.add_column("时间", max_width=20)
            table.add_column("变更", max_width=35)
            table.add_column("操作人", max_width=15)
            table.add_column("角色", max_width=10)
            table.add_column("备注", max_width=30)

            for i, tr in enumerate(transitions, 1):
                f = tr.from_status or "(创建)"
                table.add_row(
                    str(i),
                    tr.created_at[:19],
                    f"{f} -> {tr.to_status}",
                    tr.operator or "-",
                    tr.operator_role or "-",
                    tr.comment or "",
                )
            console.print(table)

    asyncio.run(_run())


# ─────────────────────── flow ───────────────────────

@task_app.command("flow")
def task_flow(
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """显示状态流转图（所有合法路径）"""
    from .models import VALID_TRANSITIONS
    console.print("\n[bold]任务状态流转图[/bold]\n")
    lines = []
    for from_s, to_list in VALID_TRANSITIONS.items():
        if to_list:
            targets = ", ".join(s.value for s in to_list)
            lines.append(f"  {from_s.value:<15} -> [{targets}]")
        else:
            lines.append(f"  {from_s.value:<15} -> [终态]")
    panel = Panel("\n".join(lines), border_style="cyan")
    console.print(panel)
