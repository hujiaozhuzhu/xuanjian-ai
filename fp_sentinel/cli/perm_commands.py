"""
企业权限管理 CLI 子命令组（xuanjian perm）

注意：本模块只暴露 perm_app = typer.Typer()，由注册方在
fp_sentinel/cli/__init__.py 中统一注册（本模块不得修改该文件）。

安全红线：
- 权限校验纯本地，零网络调用；
- 所有操作记录审计日志；
- perm:manage 权限仅管理员持有；
- 不外发用户身份信息。
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import typer
from rich.table import Table

from ..config import expand_db_path, load_config
from ..database import ProjectRepo, get_database
from ..enterprise_perm import (
    AuditResult,
    AuditAction,
    Permission,
    Role,
    ensure_perm_tables,
)
from ..enterprise_perm.permissions import PermissionChecker, PermissionDeniedError
from ..enterprise_perm.repo import AuditRepo, ProjectRoleRepo, UserRepo
from .terminal import create_console

perm_app = typer.Typer(
    name="perm",
    help="企业权限管理（三级角色/项目访问控制/审计日志）",
    add_completion=False,
    no_args_is_help=True,
)
console = create_console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


# ─────────────────────── user 命令 ───────────────────────

@perm_app.command("user-add")
def perm_user_add(
    username: str = typer.Argument(..., help="用户名"),
    role: str = typer.Option("developer", "--role", "-r", help="角色 (admin/security_engineer/developer)"),
    display_name: Optional[str] = typer.Option(None, "--name", help="显示名"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="配置文件"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """创建新用户并分配全局角色"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        try:
            _role = Role(role.lower())
        except ValueError:
            console.print(f"[red]无效角色: {role}（可选: admin/security_engineer/developer）[/red]")
            raise typer.Exit(1)

        async with get_database(db_path, config.database.wal_mode) as db:
            await ensure_perm_tables(db)
            user_repo = UserRepo(db)

            existing = await user_repo.get_by_username(username)
            if existing:
                console.print(f"[yellow]用户已存在: {username}（角色: {existing.role.value}）[/yellow]")
                return

            user = await user_repo.create(username=username, role=_role, display_name=display_name)
            console.print(f"[green]已创建用户[/green] {user.username}（ID: {user.id[:8]}...，角色: {user.role.value}）")

    asyncio.run(_run())


@perm_app.command("user-list")
def perm_user_list(
    all_users: bool = typer.Option(False, "--all", help="包含已停用用户"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """列出所有用户及其角色"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        async with get_database(db_path, config.database.wal_mode) as db:
            await ensure_perm_tables(db)
            user_repo = UserRepo(db)
            project_role_repo = ProjectRoleRepo(db)

            users = await user_repo.list_all(active_only=not all_users)
            if not users:
                console.print("[yellow]暂无用户[/yellow]")
                return

            table = Table(title="系统用户", show_lines=False)
            table.add_column("用户名", style="cyan")
            table.add_column("角色", style="magenta")
            table.add_column("状态", justify="center")
            table.add_column("项目数", justify="right")
            table.add_column("创建时间")

            for u in users:
                project_roles = await project_role_repo.get_user_projects(u.id)
                status = "[green]激活[/green]" if u.is_active else "[red]停用[/red]"
                created = u.created_at.strftime("%Y-%m-%d") if u.created_at else "-"
                table.add_row(
                    u.display_name or u.username,
                    u.role.value,
                    status,
                    str(len(project_roles)),
                    created,
                )
            console.print(table)

    asyncio.run(_run())


@perm_app.command("user-role")
def perm_user_role(
    username: str = typer.Argument(..., help="用户名"),
    new_role: str = typer.Argument(..., help="新角色 (admin/security_engineer/developer)"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """修改用户全局角色"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        try:
            _role = Role(new_role.lower())
        except ValueError:
            console.print(f"[red]无效角色: {new_role}[/red]")
            raise typer.Exit(1)

        async with get_database(db_path, config.database.wal_mode) as db:
            await ensure_perm_tables(db)
            user_repo = UserRepo(db)
            audit_repo = AuditRepo(db)

            user = await user_repo.get_by_username(username)
            if not user:
                console.print(f"[red]用户不存在: {username}[/red]")
                raise typer.Exit(1)

            old_role = user.role
            await user_repo.update_role(user.id, _role)
            await audit_repo.log(
                action=AuditAction.USER_ROLE_CHANGE.value,
                result=AuditResult.SUCCESS.value,
                user_id=user.id,
                username=user.username,
                resource_type="user",
                resource_id=user.id,
                details={"old_role": old_role.value, "new_role": _role.value},
            )
            console.print(f"[green]已更新角色[/green] {username}: {old_role.value} -> {_role.value}")

    asyncio.run(_run())


@perm_app.command("user-deactivate")
def perm_user_deactivate(
    username: str = typer.Argument(..., help="用户名"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """停用用户"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        async with get_database(db_path, config.database.wal_mode) as db:
            await ensure_perm_tables(db)
            user_repo = UserRepo(db)
            audit_repo = AuditRepo(db)

            user = await user_repo.get_by_username(username)
            if not user:
                console.print(f"[red]用户不存在: {username}[/red]")
                raise typer.Exit(1)

            await user_repo.deactivate(user.id)
            await audit_repo.log(
                action=AuditAction.USER_DELETE.value,
                result=AuditResult.SUCCESS.value,
                user_id=user.id,
                username=user.username,
                resource_type="user",
                resource_id=user.id,
                details={"action": "deactivate"},
            )
            console.print(f"[green]已停用用户[/green] {username}")

    asyncio.run(_run())


# ─────────────────────── project 命令 ───────────────────────

@perm_app.command("project-grant")
def perm_project_grant(
    username: str = typer.Argument(..., help="用户名"),
    project_id: str = typer.Argument(..., help="项目ID（来自 xuanjian projects 或 scan 的结果）"),
    role: str = typer.Option(..., "--role", "-r", help="项目角色 (admin/security_engineer/developer)"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """授予用户在某项目上的角色覆盖"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        try:
            _role = Role(role.lower())
        except ValueError:
            console.print(f"[red]无效角色: {role}[/red]")
            raise typer.Exit(1)

        async with get_database(db_path, config.database.wal_mode) as db:
            await ensure_perm_tables(db)
            user_repo = UserRepo(db)
            project_role_repo = ProjectRoleRepo(db)
            audit_repo = AuditRepo(db)

            user = await user_repo.get_by_username(username)
            if not user:
                console.print(f"[red]用户不存在: {username}[/red]")
                raise typer.Exit(1)

            await project_role_repo.grant(
                user_id=user.id,
                project_id=project_id,
                role=_role,
            )
            await audit_repo.log(
                action=AuditAction.PROJECT_GRANT.value,
                result=AuditResult.SUCCESS.value,
                user_id=user.id,
                username=user.username,
                resource_type="project_role",
                resource_id=project_id,
                details={"role": _role.value},
            )
            console.print(f"[green]已授权[/green] {username} 在项目 {project_id[:8]}... 上角色 {_role.value}")

    asyncio.run(_run())


@perm_app.command("project-revoke")
def perm_project_revoke(
    username: str = typer.Argument(..., help="用户名"),
    project_id: str = typer.Argument(..., help="项目ID"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """撤销用户在某项目上的角色覆盖"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        async with get_database(db_path, config.database.wal_mode) as db:
            await ensure_perm_tables(db)
            user_repo = UserRepo(db)
            project_role_repo = ProjectRoleRepo(db)
            audit_repo = AuditRepo(db)

            user = await user_repo.get_by_username(username)
            if not user:
                console.print(f"[red]用户不存在: {username}[/red]")
                raise typer.Exit(1)

            revoked = await project_role_repo.revoke(user_id=user.id, project_id=project_id)
            if revoked:
                await audit_repo.log(
                    action=AuditAction.PROJECT_REVOKE.value,
                    result=AuditResult.SUCCESS.value,
                    user_id=user.id,
                    username=user.username,
                    resource_type="project_role",
                    resource_id=project_id,
                )
                console.print(f"[green]已撤销[/green] {username} 在项目 {project_id[:8]}... 的角色")
            else:
                console.print("[yellow]该用户无此项目角色覆盖[/yellow]")

    asyncio.run(_run())


# ─────────────────────── check 命令 ───────────────────────

@perm_app.command("check")
def perm_check(
    username: str = typer.Argument(..., help="用户名"),
    permission: str = typer.Option(..., "--perm", help="权限 (如 scan:run)"),
    project_id: Optional[str] = typer.Option(None, "--project", help="项目ID（可选）"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """检查用户是否拥有某权限（调试用）"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        try:
            _perm = Permission(permission)
        except ValueError:
            console.print(f"[red]无效权限: {permission}[/red]")
            raise typer.Exit(1)

        async with get_database(db_path, config.database.wal_mode) as db:
            await ensure_perm_tables(db)
            user_repo = UserRepo(db)
            checker = PermissionChecker(db)

            user = await user_repo.get_by_username(username)
            if not user:
                console.print(f"[red]用户不存在: {username}[/red]")
                raise typer.Exit(1)

            result = await checker.check(user.id, _perm, project_id, log_allowed=True)
            status = "[green]允许[/green]" if result.allowed else "[red]拒绝[/red]"
            console.print(f"用户: {username}  权限: {_perm.value}  结果: {status}")
            console.print(f"  角色: {result.role.value if result.role else "无"}  来源: {result.source}")

    asyncio.run(_run())


# ─────────────────────── audit 命令 ───────────────────────

@perm_app.command("audit")
def perm_audit(
    username: Optional[str] = typer.Option(None, "--user", help="按用户名过滤"),
    action_filter: Optional[str] = typer.Option(None, "--action", help="按操作类型过滤"),
    show_denied: bool = typer.Option(False, "--denied", help="仅显示拒绝的记录"),
    limit: int = typer.Option(20, "--limit", "-n", help="显示条数"),
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """查看审计日志"""

    async def _run():
        _setup_logging(verbose)
        config = load_config(config_file)
        db_path = expand_db_path(config.database.path)

        async with get_database(db_path, config.database.wal_mode) as db:
            await ensure_perm_tables(db)
            user_repo = UserRepo(db)
            audit_repo = AuditRepo(db)

            # 解析用户过滤
            user_id = None
            if username:
                user = await user_repo.get_by_username(username)
                if user:
                    user_id = user.id

            result_filter = AuditResult.DENIED.value if show_denied else None
            entries = await audit_repo.list_entries(
                user_id=user_id,
                action=action_filter,
                result_filter=result_filter,
                limit=limit,
            )

            if not entries:
                console.print("[yellow]暂无审计记录[/yellow]")
                return

            table = Table(title="审计日志", show_lines=False)
            table.add_column("时间", style="dim", max_width=20)
            table.add_column("用户", max_width=16)
            table.add_column("操作", max_width=20)
            table.add_column("结果", max_width=10)
            table.add_column("资源", max_width=20)
            table.add_column("详情", max_width=40)

            for e in entries:
                ts = e.timestamp.strftime("%m-%d %H:%M:%S") if e.timestamp else "-"
                result_style = "[green]allowed[/green]" if e.result == "allowed" else ("[red]denied[/red]" if e.result == "denied" else e.result)
                table.add_row(
                    ts,
                    e.username or "-",
                    e.action,
                    result_style,
                    f"{e.resource_type}:{e.resource_id}" if e.resource_type else "-",
                    (e.details or "")[:40],
                )
            console.print(table)

    asyncio.run(_run())


# ─────────────────────── roles 命令 ───────────────────────

@perm_app.command("roles")
def perm_roles(
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """查看所有角色及其权限矩阵"""

    from ..enterprise_perm.models import ROLE_PERMISSIONS

    console.print("[bold]三级角色权限矩阵[/bold]\n")

    table = Table(show_lines=False)
    table.add_column("角色", style="cyan")
    table.add_column("权限列表", max_width=80)
    table.add_column("权限数", justify="right")

    for _role in Role:
        perms = ROLE_PERMISSIONS.get(_role, set())
        perm_strs = sorted(p.value for p in perms)
        table.add_row(
            _role.value,
            ", ".join(perm_strs),
            str(len(perms)),
        )
    console.print(table)
