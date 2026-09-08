"""
DevSecOps - CLI commands

Subcommands:
- sync: sync findings to issues
- gate: evaluate pipeline gate
- close: close ticket
- link: link fix commit
- status: list mappings
- stats: module statistics
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table

from ..database.connection import get_database
from .models import (
    DevOpsConfig,
    DevOpsProvider,
    FindingRef,
    SyncFindingsRequest,
    TicketCloseRequest,
    TicketLinkRequest,
    PipelineGateRequest,
)
from .pipeline_gate import evaluate_gate, format_gate_output, gate_exit_code
from .repository import FindingTicketMappingRepo, PipelineGateRecordRepo, SyncRecordRepo
from .service import DevOpsService

logger = logging.getLogger(__name__)
console = Console()

devops_app = typer.Typer(
    name="devops",
    help="DevSecOps: GitLab/Jira/GitHub sync, pipeline gate, ticket linkage",
    add_completion=False,
)


def _load_config() -> DevOpsConfig:
    import os
    return DevOpsConfig(
        provider=DevOpsProvider(os.environ.get("XUANJIAN_DEVOPS_PROVIDER", "gitlab")),
        base_url=os.environ.get("XUANJIAN_DEVOPS_BASE_URL", ""),
        api_token=os.environ.get("XUANJIAN_DEVOPS_API_TOKEN", ""),
        project_id=os.environ.get("XUANJIAN_DEVOPS_PROJECT_ID", ""),
        jira_project_key=os.environ.get("XUANJIAN_DEVOPS_JIRA_KEY", ""),
    )


def _load_findings_from_json(json_path: str) -> List[FindingRef]:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return [FindingRef(**item) if isinstance(item, dict) else FindingRef(id=str(item)) for item in data]
    return []


def _get_service() -> DevOpsService:
    db = get_database()
    mapping_repo = FindingTicketMappingRepo(db.conn)
    sync_repo = SyncRecordRepo(db.conn)
    gate_repo = PipelineGateRecordRepo(db.conn)
    return DevOpsService(mapping_repo, sync_repo, gate_repo)


@devops_app.command("sync")
def sync_findings(
    provider: str = typer.Option(..., "--provider", "-p", help="Platform: gitlab/jira/github"),
    project_id: str = typer.Option(..., "--project-id", help="Project ID"),
    findings_json: str = typer.Option(..., "--findings-json", "-f", help="Findings JSON file"),
    repository_url: str = typer.Option("", "--repo", help="Repository URL"),
    commit_hash: str = typer.Option("", "--commit", help="Commit hash"),
    branch: str = typer.Option("", "--branch", help="Branch name"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Dry run only"),
):
    """Sync findings to external issues/tickets"""
    async def _run():
        findings = _load_findings_from_json(findings_json)
        if not findings:
            console.print("[yellow]No findings to sync[/yellow]")
            return
        config = _load_config()
        config.project_id = project_id
        async with get_database() as db:
            service = _get_service()
            request = SyncFindingsRequest(
                provider=DevOpsProvider(provider),
                project_id=project_id,
                findings=findings,
                repository_url=repository_url,
                commit_hash=commit_hash,
                branch=branch,
                config=config,
                dry_run=dry_run,
            )
            result = await service.sync_findings(request)
            console.print(f"[bold]Sync result:[/bold]")
            console.print(f"  Status: {result.status.value}")
            console.print(f"  Total: {result.total_findings}")
            console.print(f"  Created: {result.created_count}")
            console.print(f"  Skipped: {result.skipped_count}")
            console.print(f"  Failed: {result.failed_count}")
            if result.errors:
                for err in result.errors[:5]:
                    console.print(f"  [red]ERROR:[/red] {err}")
    asyncio.run(_run())


@devops_app.command("gate")
def pipeline_gate(
    provider: str = typer.Option(..., "--provider", "-p", help="Platform: gitlab/jira/github"),
    project_id: str = typer.Option(..., "--project-id", help="Project ID"),
    findings_json: str = typer.Option(..., "--findings-json", "-f", help="Findings JSON file"),
    commit_hash: str = typer.Option("", "--commit", help="Commit hash"),
    branch: str = typer.Option("", "--branch", help="Branch name"),
    output_format: str = typer.Option("text", "--format", help="Output format: text/json"),
):
    """Evaluate pipeline security gate"""
    findings = _load_findings_from_json(findings_json)
    request = PipelineGateRequest(
        provider=DevOpsProvider(provider),
        project_id=project_id,
        commit_hash=commit_hash,
        branch=branch,
        findings=findings,
    )
    result = evaluate_gate(request)
    output = format_gate_output(result, output_format)
    console.print(output)
    exit_code = gate_exit_code(result)
    raise typer.Exit(code=exit_code)


@devops_app.command("close")
def close_ticket(
    provider: str = typer.Option(..., "--provider", "-p", help="Platform: gitlab/jira/github"),
    ticket_id: str = typer.Option(..., "--ticket-id", help="Ticket ID"),
    comment: str = typer.Option("", "--comment", help="Close comment"),
    commit_hash: str = typer.Option("", "--commit", help="Fix commit hash"),
    resolution: str = typer.Option("fixed", "--resolution", help="Resolution"),
):
    """Close external ticket"""
    async def _run():
        config = _load_config()
        async with get_database() as db:
            service = _get_service()
            request = TicketCloseRequest(
                provider=DevOpsProvider(provider),
                ticket_id=ticket_id,
                resolution=resolution,
                comment=comment,
                commit_hash=commit_hash,
            )
            record = await service.close_ticket(request)
            if record.status.value == "synced":
                console.print(f"[green]Ticket {ticket_id} closed[/green]")
            else:
                console.print(f"[red]Close failed: {record.error_message}[/red]")
                raise typer.Exit(1)
    asyncio.run(_run())


@devops_app.command("link")
def link_commit(
    provider: str = typer.Option(..., "--provider", "-p", help="Platform: gitlab/jira/github"),
    ticket_id: str = typer.Option(..., "--ticket-id", help="Ticket ID"),
    commit_hash: str = typer.Option(..., "--commit", help="Fix commit hash"),
    branch: str = typer.Option("", "--branch", help="Branch"),
    comment: str = typer.Option("", "--comment", help="Comment"),
    no_close: bool = typer.Option(False, "--no-close", help="Do not close after link"),
):
    """Link fix commit to ticket"""
    async def _run():
        config = _load_config()
        async with get_database() as db:
            service = _get_service()
            request = TicketLinkRequest(
                provider=DevOpsProvider(provider),
                ticket_id=ticket_id,
                commit_hash=commit_hash,
                branch=branch,
                comment=comment,
                close_after_link=not no_close,
            )
            record = await service.link_fix_commit(request)
            if record.status.value == "synced":
                console.print(f"[green]Linked commit {commit_hash[:10]} to ticket {ticket_id}[/green]")
            else:
                console.print(f"[red]Link failed: {record.error_message}[/red]")
                raise typer.Exit(1)
    asyncio.run(_run())


@devops_app.command("status")
def list_mappings(
    provider: Optional[str] = typer.Option(None, "--provider", help="Filter by platform"),
    ticket_status: Optional[str] = typer.Option(None, "--status", help="Filter by status"),
    limit: int = typer.Option(20, "--limit", help="Max rows"),
):
    """List finding-ticket mappings"""
    async def _run():
        async with get_database() as db:
            repo = FindingTicketMappingRepo(db.conn)
            mappings = await repo.list_mappings(
                provider=provider,
                ticket_status=ticket_status,
                limit=limit,
            )
            if not mappings:
                console.print("[dim]No mappings[/dim]")
                return
            table = Table(title="DevOps Ticket Mappings")
            table.add_column("ID", style="dim", width=8)
            table.add_column("Provider", style="cyan")
            table.add_column("Finding", style="yellow")
            table.add_column("Ticket", style="green")
            table.add_column("Status", style="bold")
            table.add_column("Severity", style="red")
            for m in mappings:
                table.add_row(
                    m.id[:8], m.provider.value, m.finding_id[:12],
                    m.ticket_key or m.ticket_id[:12],
                    m.ticket_status.value, m.severity,
                )
            console.print(table)
    asyncio.run(_run())


@devops_app.command("stats")
def show_stats():
    """DevOps module statistics"""
    async def _run():
        async with get_database() as db:
            service = _get_service()
            stats = await service.get_stats()
            table = Table(title="DevOps Statistics")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="bold")
            table.add_row("Total mappings", str(stats.total_mappings))
            table.add_row("Open tickets", str(stats.open_tickets))
            table.add_row("Resolved tickets", str(stats.resolved_tickets))
            table.add_row("Closed tickets", str(stats.closed_tickets))
            table.add_row("In-progress tickets", str(stats.in_progress_tickets))
            table.add_row("Total syncs", str(stats.total_syncs))
            table.add_row("Successful syncs", str(stats.successful_syncs))
            table.add_row("Failed syncs", str(stats.failed_syncs))
            table.add_row("Pending syncs", str(stats.pending_syncs))
            table.add_row("By provider", ", ".join(f"{k}:{v}" for k, v in stats.by_provider.items()))
            console.print(table)
    asyncio.run(_run())
