"""
fp-sentinel notify 子命令 - 企业通知管理 CLI

命令:
    fp-sentinel notify channel add    - 添加通知渠道
    fp-sentinel notify channel list   - 列出通知渠道
    fp-sentinel notify channel test   - 测试渠道连通性
    fp-sentinel notify channel delete - 删除通知渠道
    fp-sentinel notify rule add       - 添加推送规则
    fp-sentinel notify rule list      - 列出推送规则
    fp-sentinel notify rule delete    - 删除推送规则
    fp-sentinel notify send           - 手动发送一条通知(测试用)
    fp-sentinel notify history        - 查看推送历史
    fp-sentinel notify stats          - 查看通知统计
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table
from rich import box

from ..models import Finding, Severity
from .engine import match_rules, NotifyEngine, process_findings
from .models import (
    ChannelTestResult,
    IMChannel,
    IMChannelType,
    NotificationPayload,
    NotifyEvent,
    NotifyFrequency,
    NotifyRecord,
    NotifyRule,
    NotifyStatus,
    event_to_display,
    status_to_display,
)
from .store import NotifyStore, open_store
from .webhook import check_channel as _test_channel


logger = logging.getLogger(__name__)

notify_app = typer.Typer(
    name="notify",
    help="企业通知管理 (IM Webhook 推送: 飞书/钉钉/企业微信)",
    add_completion=False,
)

channel_app = typer.Typer(
    name="channel",
    help="通知渠道管理 (IM Webhook 配置)",
    add_completion=False,
)
notify_app.add_typer(channel_app, name="channel")

rule_app = typer.Typer(
    name="rule",
    help="推送规则管理",
    add_completion=False,
)
notify_app.add_typer(rule_app, name="rule")


def _fmt_time(t) -> str:
    if t is None:
        return "-"
    if isinstance(t, datetime):
        return t.strftime("%Y-%m-%d %H:%M")
    return str(t)[:16]


# ════════════════════ 渠道管理 ════════════════════

@channel_app.command("add")
def channel_add(
    name: str = typer.Option(..., "--name", "-n", help="渠道名称"),
    channel_type: str = typer.Option(..., "--type", "-t",
                                     help="渠道类型: feishu / dingtalk / wechat_work"),
    webhook_url: str = typer.Option(..., "--webhook", "-w", help="Webhook URL"),
    secret: Optional[str] = typer.Option(None, "--secret", "-s", help="签名密钥(可选)"),
    timeout: int = typer.Option(10, "--timeout", help="超时秒数(1-60)"),
):
    """添加 IM 通知渠道"""

    async def _run():
        try:
            ctype = IMChannelType(channel_type.lower())
        except ValueError:
            typer.echo(f"[red]未知渠道类型: {channel_type} (可选 feishu/dingtalk/wechat_work)[/red]")
            raise typer.Exit(1)

        channel = IMChannel(
            name=name,
            channel_type=ctype,
            webhook_url=webhook_url,
            secret=secret,
            timeout_seconds=timeout,
        )
        async with open_store() as store:
            saved = await store.create_channel(channel)
            typer.echo(
                f"[green]已添加通知渠道[/green]\n"
                f"  ID   : {saved.id}\n"
                f"  名称 : {saved.name}\n"
                f"  类型 : {saved.channel_type.value}\n"
                f"  URL  : {saved.webhook_url}"
            )

    asyncio.run(_run())


@channel_app.command("list")
def channel_list(
    all_: bool = typer.Option(False, "--all", help="包含已禁用的渠道"),
):
    """列出所有通知渠道"""

    async def _run():
        async with open_store() as store:
            channels = await store.list_channels(enabled_only=not all_)
            if not channels:
                typer.echo("[yellow]暂无通知渠道[/yellow]")
                return

            table = Table(title="通知渠道", box=box.ROUNDED, show_lines=True)
            table.add_column("ID", style="dim", max_width=12)
            table.add_column("名称")
            table.add_column("类型")
            table.add_column("Webhook URL", max_width=50)
            table.add_column("启用", justify="center")
            table.add_column("超时", justify="right")
            table.add_column("创建时间")
            for c in channels:
                table.add_row(
                    c.id[:8] if c.id else "-",
                    c.name,
                    c.channel_type.value,
                    c.webhook_url if c.webhook_url else "-",
                    "是" if c.enabled else "否",
                    f"{c.timeout_seconds}s",
                    _fmt_time(c.created_at),
                )
            typer.echo(table)

    asyncio.run(_run())


@channel_app.command("test")
def channel_test(
    channel_id: str = typer.Argument(..., help="渠道 ID"),
):
    """测试渠道连通性 (发送一条测试消息)"""

    async def _run():
        async with open_store() as store:
            channel = await store.get_channel(channel_id)
            if channel is None:
                typer.echo(f"[red]未找到渠道: {channel_id}[/red]")
                raise typer.Exit(1)

            typer.echo(f"[cyan]正在测试渠道 {channel.name} ({channel.channel_type.value})...[/cyan]")
            result = await _test_channel(channel)
            if result.success:
                typer.echo(
                    f"[green]测试通过[/green]\n"
                    f"  渠道  : {result.channel_type.value}\n"
                    f"  状态码: {result.status_code}\n"
                    f"  延迟  : {result.latency_ms}ms"
                )
            else:
                typer.echo(
                    f"[red]测试失败[/red]\n"
                    f"  渠道  : {result.channel_type.value}\n"
                    f"  原因  : {result.message}"
                )
                raise typer.Exit(1)

    asyncio.run(_run())


@channel_app.command("delete")
def channel_delete(
    channel_id: str = typer.Argument(..., help="渠道 ID"),
):
    """删除通知渠道"""

    async def _run():
        async with open_store() as store:
            ok = await store.delete_channel(channel_id)
            if ok:
                typer.echo(f"[green]已删除渠道: {channel_id}[/green]")
            else:
                typer.echo(f"[yellow]未找到渠道: {channel_id}[/yellow]")
                raise typer.Exit(1)

    asyncio.run(_run())


# ════════════════════ 规则管理 ════════════════════

@rule_app.command("add")
def rule_add(
    name: str = typer.Option(..., "--name", "-n", help="规则名称"),
    min_severity: str = typer.Option("HIGH", "--min-severity",
                                      help="最低触发严重度 (CRITICAL/HIGH/MEDIUM/LOW)"),
    events: str = typer.Option("new_critical,new_high", "--events",
                                help="触发事件(逗号分隔): new_critical,new_high,status_changed,scan_completed,daily_digest"),
    channels: str = typer.Option("", "--channels",
                                 help="关联渠道 ID (逗号分隔)"),
    frequency: str = typer.Option("realtime", "--frequency",
                                    help="推送频率: realtime/hourly/daily/weekly"),
    rule_id_patterns: str = typer.Option("", "--rule-id-patterns",
                                           help="规则 ID 前缀匹配 (逗号分隔, 空=全部)"),
    path_patterns: str = typer.Option("", "--path-patterns",
                                       help="文件路径前缀匹配 (逗号分隔, 空=全部)"),
    suppress_minutes: int = typer.Option(60, "--suppress-minutes",
                                          help="重复抑制分钟数 (0-1440)"),
):
    """添加通知推送规则"""

    async def _run():
        try:
            event_list = [NotifyEvent(e.strip()) for e in events.split(",") if e.strip()]
        except ValueError as e:
            typer.echo(f"[red]无效事件类型: {e}[/red]")
            raise typer.Exit(1)

        try:
            freq = NotifyFrequency(frequency.lower())
        except ValueError:
            typer.echo(f"[red]无效频率: {frequency} (可选 realtime/hourly/daily/weekly)[/red]")
            raise typer.Exit(1)

        channel_ids = [c.strip() for c in channels.split(",") if c.strip()] if channels else []
        rid_pats = [p.strip() for p in rule_id_patterns.split(",") if p.strip()] if rule_id_patterns else []
        path_pats = [p.strip() for p in path_patterns.split(",") if p.strip()] if path_patterns else []

        rule = NotifyRule(
            name=name,
            min_severity=min_severity.upper(),
            events=event_list,
            channels=channel_ids,
            frequency=freq,
            rule_id_patterns=rid_pats,
            path_patterns=path_pats,
            suppress_duplicates_minutes=suppress_minutes,
        )

        async with open_store() as store:
            saved = await store.create_rule(rule)
            typer.echo(
                f"[green]已添加推送规则[/green]\n"
                f"  ID       : {saved.id}\n"
                f"  名称     : {saved.name}\n"
                f"  最低严重度: {saved.min_severity}\n"
                f"  事件     : {', '.join(e.value for e in saved.events)}\n"
                f"  频率     : {saved.frequency.value}\n"
                f"  关联渠道 : {', '.join(saved.channels) if saved.channels else '(无)'}\n"
                f"  抑制分钟 : {saved.suppress_duplicates_minutes}"
            )

    asyncio.run(_run())


@rule_app.command("list")
def rule_list(
    all_: bool = typer.Option(False, "--all", help="包含已禁用的规则"),
):
    """列出所有推送规则"""

    async def _run():
        async with open_store() as store:
            rules = await store.list_rules(enabled_only=not all_)
            if not rules:
                typer.echo("[yellow]暂无推送规则[/yellow]")
                return

            table = Table(title="推送规则", box=box.ROUNDED, show_lines=True)
            table.add_column("ID", style="dim", max_width=12)
            table.add_column("名称")
            table.add_column("严重度>=")
            table.add_column("事件")
            table.add_column("频率")
            table.add_column("渠道数")
            table.add_column("启用", justify="center")
            table.add_column("创建时间")
            for r in rules:
                table.add_row(
                    r.id[:8] if r.id else "-",
                    r.name,
                    r.min_severity,
                    ", ".join(e.value for e in r.events),
                    r.frequency.value,
                    str(len(r.channels)),
                    "是" if r.enabled else "否",
                    _fmt_time(r.created_at),
                )
            typer.echo(table)

    asyncio.run(_run())


@rule_app.command("delete")
def rule_delete(
    rule_id: str = typer.Argument(..., help="规则 ID"),
):
    """删除推送规则"""

    async def _run():
        async with open_store() as store:
            ok = await store.delete_rule(rule_id)
            if ok:
                typer.echo(f"[green]已删除规则: {rule_id}[/green]")
            else:
                typer.echo(f"[yellow]未找到规则: {rule_id}[/yellow]")
                raise typer.Exit(1)

    asyncio.run(_run())


# ════════════════════ 推送与历史 ════════════════════

@notify_app.command("send")
def notify_send(
    channel_id: str = typer.Option(..., "--channel", help="渠道 ID"),
    title: str = typer.Option(..., "--title", help="通知标题"),
    content: str = typer.Option(..., "--content", help="通知内容"),
    severity: str = typer.Option("HIGH", "--severity", help="严重程度"),
):
    """手动发送一条通知 (测试用)"""

    async def _run():
        async with open_store() as store:
            channel = await store.get_channel(channel_id)
            if channel is None:
                typer.echo(f"[red]未找到渠道: {channel_id}[/red]")
                raise typer.Exit(1)

        payload = NotificationPayload(
            title=title, content=content, severity=severity,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        from .webhook import send_notification
        result = await send_notification(channel, payload)
        if result.success:
            typer.echo(f"[green]发送成功[/green]  延迟: {result.latency_ms}ms")
        else:
            typer.echo(f"[red]发送失败[/red]  原因: {result.message}")
            raise typer.Exit(1)

    asyncio.run(_run())


@notify_app.command("history")
def notify_history(
    status_filter: Optional[str] = typer.Option(None, "--status",
                                                  help="过滤状态: pending/sent/failed/suppressed"),
    limit: int = typer.Option(50, "--limit", "-n", help="显示数量"),
):
    """查看推送历史"""

    async def _run():
        async with open_store() as store:
            sf = None
            if status_filter:
                try:
                    sf = NotifyStatus(status_filter.lower())
                except ValueError:
                    typer.echo(f"[red]无效状态: {status_filter}[/red]")
                    raise typer.Exit(1)
            records = await store.list_records(status_filter=sf, limit=limit)
            if not records:
                typer.echo("[yellow]暂无推送记录[/yellow]")
                return

            table = Table(title="推送历史", box=box.ROUNDED, show_lines=True)
            table.add_column("ID", style="dim", max_width=10)
            table.add_column("事件")
            table.add_column("标题", max_width=40)
            table.add_column("状态")
            table.add_column("创建时间")
            table.add_column("发送时间")
            for r in records:
                table.add_row(
                    r.id[:8] if r.id else "-",
                    event_to_display(r.event) if r.event else "-",
                    r.title[:40] if r.title else "-",
                    status_to_display(r.status),
                    _fmt_time(r.created_at),
                    _fmt_time(r.sent_at),
                )
            typer.echo(table)

    asyncio.run(_run())


@notify_app.command("stats")
def notify_stats():
    """查看通知统计"""

    async def _run():
        async with open_store() as store:
            stats = await store.stats()
            panel = Panel(
                f"[bold]启用渠道数[/bold]:     {stats['channels']}\n"
                f"[bold]启用规则数[/bold]:     {stats['rules']}\n"
                f"[bold]推送记录总数[/bold]:   {stats['records_total']}\n"
                f"[bold]已发送[/bold]:         {stats['records_sent']}\n"
                f"[bold]发送失败[/bold]:       {stats['records_failed']}",
                title="企业通知统计",
                border_style="cyan",
            )
            typer.echo(panel)

    asyncio.run(_run())


@notify_app.command("clean")
def notify_clean(
    days: int = typer.Option(90, "--days", help="清理超过 N 天的推送记录"),
):
    """清理过期推送记录 (S5 红线语义)"""

    async def _run():
        async with open_store() as store:
            n = await store.purge_records(days)
            typer.echo(f"[green]已清理 {n} 条过期推送记录[/green]")

    asyncio.run(_run())


# ════════════════════ CLI 入口 ════════════════════

def main():
    notify_app()


if __name__ == "__main__":
    main()
