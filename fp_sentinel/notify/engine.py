"""
企业通知模块 - 通知引擎

负责:
1. 将扫描结果与通知规则进行匹配(严重度、事件类型、规则 ID 前缀、文件路径)
2. 频率控制(重复抑制)
3. 生成通知消息体并通过 Webhook 适配器发送
4. 记录所有推送记录到 SQLite

安全约束:
- S1 (仅内部 IM): URL 由渠道创建时校验
- S2 (禁止修改代码): 仅生成通知消息和发送请求,不修改任何文件
- S4 (禁止真实攻击): 仅发送通知文本
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from ..models import Finding, Severity
from .models import (
    IMChannel,
    NotificationPayload,
    NotifyEvent,
    NotifyRecord,
    NotifyRule,
    NotifyStatus,
    severity_rank,
)
from .store import NotifyStore, open_store
from .webhook import send_notification

logger = logging.getLogger(__name__)


def _prefix_matches(value: str, patterns: List[str]) -> bool:
    """判断 value 是否匹配任一前缀模式(空 patterns 表全部匹配)"""
    if not patterns:
        return True
    for pat in patterns:
        if value.startswith(pat):
            return True
    return False


def match_rule(
    rule: NotifyRule,
    finding: Finding,
    event: NotifyEvent,
) -> bool:
    """
    判断一条 finding + 事件是否匹配某条通知规则

    匹配条件(AND):
    1. 规则已启用
    2. finding 严重度 >= 规则 min_severity
    3. 事件类型在规则 events 中
    4. finding.rule_id 匹配 rule_id_patterns(如有)
    5. finding.file_path 匹配 path_patterns(如有)
    """
    if not rule.enabled:
        return False

    finding_sev = (
        finding.severity.value
        if isinstance(finding.severity, Severity)
        else str(finding.severity)
    )
    if severity_rank(finding_sev) < severity_rank(rule.min_severity):
        return False

    if event not in rule.events:
        return False

    if not _prefix_matches(finding.rule_id, rule.rule_id_patterns):
        return False

    if not _prefix_matches(finding.file_path, rule.path_patterns):
        return False

    return True


def match_rules(
    rules: List[NotifyRule],
    finding: Finding,
    event: NotifyEvent,
) -> List[NotifyRule]:
    """返回所有匹配的 rules"""
    return [r for r in rules if match_rule(r, finding, event)]


def _event_title(finding: Finding, event: NotifyEvent) -> str:
    """生成通知标题"""
    prefix = {
        NotifyEvent.NEW_CRITICAL: "[CRITICAL]",
        NotifyEvent.NEW_HIGH: "[HIGH]",
        NotifyEvent.STATUS_CHANGED: "[状态变更]",
        NotifyEvent.SCAN_COMPLETED: "[扫描完成]",
        NotifyEvent.DAILY_DIGEST: "[日报]",
    }.get(event, "[通知]")
    msg = finding.message[:80] if finding.message else finding.rule_id
    return f"{prefix} {msg}"


def _build_payload(
    finding: Finding,
    event: NotifyEvent,
    *,
    status_from: Optional[str] = None,
    status_to: Optional[str] = None,
) -> NotificationPayload:
    """从 finding 构建通知消息体"""
    sev = (
        finding.severity.value
        if isinstance(finding.severity, Severity)
        else str(finding.severity)
    )

    title = _event_title(finding, event)
    content_parts: list[str] = [f"发现安全漏洞: {finding.message}"]

    return NotificationPayload(
        title=title,
        content="\n".join(content_parts),
        severity=sev,
        timestamp=datetime.now(timezone.utc).isoformat(),
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        line_start=finding.line_start,
        message=finding.message[:500] if finding.message else "",
        category=finding.category,
        cwe=finding.cwe,
        status_from=status_from,
        status_to=status_to,
    )


class NotifyEngine:
    """
    通知引擎: 管理通知的完整生命周期

    用法::

        async with NotifyEngine() as engine:
            results = await engine.process_findings(findings)
    """

    def __init__(
        self,
        store: Optional[NotifyStore] = None,
        http_client_factory: Optional[Callable[..., Any]] = None,
    ):
        self._store = store
        self._store_owned = store is None
        self._http_factory = http_client_factory

    async def __aenter__(self):
        if self._store_owned:
            self._store = open_store()
            await self._store.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._store_owned and self._store:
            await self._store.__aexit__(exc_type, exc_val, exc_tb)
        return False

    @property
    def store(self) -> NotifyStore:
        if self._store is None:
            raise RuntimeError("engine not entered")
        return self._store

    async def process_findings(
        self,
        findings: List[Finding],
        events: Optional[List[NotifyEvent]] = None,
    ) -> List[NotifyRecord]:
        """
        批量处理通知: 对每条 finding 匹配规则并发送通知

        Args:
            findings: 扫描结果列表
            events: 触发事件类型(默认按 finding 严重度自动判断)

        Returns:
            通知推送记录列表
        """
        if events is None:
            events = [NotifyEvent.NEW_CRITICAL, NotifyEvent.NEW_HIGH]

        all_records: List[NotifyRecord] = []
        rules = await self.store.list_rules(enabled_only=True)
        channels_cache: Dict[str, IMChannel] = {}

        for finding in findings:
            finding_sev = (
                finding.severity.value
                if isinstance(finding.severity, Severity)
                else str(finding.severity)
            )

            event: Optional[NotifyEvent] = None
            if finding_sev == "CRITICAL" and NotifyEvent.NEW_CRITICAL in events:
                event = NotifyEvent.NEW_CRITICAL
            elif finding_sev == "HIGH" and NotifyEvent.NEW_HIGH in events:
                event = NotifyEvent.NEW_HIGH
            else:
                continue

            matched = match_rules(rules, finding, event)
            for rule in matched:
                finding_id = finding.id or finding.fingerprint
                if finding_id and rule.suppress_duplicates_minutes > 0:
                    count = await self.store.count_recent_by_finding(
                        finding_id, rule.suppress_duplicates_minutes
                    )
                    if count > 0:
                        rec = await self._create_suppressed_record(
                            finding, event, rule, "重复抑制"
                        )
                        all_records.append(rec)
                        continue

                for channel_id in rule.channels:
                    channel = channels_cache.get(channel_id)
                    if channel is None:
                        channel = await self.store.get_channel(channel_id)
                        if channel is not None:
                            channels_cache[channel_id] = channel
                    if channel is None or not channel.enabled:
                        continue

                    payload = _build_payload(finding, event)
                    record = await self._dispatch(
                        channel, rule, finding, event, payload
                    )
                    all_records.append(record)

        return all_records

    async def notify_status_change(
        self,
        finding: Finding,
        old_status: str,
        new_status: str,
    ) -> List[NotifyRecord]:
        """漏洞状态变更通知(专用入口)"""
        all_records: List[NotifyRecord] = []
        rules = await self.store.list_rules(enabled_only=True)

        for rule in rules:
            if not rule.enabled:
                continue
            if NotifyEvent.STATUS_CHANGED not in rule.events:
                continue
            finding_sev = (
                finding.severity.value
                if isinstance(finding.severity, Severity)
                else str(finding.severity)
            )
            if severity_rank(finding_sev) < severity_rank(rule.min_severity):
                continue
            if not _prefix_matches(finding.rule_id, rule.rule_id_patterns):
                continue
            if not _prefix_matches(finding.file_path, rule.path_patterns):
                continue

            for channel_id in rule.channels:
                channel = await self.store.get_channel(channel_id)
                if channel is None or not channel.enabled:
                    continue

                payload = _build_payload(
                    finding, NotifyEvent.STATUS_CHANGED,
                    status_from=old_status, status_to=new_status,
                )
                record = await self._dispatch(
                    channel, rule, finding,
                    NotifyEvent.STATUS_CHANGED, payload,
                )
                all_records.append(record)

        return all_records

    async def _dispatch(
        self,
        channel: IMChannel,
        rule: NotifyRule,
        finding: Finding,
        event: NotifyEvent,
        payload: NotificationPayload,
    ) -> NotifyRecord:
        """创建记录并发送"""
        finding_id = finding.id or finding.fingerprint

        record = NotifyRecord(
            channel_id=channel.id,
            rule_id=rule.id,
            event=event,
            finding_id=finding_id,
            status=NotifyStatus.PENDING,
            title=payload.title,
            content=payload.content,
        )
        await self.store.create_record(record)

        try:
            result = await send_notification(channel, payload)
            if result.success:
                sent_time = datetime.now(timezone.utc)
                await self.store.update_record_status(
                    record.id,
                    NotifyStatus.SENT,
                    sent_at=sent_time,
                )
                record.status = NotifyStatus.SENT
                record.sent_at = sent_time
            else:
                await self.store.update_record_status(
                    record.id,
                    NotifyStatus.FAILED,
                    error_message=result.message,
                )
                record.status = NotifyStatus.FAILED
                record.error_message = result.message
        except Exception as e:
            logger.warning("通知发送异常: %s", e)
            await self.store.update_record_status(
                record.id,
                NotifyStatus.FAILED,
                error_message=str(e),
            )
            record.status = NotifyStatus.FAILED
            record.error_message = str(e)

        return record

    async def _create_suppressed_record(
        self,
        finding: Finding,
        event: NotifyEvent,
        rule: NotifyRule,
        reason: str,
    ) -> NotifyRecord:
        """创建被抑制的记录"""
        finding_id = finding.id or finding.fingerprint
        record = NotifyRecord(
            rule_id=rule.id,
            event=event,
            finding_id=finding_id,
            status=NotifyStatus.SUPPRESSED,
            title=f"[抑制] {_event_title(finding, event)}",
            content=reason,
        )
        await self.store.create_record(record)
        return record


async def process_findings(
    findings: List[Finding],
    events: Optional[List[NotifyEvent]] = None,
) -> List[NotifyRecord]:
    """便捷函数: 使用默认配置处理 finding 通知"""
    async with NotifyEngine() as engine:
        return await engine.process_findings(findings, events=events)


async def notify_status_change(
    finding: Finding,
    old_status: str,
    new_status: str,
) -> List[NotifyRecord]:
    """便捷函数: 发送状态变更通知"""
    async with NotifyEngine() as engine:
        return await engine.notify_status_change(finding, old_status, new_status)
