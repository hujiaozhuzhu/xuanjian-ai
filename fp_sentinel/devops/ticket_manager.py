"""
DevSecOps 对接模块 - 工单状态联动引擎

当漏洞修复完成后：
1. 自动关闭对应外部工单（GitLab Issue / Jira Ticket / GitHub Issue）
2. 自动将修复 commit 关联到工单
3. 更新本地映射状态
4. 支持通过 Webhook 事件被动更新

安全红线：
- S3: 仅调用外部 API 关闭工单，本地操作只更新 mapping 状态
- S1: 通过适配器层隔离外部 HTTP 调用
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional

from .adapters import DevOpsAdapter, fingerprint_finding
from .models import (
    FindingRef,
    FindingTicketMapping,
    SyncRecord,
    SyncStatus,
    SyncDirection,
    TicketLinkRequest,
    TicketStatus,
)
from .repository import FindingTicketMappingRepo, SyncRecordRepo

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class TicketManager:
    """工单状态联动管理器"""

    def __init__(
        self,
        mapping_repo: FindingTicketMappingRepo,
        sync_repo: SyncRecordRepo,
    ):
        self.mappings = mapping_repo
        self.syncs = sync_repo

    async def auto_close_resolved_findings(
        self,
        findings: List[FindingRef],
        adapter: DevOpsAdapter,
        resolution: str = "fixed",
        default_comment: str = "",
    ) -> List[SyncRecord]:
        """
        对已修复（不再出现于最新扫描）的 finding 自动关闭工单

        Args:
            findings: 最新扫描的 finding 列表（仍存在的漏洞）
            adapter: DevOps 适配器
            resolution: 解决方式描述
            default_comment: 关单备注

        Returns:
            关单同步记录列表
        """
        sync_records: List[SyncRecord] = []

        # 查找所有 open 状态的映射
        open_mappings = await self.mappings.list_mappings(ticket_status=TicketStatus.OPEN.value)

        # 构建仍存在漏洞的指纹集合
        active_fingerprints = set()
        for f in findings:
            active_fingerprints.add(fingerprint_finding(f))

        for mapping in open_mappings:
            # 对应 finding 不存在于最新扫描 -> 已修复
            if mapping.finding_fingerprint and mapping.finding_fingerprint not in active_fingerprints:
                record = await self.close_ticket(
                    mapping=mapping,
                    adapter=adapter,
                    resolution=resolution,
                    comment=default_comment or "漏洞已修复，自动关闭",
                )
                sync_records.append(record)

        return sync_records

    async def close_ticket(
        self,
        mapping: FindingTicketMapping,
        adapter: DevOpsAdapter,
        resolution: str = "fixed",
        comment: str = "",
        commit_hash: str = "",
    ) -> SyncRecord:
        """
        关闭单个工单

        Args:
            mapping: 工单映射对象
            adapter: DevOps 适配器
            resolution: 解决方式
            comment: 备注
            commit_hash: 修复 commit

        Returns:
            SyncRecord 同步记录
        """
        record = SyncRecord(
            mapping_id=mapping.id,
            finding_id=mapping.finding_id,
            provider=mapping.provider,
            sync_direction=SyncDirection.FINDING_TO_TICKET,
            status=SyncStatus.PENDING,
            ticket_id=mapping.ticket_id,
            ticket_key=mapping.ticket_key or "",
        )

        try:
            success = await adapter.close_issue(
                ticket_id=mapping.ticket_id,
                resolution=resolution,
                comment=comment,
                commit_hash=commit_hash,
            )
            if success:
                record.status = SyncStatus.SYNCED
                record.response_summary = "closed"
                await self.mappings.update(
                    mapping.id,
                    ticket_status=TicketStatus.CLOSED,
                    sync_status=SyncStatus.SYNCED,
                    sync_direction=SyncStatus.SYNCED,
                    last_sync_at=_now_iso(),
                )
            else:
                record.status = SyncStatus.FAILED
                record.error_message = "close_issue returned False"
        except Exception as e:
            record.status = SyncStatus.FAILED
            record.error_message = str(e)

        await self.syncs.create(record)
        return record

    async def link_commit_to_ticket(
        self,
        request: TicketLinkRequest,
        adapter: DevOpsAdapter,
    ) -> SyncRecord:
        """
        关联修复提交到工单

        Args:
            request: 关联请求
            adapter: DevOps 适配器

        Returns:
            SyncRecord 同步记录
        """
        mapping = await self.mappings.get_by_ticket_id(request.ticket_id, request.provider.value)

        record = SyncRecord(
            mapping_id=mapping.id if mapping else "",
            finding_id="",
            provider=request.provider,
            sync_direction=SyncDirection.FINDING_TO_TICKET,
            status=SyncStatus.PENDING,
            ticket_id=request.ticket_id,
            ticket_key="",
        )

        try:
            # 添加评论记录修复提交
            comment_parts = [f"关联修复提交: {request.commit_hash}"]
            if request.branch:
                comment_parts.append(f"分支: {request.branch}")
            if request.comment:
                comment_parts.append(request.comment)
            comment = "\n".join(comment_parts)

            ok = await adapter.add_comment(request.ticket_id, comment)
            if ok:
                record.status = SyncStatus.SYNCED
                record.response_summary = "comment_added"
            else:
                record.status = SyncStatus.FAILED
                record.error_message = "add_comment returned False"

            # 如需要则关闭工单
            if request.close_after_link and ok:
                close_ok = await adapter.close_issue(
                    ticket_id=request.ticket_id,
                    resolution=request.resolution,
                    comment="自动关闭: 漏洞已修复",
                    commit_hash=request.commit_hash,
                )
                if close_ok:
                    record.response_summary += "+closed"
                    if mapping:
                        await self.mappings.update(
                            mapping.id,
                            ticket_status=TicketStatus.CLOSED,
                            sync_status=SyncStatus.SYNCED,
                            last_sync_at=_now_iso(),
                            commit_hash=request.commit_hash,
                        )
                else:
                    record.response_summary += "+close_failed"

        except Exception as e:
            record.status = SyncStatus.FAILED
            record.error_message = str(e)

        await self.syncs.create(record)
        return record

    async def handle_status_webhook(
        self,
        ticket_id: str,
        from_status: TicketStatus,
        to_status: TicketStatus,
        provider_value: str,
        commit_hash: str = "",
    ) -> Optional[SyncRecord]:
        """
        处理外部工单状态变更 Webhook
        """
        mapping = await self.mappings.get_by_ticket_id(ticket_id, provider_value)
        if not mapping:
            return None

        now = _now_iso()
        await self.mappings.update(
            mapping.id,
            ticket_status=to_status,
            sync_direction=SyncStatus.SYNCED,
            sync_status=SyncStatus.SYNCED,
            last_sync_at=now,
            commit_hash=commit_hash or mapping.commit_hash,
        )

        record = SyncRecord(
            mapping_id=mapping.id,
            finding_id=mapping.finding_id,
            provider=mapping.provider,
            sync_direction=SyncDirection.TICKET_TO_LOCAL,
            status=SyncStatus.SYNCED,
            ticket_id=ticket_id,
            ticket_key=mapping.ticket_key or "",
            response_summary=f"{from_status.value}->{to_status.value}",
        )
        await self.syncs.create(record)
        return record

    async def reopen_ticket_if_vulnerable(
        self,
        mapping: FindingTicketMapping,
        adapter: DevOpsAdapter,
        reason: str = "漏洞重新出现",
    ) -> Optional[SyncRecord]:
        """
        重新打开已关闭工单（当漏洞重新出现时）
        """
        if mapping.ticket_status not in (TicketStatus.CLOSED, TicketStatus.RESOLVED):
            return None

        try:
            ok = await adapter.update_issue_status(
                ticket_id=mapping.ticket_id,
                new_status=TicketStatus.REOPENED,
                comment=reason,
            )
            record = SyncRecord(
                mapping_id=mapping.id,
                finding_id=mapping.finding_id,
                provider=mapping.provider,
                sync_direction=SyncDirection.FINDING_TO_TICKET,
                status=SyncStatus.SYNCED if ok else SyncStatus.FAILED,
                ticket_id=mapping.ticket_id,
                ticket_key=mapping.ticket_key or "",
                response_summary="reopened" if ok else "reopen_failed",
            )
            if ok:
                await self.mappings.update(
                    mapping.id,
                    ticket_status=TicketStatus.REOPENED,
                    sync_status=SyncStatus.SYNCED,
                    last_sync_at=_now_iso(),
                )
            await self.syncs.create(record)
            return record
        except Exception as e:
            logger.exception("reopen_ticket_if_vulnerable error")
            record = SyncRecord(
                mapping_id=mapping.id,
                finding_id=mapping.finding_id,
                provider=mapping.provider,
                sync_direction=SyncDirection.FINDING_TO_TICKET,
                status=SyncStatus.FAILED,
                ticket_id=mapping.ticket_id,
                error_message=str(e),
            )
            await self.syncs.create(record)
            return record
