"""
DevSecOps 对接模块 - 业务编排层

编排适配器、卡点引擎、工单管理、持久化的完整业务流：
- sync_findings: 将扫描发现自动同步为 Issue/工单
- evaluate_pipeline_gate: Pipeline 卡点评估 + 持久化
- handle_webhook_event: 处理外部 Webhook 联动
- get_stats: 模块运营统计

安全红线：
- S1: 外部调用全部通过适配器注入
- S2: 不修改被扫描代码
- S3: 本地操作只增不改不删（除状态更新 mapping 状态字段）
- S5: 数据保留周期可配置
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .adapters import DevOpsAdapter, create_adapter, fingerprint_finding
from .models import (
    BatchSyncFindingsRequest,
    DevOpsConfig,
    DevOpsProvider,
    DevOpsStats,
    FindingRef,
    FindingTicketMapping,
    PipelineGateRequest,
    PipelineGateResult,
    SyncFindingsRequest,
    SyncRecord,
    SyncResult,
    SyncStatus,
    SyncDirection,
    TicketCloseRequest,
    TicketLinkRequest,
    TicketStatus,
    WebhookEventType,
)
from .pipeline_gate import evaluate_gate
from .repository import (
    FindingTicketMappingRepo,
    PipelineGateRecordRepo,
    SyncRecordRepo,
)
from .ticket_manager import TicketManager

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _generate_id() -> str:
    return str(uuid.uuid4())


class DevOpsService:
    """DevSecOps 业务编排服务"""

    def __init__(
        self,
        mapping_repo: FindingTicketMappingRepo,
        sync_repo: SyncRecordRepo,
        gate_repo: PipelineGateRecordRepo,
    ):
        self.mappings = mapping_repo
        self.syncs = sync_repo
        self.gates = gate_repo
        self.ticket_mgr = TicketManager(mapping_repo, sync_repo)

    # ─────────────────── 同步发现到工单 ───────────────────

    async def sync_findings(
        self,
        request: SyncFindingsRequest,
        adapter: Optional[DevOpsAdapter] = None,
    ) -> SyncResult:
        """
        将扫描发现同步到外部平台 Issue/工单

        完整流程：
        1. 遍历 findings
        2. 检查是否已有映射（去重）
        3. 调用适配器创建 Issue
        4. 保存映射 + 同步记录

        Args:
            request: 同步请求
            adapter: 可选适配器（不传则根据 config 创建）

        Returns:
            SyncResult 同步结果
        """
        config = request.config or DevOpsConfig(
            provider=request.provider,
            base_url="",
            project_id=request.project_id,
        )
        should_close = False
        if adapter is None:  # pragma: no cover - 间接路径，测试时总是注入 adapter
            adapter = create_adapter(request.provider, config)
            should_close = True

        result = SyncResult(
            status=SyncStatus.PENDING,
            provider=request.provider,
            total_findings=len(request.findings),
            dry_run=request.dry_run,
        )

        try:
            for finding in request.findings:
                await self._sync_single_finding(
                    finding=finding,
                    request=request,
                    config=config,
                    adapter=adapter,
                    result=result,
                )
            result.status = SyncStatus.SYNCED if result.failed_count == 0 else SyncStatus.FAILED
        finally:
            if should_close:
                await adapter.close()

        return result

    async def _sync_single_finding(
        self,
        finding: FindingRef,
        request: SyncFindingsRequest,
        config: DevOpsConfig,
        adapter: DevOpsAdapter,
        result: SyncResult,
    ) -> None:
        """同步单个 finding 到外部工单"""
        fp = fingerprint_finding(finding)

        # 去重检查
        existing = await self.mappings.get_by_finding_id(finding.id, request.provider.value)
        if existing and existing.sync_status == SyncStatus.SYNCED:
            result.skipped_count += 1
            return

        if request.dry_run:
            result.skipped_count += 1
            return

        # 调用适配器创建 Issue
        ticket_id, ticket_key, ticket_url = await adapter.create_issue(
            finding=finding,
            repository_url=request.repository_url,
            commit_hash=request.commit_hash,
            branch=request.branch,
        )

        if not ticket_id:
            result.failed_count += 1
            result.errors.append(f"创建工单失败: {finding.rule_id} @ {finding.file_path}")
            # 记录失败
            sync_record = SyncRecord(
                mapping_id=existing.id if existing else _generate_id(),
                finding_id=finding.id,
                provider=request.provider,
                sync_direction=SyncDirection.FINDING_TO_TICKET,
                status=SyncStatus.FAILED,
                error_message="create_issue returned no ticket_id",
                request_payload=json.dumps(finding.model_dump(), default=str),
            )
            await self.syncs.create(sync_record)
            return

        # 构建映射
        now = _now_iso()
        mapping = FindingTicketMapping(
            id=_generate_id(),
            finding_id=finding.id,
            finding_fingerprint=fp,
            provider=request.provider,
            ticket_id=ticket_id,
            ticket_key=ticket_key or "",
            ticket_url=ticket_url or "",
            ticket_status=TicketStatus.OPEN,
            project_id=request.project_id,
            repository_url=request.repository_url,
            commit_hash=request.commit_hash,
            branch=request.branch,
            sync_status=SyncStatus.SYNCED,
            sync_direction=SyncDirection.FINDING_TO_TICKET,
            severity=finding.severity,
            rule_id=finding.rule_id,
            title=f"[{finding.severity}] {finding.rule_id}",
            created_at=now,
            updated_at=now,
            last_sync_at=now,
        )

        await self.mappings.create(mapping)
        result.created_count += 1
        result.mappings.append(mapping)

        # 记录同步流水
        sync_record = SyncRecord(
            mapping_id=mapping.id,
            finding_id=finding.id,
            provider=request.provider,
            sync_direction=SyncDirection.FINDING_TO_TICKET,
            status=SyncStatus.SYNCED,
            ticket_id=ticket_id,
            ticket_key=ticket_key or "",
            request_payload=json.dumps(finding.model_dump(), default=str),
            response_summary=f"issue_created: {ticket_key}",
        )
        await self.syncs.create(sync_record)

    # ─────────────────── Pipeline 卡点评估 ───────────────────

    async def evaluate_pipeline_gate(
        self,
        request: PipelineGateRequest,
        persist: bool = True,
    ) -> PipelineGateResult:
        """
        执行 Pipeline 卡点评估并可选持久化结果

        Args:
            request: 评估请求
            persist: 是否持久化结果到 SQLite

        Returns:
            PipelineGateResult 评估结果
        """
        result = evaluate_gate(request)
        if persist:
            try:
                await self.gates.save_result(result)
            except Exception as e:
                logger.warning("Pipeline gate persist failed: %s", e)
        return result

    # ─────────────────── Webhook 事件处理 ───────────────────

    async def handle_webhook_event(
        self,
        event_type: WebhookEventType,
        provider_value: str,
        payload: Dict[str, Any],
        adapter: Optional[DevOpsAdapter] = None,
    ) -> Optional[SyncRecord]:
        """
        处理外部 Webhook 事件，更新本地状态

        支持事件类型：
        - issue_closed: 外部关闭工单 -> 更新本地 mapping 状态
        - issue_reopened: 重新打开 -> 更新状态
        - merge_request: 合并请求 -> 可触发重新扫描
        - pipeline_status: 流水线状态 -> 记录历史

        Args:
            event_type: 事件类型
            provider_value: 平台类型字符串
            payload: Webhook 原始载荷
            adapter: 可选适配器

        Returns:
            SyncRecord or None
        """
        if event_type == WebhookEventType.ISSUE_CLOSED:
            return await self._handle_issue_closed(provider_value, payload)
        elif event_type == WebhookEventType.ISSUE_REOPENED:
            return await self._handle_issue_reopened(provider_value, payload, adapter)
        elif event_type == WebhookEventType.MERGE_REQUEST:
            return await self._handle_merge_request(provider_value, payload)
        elif event_type == WebhookEventType.PIPELINE_STATUS:
            return await self._handle_pipeline_status(provider_value, payload)
        return None

    async def _handle_issue_closed(
        self,
        provider_value: str,
        payload: Dict[str, Any],
    ) -> Optional[SyncRecord]:
        """处理工单关闭事件"""
        ticket_id, commit_hash = _extract_ticket_id_and_commit(provider_value, payload)
        if ticket_id is None:
            return None
        record = await self.ticket_mgr.handle_status_webhook(
            ticket_id=str(ticket_id),
            from_status=TicketStatus.OPEN,
            to_status=TicketStatus.CLOSED,
            provider_value=provider_value,
            commit_hash=commit_hash or "",
        )
        return record

    async def _handle_issue_reopened(
        self,
        provider_value: str,
        payload: Dict[str, Any],
        adapter: Optional[DevOpsAdapter],
    ) -> Optional[SyncRecord]:
        """处理工单重新打开事件"""
        ticket_id, commit_hash = _extract_ticket_id_and_commit(provider_value, payload)
        if ticket_id is None:
            return None
        return await self.ticket_mgr.handle_status_webhook(
            ticket_id=str(ticket_id),
            from_status=TicketStatus.CLOSED,
            to_status=TicketStatus.REOPENED,
            provider_value=provider_value,
            commit_hash=commit_hash or "",
        )

    async def _handle_merge_request(
        self,
        provider_value: str,
        payload: Dict[str, Any],
    ) -> Optional[SyncRecord]:
        """处理合并请求事件（预留接口）"""
        # 外部事件记录到流水即可
        mr_id = payload.get("merge_request_id") or payload.get("number") or payload.get("id")
        if not mr_id:
            return None
        record = SyncRecord(
            mapping_id="",
            finding_id="",
            provider=DevOpsProvider(provider_value) if provider_value in [p.value for p in DevOpsProvider] else DevOpsProvider.GITLAB,
            sync_direction=SyncDirection.TICKET_TO_LOCAL,
            status=SyncStatus.SYNCED,
            response_summary=f"merge_request_event: {mr_id}",
        )
        await self.syncs.create(record)
        return record

    async def _handle_pipeline_status(
        self,
        provider_value: str,
        payload: Dict[str, Any],
    ) -> Optional[SyncRecord]:
        """处理流水线状态事件"""
        status = payload.get("status") or payload.get("state")
        pipeline_id = payload.get("pipeline_id") or payload.get("id")
        if not pipeline_id:
            return None
        record = SyncRecord(
            mapping_id="",
            finding_id="",
            provider=DevOpsProvider(provider_value) if provider_value in [p.value for p in DevOpsProvider] else DevOpsProvider.GITLAB,
            sync_direction=SyncDirection.TICKET_TO_LOCAL,
            status=SyncStatus.SYNCED,
            response_summary=f"pipeline_status: {pipeline_id} -> {status}",
        )
        await self.syncs.create(record)
        return record

    # ─────────────────── 关闭工单 ───────────────────

    async def close_ticket(
        self,
        request: TicketCloseRequest,
        adapter: Optional[DevOpsAdapter] = None,
    ) -> SyncRecord:
        """
        主动关闭工单

        Args:
            request: 关闭请求
            adapter: 可选适配器

        Returns:
            SyncRecord 同步记录
        """
        config = DevOpsConfig(
            provider=request.provider,
            base_url="",
            project_id="",
        )
        should_close = False
        if adapter is None:  # pragma: no cover - 间接路径，测试时总是注入 adapter
            adapter = create_adapter(request.provider, config)
            should_close = True

        try:
            mapping = await self.mappings.get_by_ticket_id(request.ticket_id, request.provider.value)
            if not mapping:
                record = SyncRecord(
                    mapping_id="",
                    finding_id="",
                    provider=request.provider,
                    sync_direction=SyncDirection.FINDING_TO_TICKET,
                    status=SyncStatus.FAILED,
                    ticket_id=request.ticket_id,
                    error_message="mapping not found",
                )
                await self.syncs.create(record)
                return record

            return await self.ticket_mgr.close_ticket(
                mapping=mapping,
                adapter=adapter,
                resolution=request.resolution,
                comment=request.comment,
                commit_hash=request.commit_hash,
            )
        finally:
            if should_close:
                await adapter.close()

    # ─────────────────── 关联修复提交 ───────────────────

    async def link_fix_commit(
        self,
        request: TicketLinkRequest,
        adapter: Optional[DevOpsAdapter] = None,
    ) -> SyncRecord:
        """
        关联修复 commit 到工单，可选关闭工单
        """
        config = DevOpsConfig(
            provider=request.provider,
            base_url="",
            project_id="",
        )
        should_close = False
        if adapter is None:  # pragma: no cover - 间接路径，测试时总是注入 adapter
            adapter = create_adapter(request.provider, config)
            should_close = True

        try:
            return await self.ticket_mgr.link_commit_to_ticket(request, adapter)
        finally:
            if should_close:
                await adapter.close()

    # ─────────────────── 运营统计 ───────────────────

    async def get_stats(self) -> DevOpsStats:
        """获取 DevOps 模块运营统计"""
        stats = DevOpsStats()

        # 映射统计
        stats.total_mappings = await self.mappings.count()
        stats.open_tickets = await self.mappings.count(ticket_status=TicketStatus.OPEN.value)
        stats.resolved_tickets = await self.mappings.count(ticket_status=TicketStatus.RESOLVED.value)
        stats.closed_tickets = await self.mappings.count(ticket_status=TicketStatus.CLOSED.value)
        stats.in_progress_tickets = await self.mappings.count(ticket_status=TicketStatus.IN_PROGRESS.value)

        # 同步统计
        status_counts = await self.syncs.count_by_status()
        stats.total_syncs = sum(status_counts.values())
        stats.successful_syncs = status_counts.get(SyncStatus.SYNCED.value, 0)
        stats.failed_syncs = status_counts.get(SyncStatus.FAILED.value, 0)
        stats.pending_syncs = status_counts.get(SyncStatus.PENDING.value, 0)

        # 按平台统计映射
        for provider in DevOpsProvider:
            cnt = await self.mappings.count(provider=provider.value)
            if cnt > 0:
                stats.by_provider[provider.value] = cnt

        return stats


# ─────────────────────── 工具函数 ───────────────────────

def _extract_ticket_id_and_commit(
    provider_value: str,
    payload: Dict[str, Any],
) -> tuple:
    """
    从 Webhook payload 中提取 ticket_id 和 commit_hash
    适配 GitLab / Jira / GitHub 的不同字段位置
    """
    ticket_id = None
    commit_hash = ""

    if provider_value == DevOpsProvider.GITLAB.value:
        # GitLab Issue Webhook
        issue = payload.get("issue") or payload.get("object_attributes")
        if issue:
            ticket_id = str(issue.get("iid") or issue.get("id", ""))
        # 查找关联 commit
        if payload.get("object_attributes", {}).get("description"):
            desc = payload["object_attributes"]["description"]
            commit_hash = _extract_commit_from_text(desc)
    elif provider_value == DevOpsProvider.JIRA.value:
        issue = payload.get("issue")
        if issue:
            ticket_id = str(issue.get("id", ""))
        # Jira 的 comment 可能包含 commit 信息
        comment = payload.get("comment", {})
        if comment:
            commit_hash = _extract_commit_from_text(comment.get("body", ""))
    elif provider_value == DevOpsProvider.GITHUB.value:
        issue = payload.get("issue")
        if issue:
            ticket_id = str(issue.get("number") or issue.get("id", ""))
        # GitHub issue 的 body 可能包含 commit 信息
        if issue and issue.get("body"):
            commit_hash = _extract_commit_from_text(issue.get("body", ""))

    return ticket_id, commit_hash


def _extract_commit_from_text(text: str) -> str:
    """从文本中提取 40 位 commit hash"""
    import re
    if not text:
        return ""
    match = re.search(r'[0-9a-f]{40}', text)
    return match.group(0) if match else ""
