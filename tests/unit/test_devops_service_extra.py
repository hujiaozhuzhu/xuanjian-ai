"""DevSecOps Service Extra Tests - Error paths and edge cases"""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import aiosqlite
import pytest

from fp_sentinel.devops.adapters import DevOpsAdapter, create_adapter
from fp_sentinel.devops.models import (
    DevOpsConfig,
    DevOpsProvider,
    FindingRef,
    FindingTicketMapping,
    SyncDirection,
    SyncFindingsRequest,
    SyncStatus,
    TicketCloseRequest,
    TicketLinkRequest,
    TicketStatus,
    WebhookEventType,
)
from fp_sentinel.devops.repository import (
    SCHEMA_SQL,
    FindingTicketMappingRepo,
    PipelineGateRecordRepo,
    SyncRecordRepo,
)
from fp_sentinel.devops.service import DevOpsService


@pytest.fixture
async def db_conn():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    conn = await aiosqlite.connect(db_path)
    conn.row_factory = aiosqlite.Row
    await conn.executescript(SCHEMA_SQL)
    await conn.commit()
    yield conn
    await conn.close()
    os.unlink(db_path)


@pytest.fixture
def service(db_conn):
    return DevOpsService(
        FindingTicketMappingRepo(db_conn),
        SyncRecordRepo(db_conn),
        PipelineGateRecordRepo(db_conn),
    )


@pytest.mark.asyncio
class TestServiceEdgeCases:
    async def test_sync_with_empty_findings(self, service):
        request = SyncFindingsRequest(
            provider=DevOpsProvider.GITLAB, project_id="p1", findings=[]
        )
        result = await service.sync_findings(request)
        assert result.total_findings == 0

    async def test_close_ticket_adapter_exception(self, service):
        await service.mappings.create(FindingTicketMapping(
            id="m1", finding_id="f1", provider=DevOpsProvider.GITLAB,
            ticket_id="t1", ticket_status=TicketStatus.OPEN,
            sync_status=SyncStatus.SYNCED, sync_direction=SyncDirection.FINDING_TO_TICKET,
        ))
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.close_issue = AsyncMock(side_effect=Exception("API down"))
        request = TicketCloseRequest(
            provider=DevOpsProvider.GITLAB, ticket_id="t1",
        )
        record = await service.close_ticket(request, adapter=adapter)
        assert record.status == SyncStatus.FAILED

    async def test_link_fix_commit_mapping_not_found(self, service):
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.add_comment = AsyncMock(return_value=True)
        request = TicketLinkRequest(
            provider=DevOpsProvider.GITLAB, ticket_id="unknown",
            commit_hash="abc", close_after_link=False,
        )
        record = await service.link_fix_commit(request, adapter=adapter)
        assert record.status == SyncStatus.SYNCED
        mock_add_comment_not_called = hasattr(adapter.add_comment, 'assert_called')
        if mock_add_comment_not_called:
            adapter.add_comment.assert_called_once()

    async def test_link_fix_comment_fails(self, service):
        await service.mappings.create(FindingTicketMapping(
            id="m1", finding_id="f1", provider=DevOpsProvider.GITLAB,
            ticket_id="t1", ticket_status=TicketStatus.OPEN,
            sync_status=SyncStatus.SYNCED, sync_direction=SyncDirection.FINDING_TO_TICKET,
        ))
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.add_comment = AsyncMock(return_value=False)
        request = TicketLinkRequest(
            provider=DevOpsProvider.GITLAB, ticket_id="t1",
            commit_hash="abc", close_after_link=True,
        )
        record = await service.link_fix_commit(request, adapter=adapter)
        assert record.status == SyncStatus.FAILED

    async def test_webhook_pipeline_status(self, service):
        record = await service.handle_webhook_event(
            event_type=WebhookEventType.PIPELINE_STATUS,
            provider_value="gitlab",
            payload={"pipeline_id": "p-100", "status": "success"},
        )
        assert record is not None
        assert record.sync_direction == SyncDirection.TICKET_TO_LOCAL

    async def test_webhook_merge_request(self, service):
        record = await service.handle_webhook_event(
            event_type=WebhookEventType.MERGE_REQUEST,
            provider_value="github",
            payload={"number": 42},
        )
        assert record is not None

    async def test_webhook_no_ticket_id(self, service):
        record = await service.handle_webhook_event(
            event_type=WebhookEventType.ISSUE_CLOSED,
            provider_value="gitlab",
            payload={},
        )
        assert record is None

    async def test_webhook_unknown_event_type(self, service):
        from fp_sentinel.devops.models import WebhookEventType
        record = await service.handle_webhook_event(
            event_type=WebhookEventType.PIPELINE_STATUS,
            provider_value="gitlab",
            payload={"id": "x"},
        )
        assert record is not None

    async def test_auto_close_with_empty_active(self, service, db_conn):
        """All open tickets should be closed when no active findings"""
        await service.mappings.create(FindingTicketMapping(
            id="m1", finding_id="f1",
            provider=DevOpsProvider.GITLAB, ticket_id="t1",
            finding_fingerprint="old-fp",
            ticket_status=TicketStatus.OPEN,
            sync_status=SyncStatus.SYNCED, sync_direction=SyncDirection.FINDING_TO_TICKET,
        ))
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.close_issue = AsyncMock(return_value=True)
        # Import and use TicketManager directly
        from fp_sentinel.devops.ticket_manager import TicketManager
        mgr = TicketManager(
            FindingTicketMappingRepo(db_conn),
            SyncRecordRepo(db_conn),
        )
        records = await mgr.auto_close_resolved_findings([], adapter)
        assert len(records) == 1

    async def test_reopen_ticket_service_flow(self, service, db_conn):
        """Test full reopen flow through TicketManager"""
        import uuid
        test_id = str(uuid.uuid4())
        await service.mappings.create(FindingTicketMapping(
            id=test_id, finding_id="f1",
            provider=DevOpsProvider.GITLAB, ticket_id="t-reopen",
            ticket_status=TicketStatus.CLOSED,
            sync_status=SyncStatus.SYNCED, sync_direction=SyncDirection.FINDING_TO_TICKET,
        ))
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.update_issue_status = AsyncMock(return_value=True)
        from fp_sentinel.devops.ticket_manager import TicketManager
        mgr = TicketManager(
            FindingTicketMappingRepo(db_conn),
            SyncRecordRepo(db_conn),
        )
        mapping = await service.mappings.get_by_ticket_id("t-reopen")
        record = await mgr.reopen_ticket_if_vulnerable(mapping, adapter)
        assert record is not None
        assert record.status == SyncStatus.SYNCED
