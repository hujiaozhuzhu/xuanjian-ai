"""DevSecOps Service Tests"""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import aiosqlite
import pytest

from fp_sentinel.devops.adapters import DevOpsAdapter
from fp_sentinel.devops.models import (
    DevOpsProvider,
    FindingRef,
    FindingTicketMapping,
    PipelineGateRequest,
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
from fp_sentinel.devops.service import DevOpsService, _extract_commit_from_text


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


@pytest.fixture
def mock_adapter():
    adapter = MagicMock(spec=DevOpsAdapter)
    adapter.create_issue = AsyncMock(return_value=("t1", "GL-10", "https://gl.example.com/i/10"))
    adapter.close_issue = AsyncMock(return_value=True)
    adapter.add_comment = AsyncMock(return_value=True)
    adapter.update_issue_status = AsyncMock(return_value=True)
    return adapter


@pytest.mark.asyncio
class TestSyncFindings:
    async def test_creates_tickets(self, service, mock_adapter):
        request = SyncFindingsRequest(
            provider=DevOpsProvider.GITLAB,
            project_id="p1",
            findings=[
                FindingRef(id="f1", severity="HIGH", rule_id="sql"),
            ],
        )
        result = await service.sync_findings(request, adapter=mock_adapter)
        assert result.created_count == 1
        assert result.status == SyncStatus.SYNCED

    async def test_skips_duplicates(self, service, mock_adapter):
        request = SyncFindingsRequest(
            provider=DevOpsProvider.GITLAB,
            project_id="p1",
            findings=[FindingRef(id="f1", severity="HIGH", rule_id="sql")],
        )
        await service.sync_findings(request, adapter=mock_adapter)
        result = await service.sync_findings(request, adapter=mock_adapter)
        assert result.skipped_count == 1
        assert result.created_count == 0

    async def test_dry_run(self, service, mock_adapter):
        request = SyncFindingsRequest(
            provider=DevOpsProvider.GITLAB,
            project_id="p1",
            findings=[FindingRef(id="f1", severity="HIGH")],
            dry_run=True,
        )
        result = await service.sync_findings(request, adapter=mock_adapter)
        assert result.dry_run is True
        mock_adapter.create_issue.assert_not_called()

    async def test_failure_handling(self, service):
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.create_issue = AsyncMock(return_value=(None, None, None))
        request = SyncFindingsRequest(
            provider=DevOpsProvider.GITLAB,
            project_id="p1",
            findings=[FindingRef(id="f1", severity="HIGH", rule_id="sql")],
        )
        result = await service.sync_findings(request, adapter=adapter)
        assert result.failed_count == 1


@pytest.mark.asyncio
class TestEvaluatePipelineGate:
    async def test_persists(self, service):
        request = PipelineGateRequest(
            provider=DevOpsProvider.GITLAB,
            project_id="p1",
            commit_hash="abc",
            findings=[FindingRef(severity="HIGH", rule_id="sql")],
        )
        result = await service.evaluate_pipeline_gate(request, persist=True)
        assert result.verdict.value == "block"
        record = await service.gates.get_latest_by_commit("p1", "abc")
        assert record is not None

    async def test_no_persist(self, service):
        request = PipelineGateRequest(
            provider=DevOpsProvider.GITLAB,
            project_id="p2",
            findings=[],
        )
        result = await service.evaluate_pipeline_gate(request, persist=False)
        assert result.verdict.value == "pass"


@pytest.mark.asyncio
class TestHandleWebhookEvent:
    async def test_issue_closed(self, service):
        await service.mappings.create(FindingTicketMapping(
            id="m1", finding_id="f1",
            provider=DevOpsProvider.GITLAB,
            ticket_id="42",
            ticket_status=TicketStatus.OPEN,
            sync_status=SyncStatus.SYNCED,
            sync_direction=SyncDirection.FINDING_TO_TICKET,
        ))
        record = await service.handle_webhook_event(
            event_type=WebhookEventType.ISSUE_CLOSED,
            provider_value="gitlab",
            payload={"object_attributes": {"iid": 42, "id": 42}},
        )
        assert record is not None


@pytest.mark.asyncio
class TestCloseTicket:
    async def test_close_existing(self, service, mock_adapter):
        await service.mappings.create(FindingTicketMapping(
            id="m1", finding_id="f1",
            provider=DevOpsProvider.GITLAB,
            ticket_id="t1",
            ticket_status=TicketStatus.OPEN,
            sync_status=SyncStatus.SYNCED,
            sync_direction=SyncDirection.FINDING_TO_TICKET,
        ))
        request = TicketCloseRequest(
            provider=DevOpsProvider.GITLAB, ticket_id="t1",
        )
        record = await service.close_ticket(request, adapter=mock_adapter)
        assert record.status == SyncStatus.SYNCED

    async def test_close_unknown(self, service, mock_adapter):
        request = TicketCloseRequest(
            provider=DevOpsProvider.GITLAB, ticket_id="nonexistent",
        )
        record = await service.close_ticket(request, adapter=mock_adapter)
        assert record.status == SyncStatus.FAILED


@pytest.mark.asyncio
class TestGetStats:
    async def test_empty(self, service):
        stats = await service.get_stats()
        assert stats.total_mappings == 0

    async def test_with_data(self, service):
        await service.mappings.create(FindingTicketMapping(
            finding_id="f1", provider=DevOpsProvider.GITLAB,
            ticket_id="t1", ticket_status=TicketStatus.OPEN,
            sync_status=SyncStatus.SYNCED, sync_direction=SyncDirection.FINDING_TO_TICKET,
        ))
        stats = await service.get_stats()
        assert stats.total_mappings == 1
        assert stats.open_tickets == 1


class TestExtractCommit:
    def test_finds_hash(self):
        text = "Fixed in abc123def456789012345678901234567890abcd"
        assert _extract_commit_from_text(text) == "abc123def456789012345678901234567890abcd"

    def test_no_hash(self):
        assert _extract_commit_from_text("no commit") == ""

    def test_empty(self):
        assert _extract_commit_from_text("") == ""
