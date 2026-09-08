"""DevSecOps Ticket Manager Tests - Mock Adapter"""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import aiosqlite
import pytest

from fp_sentinel.devops.adapters import DevOpsAdapter, fingerprint_finding
from fp_sentinel.devops.models import (
    DevOpsProvider,
    FindingRef,
    FindingTicketMapping,
    SyncDirection,
    SyncRecord,
    SyncStatus,
    TicketCloseRequest,
    TicketLinkRequest,
    TicketStatus,
)
from fp_sentinel.devops.repository import (
    SCHEMA_SQL,
    FindingTicketMappingRepo,
    SyncRecordRepo,
)
from fp_sentinel.devops.ticket_manager import TicketManager


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
def mock_adapter():
    adapter = MagicMock(spec=DevOpsAdapter)
    adapter.close_issue = AsyncMock(return_value=True)
    adapter.add_comment = AsyncMock(return_value=True)
    adapter.update_issue_status = AsyncMock(return_value=True)
    return adapter


def _make_mapping(**kwargs):
    import uuid
    defaults = dict(
        id=str(uuid.uuid4()),
        finding_id="f1",
        finding_fingerprint="fp1",
        provider=DevOpsProvider.GITLAB,
        ticket_id="t1",
        ticket_key="GL-10",
        ticket_status=TicketStatus.OPEN,
        project_id="p1",
        sync_status=SyncStatus.SYNCED,
        sync_direction=SyncDirection.FINDING_TO_TICKET,
    )
    defaults.update(kwargs)
    return FindingTicketMapping(**defaults)


@pytest.mark.asyncio
class TestCloseTicket:
    async def test_successful_close(self, db_conn, mock_adapter):
        repo = FindingTicketMappingRepo(db_conn)
        mapping = _make_mapping()
        await repo.create(mapping)
        sync_repo = SyncRecordRepo(db_conn)
        mgr = TicketManager(repo, sync_repo)

        record = await mgr.close_ticket(mapping, mock_adapter)

        assert record.status == SyncStatus.SYNCED
        assert record.response_summary == "closed"
        mock_adapter.close_issue.assert_called_once()

        updated = await repo.get_by_id(mapping.id)
        assert updated.ticket_status == TicketStatus.CLOSED

    async def test_failed_close(self, db_conn):
        repo = FindingTicketMappingRepo(db_conn)
        mapping = _make_mapping()
        await repo.create(mapping)

        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.close_issue = AsyncMock(return_value=False)
        sync_repo = SyncRecordRepo(db_conn)
        mgr = TicketManager(repo, sync_repo)

        record = await mgr.close_ticket(mapping, adapter)

        assert record.status == SyncStatus.FAILED

    async def test_exception_handling(self, db_conn):
        repo = FindingTicketMappingRepo(db_conn)
        mapping = _make_mapping()
        await repo.create(mapping)

        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.close_issue = AsyncMock(side_effect=Exception("Connection error"))
        sync_repo = SyncRecordRepo(db_conn)
        mgr = TicketManager(repo, sync_repo)

        record = await mgr.close_ticket(mapping, adapter)
        assert record.status == SyncStatus.FAILED
        assert "Connection error" in record.error_message

    async def test_creates_sync_record(self, db_conn, mock_adapter):
        repo = FindingTicketMappingRepo(db_conn)
        await repo.create(_make_mapping())
        sync_repo = SyncRecordRepo(db_conn)
        mgr = TicketManager(repo, sync_repo)

        mapping = await repo.get_by_ticket_id("t1")
        await mgr.close_ticket(mapping, mock_adapter)

        records = await sync_repo.list_by_mapping(mapping.id)
        assert len(records) == 1


@pytest.mark.asyncio
class TestAutoCloseResolvedFindings:
    async def test_closes_fixed_finding(self, db_conn, mock_adapter):
        repo = FindingTicketMappingRepo(db_conn)
        # mapping with fingerprint that won't be in active findings
        await repo.create(_make_mapping(
            finding_id="fixed-finding",
            finding_fingerprint="old-fp",
            ticket_id="old-ticket",
        ))
        sync_repo = SyncRecordRepo(db_conn)
        mgr = TicketManager(repo, sync_repo)

        # Active findings don't include the old fingerprint
        active_findings = [
            FindingRef(rule_id="new", file_path="a.js", line_start=1, severity="HIGH"),
        ]
        records = await mgr.auto_close_resolved_findings(active_findings, mock_adapter)

        assert len(records) == 1
        assert records[0].status == SyncStatus.SYNCED

    async def test_does_not_close_still_vulnerable(self, db_conn, mock_adapter):
        repo = FindingTicketMappingRepo(db_conn)
        fp = fingerprint_finding(FindingRef(
            rule_id="sql", file_path="a.js", line_start=10, severity="HIGH",
        ))
        await repo.create(_make_mapping(
            finding_id="f1",
            finding_fingerprint=fp,
            ticket_id="t1",
        ))
        sync_repo = SyncRecordRepo(db_conn)
        mgr = TicketManager(repo, sync_repo)

        # Same finding still exists
        active_findings = [
            FindingRef(rule_id="sql", file_path="a.js", line_start=10, severity="HIGH"),
        ]
        records = await mgr.auto_close_resolved_findings(active_findings, mock_adapter)
        assert len(records) == 0

    async def test_no_open_mappings(self, db_conn, mock_adapter):
        repo = FindingTicketMappingRepo(db_conn)
        await repo.create(_make_mapping(ticket_status=TicketStatus.CLOSED))
        sync_repo = SyncRecordRepo(db_conn)
        mgr = TicketManager(repo, sync_repo)

        records = await mgr.auto_close_resolved_findings([], mock_adapter)
        assert len(records) == 0


@pytest.mark.asyncio
class TestHandleStatusWebhook:
    async def test_updates_mapping(self, db_conn):
        repo = FindingTicketMappingRepo(db_conn)
        await repo.create(_make_mapping(ticket_id="42"))
        sync_repo = SyncRecordRepo(db_conn)
        mgr = TicketManager(repo, sync_repo)

        record = await mgr.handle_status_webhook(
            ticket_id="42",
            from_status=TicketStatus.OPEN,
            to_status=TicketStatus.CLOSED,
            provider_value="gitlab",
        )

        assert record is not None
        assert record.sync_direction == SyncDirection.TICKET_TO_LOCAL

        updated = await repo.get_by_ticket_id("42")
        assert updated.ticket_status == TicketStatus.CLOSED

    async def test_unknown_ticket(self, db_conn):
        repo = FindingTicketMappingRepo(db_conn)
        sync_repo = SyncRecordRepo(db_conn)
        mgr = TicketManager(repo, sync_repo)

        record = await mgr.handle_status_webhook(
            ticket_id="nonexistent",
            from_status=TicketStatus.OPEN,
            to_status=TicketStatus.CLOSED,
            provider_value="gitlab",
        )
        assert record is None


@pytest.mark.asyncio
class TestLinkCommitToTicket:
    async def test_link_and_close(self, db_conn, mock_adapter):
        repo = FindingTicketMappingRepo(db_conn)
        await repo.create(_make_mapping(ticket_id="t1"))
        sync_repo = SyncRecordRepo(db_conn)
        mgr = TicketManager(repo, sync_repo)

        request = TicketLinkRequest(
            provider=DevOpsProvider.GITLAB,
            ticket_id="t1",
            commit_hash="abc123def456",
            close_after_link=True,
        )
        record = await mgr.link_commit_to_ticket(request, mock_adapter)

        assert record.status == SyncStatus.SYNCED
        mock_adapter.add_comment.assert_called_once()
        mock_adapter.close_issue.assert_called_once()

    async def test_link_without_close(self, db_conn, mock_adapter):
        repo = FindingTicketMappingRepo(db_conn)
        await repo.create(_make_mapping(ticket_id="t1"))
        sync_repo = SyncRecordRepo(db_conn)
        mgr = TicketManager(repo, sync_repo)

        request = TicketLinkRequest(
            provider=DevOpsProvider.GITLAB,
            ticket_id="t1",
            commit_hash="abc123",
            close_after_link=False,
        )
        record = await mgr.link_commit_to_ticket(request, mock_adapter)
        mock_adapter.close_issue.assert_not_called()


@pytest.mark.asyncio
class TestReopenTicket:
    async def test_reopen_closed_ticket(self, db_conn, mock_adapter):
        repo = FindingTicketMappingRepo(db_conn)
        await repo.create(_make_mapping(
            ticket_id="t1",
            ticket_status=TicketStatus.CLOSED,
        ))
        sync_repo = SyncRecordRepo(db_conn)
        mgr = TicketManager(repo, sync_repo)

        mapping = await repo.get_by_ticket_id("t1")
        record = await mgr.reopen_ticket_if_vulnerable(mapping, mock_adapter)

        assert record is not None
        assert record.status == SyncStatus.SYNCED
        updated = await repo.get_by_ticket_id("t1")
        assert updated.ticket_status == TicketStatus.REOPENED

    async def test_skip_open_ticket(self, db_conn, mock_adapter):
        repo = FindingTicketMappingRepo(db_conn)
        await repo.create(_make_mapping(
            ticket_id="t1",
            ticket_status=TicketStatus.OPEN,
        ))
        sync_repo = SyncRecordRepo(db_conn)
        mgr = TicketManager(repo, sync_repo)

        mapping = await repo.get_by_ticket_id("t1")
        record = await mgr.reopen_ticket_if_vulnerable(mapping, mock_adapter)
        assert record is None
