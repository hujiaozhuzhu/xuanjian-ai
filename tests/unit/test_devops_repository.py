"""DevSecOps Repository Tests - SQLite with temp db"""

import asyncio
import os
import tempfile

import aiosqlite
import pytest

from fp_sentinel.devops.models import (
    DevOpsProvider,
    FindingTicketMapping,
    SyncDirection,
    SyncRecord,
    SyncStatus,
    TicketStatus,
)
from fp_sentinel.devops.repository import (
    SCHEMA_SQL,
    FindingTicketMappingRepo,
    SyncRecordRepo,
    PipelineGateRecordRepo,
)


@pytest.fixture
async def db_conn():
    """创建临时数据库连接"""
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
def fresh_mapping():
    return FindingTicketMapping(
        id="m-test-001",
        finding_id="f1",
        finding_fingerprint="abc123",
        provider=DevOpsProvider.GITLAB,
        ticket_id="t1",
        ticket_key="GL-10",
        ticket_url="https://gl.example.com/issues/10",
        ticket_status=TicketStatus.OPEN,
        project_id="proj1",
        repository_url="https://gl.example.com/proj1",
        commit_hash="deadbeef",
        branch="main",
        sync_status=SyncStatus.SYNCED,
        sync_direction=SyncDirection.FINDING_TO_TICKET,
        severity="HIGH",
        rule_id="sql.inj",
    )


@pytest.mark.asyncio
class TestFindingTicketMappingRepo:
    async def test_create_and_get(self, db_conn, fresh_mapping):
        repo = FindingTicketMappingRepo(db_conn)
        created = await repo.create(fresh_mapping)
        assert created.id is not None

        fetched = await repo.get_by_id(created.id)
        assert fetched is not None
        assert fetched.finding_id == "f1"
        assert fetched.ticket_id == "t1"
        assert fetched.provider == DevOpsProvider.GITLAB
        assert fetched.ticket_status == TicketStatus.OPEN
        assert fetched.severity == "HIGH"

    async def test_get_by_finding_id(self, db_conn, fresh_mapping):
        repo = FindingTicketMappingRepo(db_conn)
        created = await repo.create(fresh_mapping)

        fetched = await repo.get_by_finding_id("f1")
        assert fetched is not None
        assert fetched.id == created.id

    async def test_get_by_finding_id_with_provider(self, db_conn, fresh_mapping):
        repo = FindingTicketMappingRepo(db_conn)
        await repo.create(fresh_mapping)

        fetched = await repo.get_by_finding_id("f1", provider="gitlab")
        assert fetched is not None

        fetched_none = await repo.get_by_finding_id("f1", provider="jira")
        assert fetched_none is None

    async def test_get_by_ticket_id(self, db_conn, fresh_mapping):
        repo = FindingTicketMappingRepo(db_conn)
        await repo.create(fresh_mapping)

        fetched = await repo.get_by_ticket_id("t1")
        assert fetched is not None
        assert fetched.finding_id == "f1"

    async def test_update(self, db_conn, fresh_mapping):
        repo = FindingTicketMappingRepo(db_conn)
        created = await repo.create(fresh_mapping)

        ok = await repo.update(
            created.id,
            ticket_status=TicketStatus.CLOSED,
            sync_status=SyncStatus.SYNCED,
            last_sync_at="2026-01-01T00:00:00+00:00",
        )
        assert ok is True

        fetched = await repo.get_by_id(created.id)
        assert fetched.ticket_status == TicketStatus.CLOSED

    async def test_list_mappings(self, db_conn, fresh_mapping):
        repo = FindingTicketMappingRepo(db_conn)
        await repo.create(fresh_mapping)
        await repo.create(FindingTicketMapping(
            finding_id="f2",
            provider=DevOpsProvider.JIRA,
            ticket_id="t2",
            ticket_status=TicketStatus.CLOSED,
            sync_status=SyncStatus.SYNCED,
            sync_direction=SyncDirection.FINDING_TO_TICKET,
            severity="MEDIUM",
        ))

        all_mappings = await repo.list_mappings()
        assert len(all_mappings) == 2

        open_only = await repo.list_mappings(ticket_status="open")
        assert len(open_only) == 1

        gitlab_only = await repo.list_mappings(provider="gitlab")
        assert len(gitlab_only) == 1

    async def test_count(self, db_conn, fresh_mapping):
        repo = FindingTicketMappingRepo(db_conn)
        await repo.create(fresh_mapping)
        await repo.create(FindingTicketMapping(
            finding_id="f2",
            provider=DevOpsProvider.GITLAB,
            ticket_id="t2",
        ))

        assert await repo.count() == 2
        assert await repo.count(provider="gitlab") == 2
        assert await repo.count(ticket_status="open") == 2
        assert await repo.count(ticket_status="closed") == 0

    async def test_metadata_roundtrip(self, db_conn, fresh_mapping):
        repo = FindingTicketMappingRepo(db_conn)
        fresh_mapping.metadata = {"commit": "abc", "scan_id": "s1"}
        created = await repo.create(fresh_mapping)

        fetched = await repo.get_by_id(created.id)
        assert fetched.metadata == {"commit": "abc", "scan_id": "s1"}

    async def test_sync_status_enum_roundtrip(self, db_conn, fresh_mapping):
        repo = FindingTicketMappingRepo(db_conn)
        await repo.create(fresh_mapping)

        fetched = await repo.get_by_id(fresh_mapping.id)
        assert fetched.sync_status == SyncStatus.SYNCED
        assert fetched.ticket_status == TicketStatus.OPEN


@pytest.mark.asyncio
class TestSyncRecordRepo:
    async def test_create_and_list(self, db_conn):
        repo = SyncRecordRepo(db_conn)
        record = SyncRecord(
            mapping_id="m1",
            finding_id="f1",
            provider=DevOpsProvider.GITLAB,
            sync_direction=SyncDirection.FINDING_TO_TICKET,
            status=SyncStatus.SYNCED,
            ticket_id="t1",
            ticket_key="GL-10",
        )
        created = await repo.create(record)
        assert created.id is not None

        records = await repo.list_by_mapping("m1")
        assert len(records) == 1
        assert records[0].status == SyncStatus.SYNCED

    async def test_count_by_status(self, db_conn):
        repo = SyncRecordRepo(db_conn)
        await repo.create(SyncRecord(
            mapping_id="m1", finding_id="f1",
            provider=DevOpsProvider.GITLAB,
            sync_direction=SyncDirection.FINDING_TO_TICKET,
            status=SyncStatus.SYNCED,
        ))
        await repo.create(SyncRecord(
            mapping_id="m2", finding_id="f2",
            provider=DevOpsProvider.GITLAB,
            sync_direction=SyncDirection.FINDING_TO_TICKET,
            status=SyncStatus.FAILED,
        ))

        counts = await repo.count_by_status()
        assert counts[SyncStatus.SYNCED.value] == 1
        assert counts[SyncStatus.FAILED.value] == 1

    async def test_list_all_ordered(self, db_conn):
        repo = SyncRecordRepo(db_conn)
        for i in range(5):
            await repo.create(SyncRecord(
                mapping_id=f"m{i}", finding_id=f"f{i}",
                provider=DevOpsProvider.GITLAB,
                sync_direction=SyncDirection.FINDING_TO_TICKET,
                status=SyncStatus.SYNCED,
            ))
        records = await repo.list_all(limit=3)
        assert len(records) == 3

    async def test_record_deserializes_enums(self, db_conn):
        repo = SyncRecordRepo(db_conn)
        await repo.create(SyncRecord(
            mapping_id="m1", finding_id="f1",
            provider=DevOpsProvider.JIRA,
            sync_direction=SyncDirection.TICKET_TO_LOCAL,
            status=SyncStatus.PENDING,
        ))
        records = await repo.list_by_mapping("m1")
        assert records[0].provider == DevOpsProvider.JIRA
        assert records[0].sync_direction == SyncDirection.TICKET_TO_LOCAL
        assert records[0].status == SyncStatus.PENDING


@pytest.mark.asyncio
class TestPipelineGateRecordRepo:
    async def test_save_and_list(self, db_conn):
        from fp_sentinel.devops.models import PipelineGateResult, PipelineGateVerdict
        repo = PipelineGateRecordRepo(db_conn)
        result = PipelineGateResult(
            verdict=PipelineGateVerdict.BLOCK,
            provider=DevOpsProvider.GITLAB,
            project_id="proj1",
            total_findings=3,
            critical_count=1,
        )
        await repo.save_result(result)

        records = await repo.list_by_project("proj1")
        assert len(records) == 1
        assert records[0]["verdict"] == "block"
        assert records[0]["total_findings"] == 3

    async def test_get_latest_by_commit(self, db_conn):
        from fp_sentinel.devops.models import PipelineGateResult, PipelineGateVerdict
        repo = PipelineGateRecordRepo(db_conn)
        await repo.save_result(PipelineGateResult(
            verdict=PipelineGateVerdict.PASS,
            provider=DevOpsProvider.GITLAB,
            project_id="p1",
            commit_hash="abc",
        ))
        await repo.save_result(PipelineGateResult(
            verdict=PipelineGateVerdict.BLOCK,
            provider=DevOpsProvider.GITLAB,
            project_id="p1",
            commit_hash="abc",
        ))

        latest = await repo.get_latest_by_commit("p1", "abc")
        assert latest is not None
        assert latest["verdict"] == "block"
