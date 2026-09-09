"""
test_kg_store —— KnowledgeStore 存储层单元测试

通过 tmp_path 文件型 SQLite 走真实 aiosqlite 路径。
"""

from __future__ import annotations

import pytest

from fp_sentinel.knowledge_graph.models import ArchiveQuery, FixRecord, FixSnapshot
from fp_sentinel.knowledge_graph.store import KnowledgeStore, open_store


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "kg.db")


@pytest.fixture
async def store(tmp_db):
    s = KnowledgeStore(tmp_db)
    async with s:
        yield s


def _snapshot(name: str = "proj", version: str = "v1") -> FixSnapshot:
    return FixSnapshot(
        id="", project_name=name, project_path=f"/tmp/{name}",
        version=version, language="python", scanner="semgrep",
        total_findings=3, by_severity={"HIGH": 2, "LOW": 1},
        by_category={"sqli": 2, "xss": 1}, duration_seconds=1.5,
        report_kind="compliance", report_text="Generated report",
        fix_cve_hits=2, fix_knowledge_hits=5,
    )


def _record(snapshot_id: str, project: str = "proj",
            rule_id: str = "py.injection.sql", category: str = "sqli",
            cwe: str = "CWE-89", severity: str = "HIGH",
            reference_cve: str = "CVE-2012-2122",
            line_start: int = 10) -> FixRecord:
    return FixRecord(
        id="", snapshot_id=snapshot_id, finding_id=f"f-{rule_id}",
        project_name=project, project_path=f"/tmp/{project}",
        rule_id=rule_id, severity=severity, file_path="app.py",
        line_start=line_start, category=category, language="python",
        cwe=cwe, reference_cve=reference_cve, fix_title="SQLi fix",
        fix_diff="--- a\n+++ b", incident_note="note",
    )


@pytest.mark.asyncio
async def test_archive_snapshot_generates_id_and_persists(store):
    saved = await store.archive_snapshot(_snapshot())
    assert saved.id
    got = await store.get_snapshot(saved.id)
    assert got is not None
    assert got.project_name == "proj"
    assert got.by_severity == {"HIGH": 2, "LOW": 1}
    assert got.by_category == {"sqli": 2, "xss": 1}
    assert got.report_text.startswith("Generated report")


@pytest.mark.asyncio
async def test_archive_records_and_search_by_category(store):
    snap = await store.archive_snapshot(_snapshot())
    rows = await store.archive_records(snap.id, [
        _record(snap.id, rule_id="py.injection.sql"),
        _record(snap.id, rule_id="js.xss.innerhtml", category="xss",
                cwe="CWE-79", severity="MEDIUM", reference_cve="CVE-2014-9031"),
    ])
    assert len(rows) == 2
    for r in rows:
        assert r.snapshot_id == snap.id
    assert len(await store.search_records(ArchiveQuery(category="sqli"))) == 1
    assert len(await store.search_records(ArchiveQuery(), snapshot_id=snap.id)) == 2


@pytest.mark.asyncio
async def test_count_snapshots_and_records(store):
    s1 = await store.archive_snapshot(_snapshot("p1", "v1"))
    await store.archive_snapshot(_snapshot("p2", "v2"))
    await store.archive_records(s1.id, [_record(s1.id), _record(s1.id)])
    assert await store.count_snapshots(ArchiveQuery(project_name="p1")) == 1
    assert await store.count_snapshots(ArchiveQuery()) == 2
    assert await store.count_records(ArchiveQuery(), snapshot_id=s1.id) == 2


@pytest.mark.asyncio
async def test_search_snapshots_by_version_and_time(store):
    snap = await store.archive_snapshot(_snapshot("p", "v3"))
    got = await store.search_snapshots(ArchiveQuery(version="v3"))
    assert len(got) == 1 and got[0].id == snap.id
    assert await store.search_snapshots(ArchiveQuery(version="never")) == []


@pytest.mark.asyncio
async def test_search_records_by_rule_prefix(store):
    snap = await store.archive_snapshot(_snapshot())
    await store.archive_records(snap.id, [
        _record(snap.id, rule_id="py.injection.sql"),
        _record(snap.id, rule_id="py.injection.format"),
        _record(snap.id, rule_id="js.xss.innerhtml", category="xss"),
    ])
    recs = await store.search_records(ArchiveQuery(rule_id="py.injection."))
    assert len(recs) == 2


@pytest.mark.asyncio
async def test_search_records_by_severity(store):
    snap = await store.archive_snapshot(_snapshot())
    await store.archive_records(snap.id, [
        _record(snap.id, severity="CRITICAL", reference_cve="CVE-2020-0001"),
        _record(snap.id, severity="LOW"),
    ])
    assert len(await store.search_records(ArchiveQuery(severity="CRITICAL"))) == 1


@pytest.mark.asyncio
async def test_stats(store):
    assert (await store.stats())["snapshots"] == 0
    s = await store.archive_snapshot(_snapshot())
    await store.archive_records(s.id, [
        _record(s.id), _record(s.id, reference_cve=""), _record(s.id),
    ])
    st = await store.stats()
    assert st["snapshots"] == 1
    assert st["records"] == 3
    assert st["cve_hits"] == 2
    assert st["projects"] == 1
    assert st["total_findings"] == 3


@pytest.mark.asyncio
async def test_purge_keeps_recent_and_purge_old(tmp_path):
    # 使用独立 store（含 now=now 写入），验证保留最近 + 清理未来过期。
    s = KnowledgeStore(str(tmp_path / "pg.db"))
    async with s:
        snap = await s.archive_snapshot(_snapshot())
        await s.archive_records(snap.id, [_record(snap.id)])
        # days=1 表示 1 天前过期的被清理：刚写入的不会被清
        removed_new = await s.purge(days=1)
        assert removed_new == 0
        assert await s.count_snapshots(ArchiveQuery()) == 1

        # 手动把 snapshot 时间改为很久以前，再 purge 应能清理
        await s.conn.execute(
            "UPDATE kg_snapshots SET archived_at = '2000-01-01T00:00:00'")
        await s.conn.commit()
        removed = await s.purge(days=1)
        assert removed == 1
        assert await s.count_snapshots(ArchiveQuery()) == 0


@pytest.mark.asyncio
async def test_limit_and_offset_pagination(store):
    snap = await store.archive_snapshot(_snapshot())
    many = [_record(snap.id, line_start=i, reference_cve="") for i in range(10)]
    await store.archive_records(snap.id, many)
    assert len(await store.search_records(ArchiveQuery(limit=3, offset=0))) == 3
    assert len(await store.search_records(ArchiveQuery(limit=3, offset=9))) == 1


@pytest.mark.asyncio
async def test_get_snapshot_missing_returns_none(store):
    assert await store.get_snapshot("nonexistent") is None


def test_open_store_returns_instance_with_wal(tmp_path):
    db = tmp_path / "kg.db"
    s = open_store(str(db))
    assert isinstance(s, KnowledgeStore)
    assert s.wal_mode is True
