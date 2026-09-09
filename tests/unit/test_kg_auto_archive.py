"""
test_kg_auto_archive —— 自动归档钩子单元测试 + REST 路由冒烟测试
"""

import asyncio
from typing import Dict, List

import pytest

from fp_sentinel.knowledge_graph.features.auto_archive import (
    AutoArchiver,
    attach_kg_metadata,
    archive_scan,
)
from fp_sentinel.knowledge_graph.features.query_plugin import KnowledgeQueryPlugin
from fp_sentinel.knowledge_graph.models import ArchiveQuery, KnowledgeMatch
from fp_sentinel.knowledge_graph.store import open_store


def _finds() -> List[Dict]:
    return [
        {"id": "f1", "rule_id": "py.injection.sql", "severity": "HIGH",
         "cwe": "CWE-89", "language": "python",
         "file_path": "app.py", "line_start": 10, "category": "sqli",
         "scanner": "python_scanner", "confidence": 0.8,
         "code_snippet": "q = 'SELECT ' + uid", "message": "sqli"},
        {"id": "f2", "rule_id": "js.xss.innerhtml", "severity": "MEDIUM",
         "cwe": "CWE-79", "language": "javascript",
         "file_path": "app.js", "line_start": 5, "category": "xss",
         "scanner": "js_scanner", "confidence": 0.6,
         "code_snippet": "el.innerHTML = x", "message": "xss"},
    ]


@pytest.fixture
async def empty_store(tmp_path):
    s = open_store(str(tmp_path / "kg.db"))
    async with s:
        yield s


@pytest.mark.asyncio
async def test_archive_scan_creates_snapshot_with_hits(tmp_path):
    result = await archive_scan(
        project_name="myproj", project_path="/tmp/myproj",
        findings=_finds(), report_md="# report", version="v2",
        language="python", scanner="python_scanner",
        report_kind="compliance", duration_seconds=1.2,
        db_path=str(tmp_path / "kg2.db"),
        top_k=5,
    )
    assert result["total_findings"] == 2
    assert result["snapshot_id"]
    # fallback knowledge guaranteed >=1
    assert result["knowledge_hits"] >= 2  # 每条 finding 至少召回 1 条
    assert result["cve_hits"] >= 1
    assert result["by_severity"].get("HIGH", 0) >= 1


@pytest.mark.asyncio
async def test_archive_scan_persists_records_queryable(tmp_path):
    result = await archive_scan(
        project_name="p", project_path="/tmp/p", findings=_finds(), version="v1",
        db_path=str(tmp_path / "kg3.db"),
    )
    s = open_store(str(tmp_path / "kg3.db"))
    async with s:
        snap = await s.get_snapshot(result["snapshot_id"])
        assert snap is not None
        recs = await s.search_records(
            ArchiveQuery(snapshot_id=result["snapshot_id"]))
        assert len(recs) == 2
        assert snap.total_findings == 2


@pytest.mark.asyncio
async def test_archive_scan_empty_findings(tmp_path):
    result = await archive_scan(
        project_name="p", project_path="/tmp/p", findings=[], version="v1",
        db_path=str(tmp_path / "kg_empty.db"),
    )
    assert result["total_findings"] == 0
    assert result["knowledge_hits"] == 0
    assert result["snapshot_id"]


@pytest.mark.asyncio
async def test_auto_archiver_context_manager_closes_store(tmp_path):
    archiver = AutoArchiver(db_path=str(tmp_path / "kg4.db"))
    async with archiver:
        res = await archiver.archive_scan(
            project_name="x", project_path="/tmp/x", findings=_finds())
    assert res["snapshot_id"]


@pytest.mark.asyncio
async def test_auto_archiver_preserves_external_store(tmp_path):
    external = open_store(str(tmp_path / "kg_ext.db"))
    await external.connect(); await external.initialize()
    try:
        archiver = AutoArchiver(store=external)
        async with archiver:
            res = await archiver.archive_scan(
                project_name="ext", project_path="/tmp/ext",
                findings=_finds())
        assert res["snapshot_id"]
        # external store should remain open
        assert external.conn is not None
        # cleanup
        count = await external.count_records(ArchiveQuery(snapshot_id=res["snapshot_id"]))
        assert count == 2
    finally:
        await external.close()


def test_attach_kg_metadata_attaches_and_is_idempotent():
    f = {"id": "f1", "rule_id": "py.injection.sql", "metadata": {}}
    matches = {"f1": [KnowledgeMatch(
        match_id="r1", rule_id="py.injection.sql", category="sqli",
        reference_cve="CVE-2012-2122", similarity=0.9)]}
    attach_kg_metadata([f], matches)
    assert f["metadata"]["knowledge_graph"]["hits"] == 1
    # idempotent
    attach_kg_metadata([f], matches)
    assert f["metadata"]["knowledge_graph"]["hits"] == 1


def test_attach_kg_metadata_handles_missing_fid():
    f = {"rule_id": "py.injection.sql", "metadata": {}}
    matches = {}
    # no id -> no key in matches, should not crash
    attach_kg_metadata([f], matches)
    assert "knowledge_graph" not in f["metadata"]


# ───────────────────────────── REST route smoke tests ─────────────────────────────


class _DummyFinder:
    def __init__(self) -> None:
        self.posted = None


@pytest.mark.asyncio
async def test_rest_match_endpoint_non_rule():
    from fp_sentinel.knowledge_graph.routes import router
    # we only validate router has expected paths
    paths = [r.path for r in router.routes]
    assert "/api/kg/match" in paths
    assert "/api/kg/archive" in paths
    assert "/api/kg/search" in paths
    assert "/api/kg/stats" in paths
    assert "/api/kg/purge" in paths
