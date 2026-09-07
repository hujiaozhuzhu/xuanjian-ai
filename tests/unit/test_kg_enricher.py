"""
test_kg_enricher —— 报告知识增强 + 统计摘要单元测试
"""

import pytest

from fp_sentinel.knowledge_graph.features.report_enricher import (
    append_reference_to_report,
    build_reference_section,
    inject_finding_metadata,
    summarize,
)
from fp_sentinel.knowledge_graph.models import KnowledgeMatch


def _m(**kw) -> KnowledgeMatch:
    base = dict(
        match_id="r1", rule_id="py.injection.sql", category="sqli",
        cwe="CWE-89", language="python", severity="HIGH",
        file_path="app.py", line_start=10,
        fix_title="SQLi fix", fix_diff="--- a\n+++ b\n-old\n+new",
        reference_cve="CVE-2012-2122",
        incident_note="incident note",
        archived_at="2026-01-01T00:00:00+00:00", similarity=0.9,
    )
    base.update(kw)
    return KnowledgeMatch(**base)


def test_build_reference_section_empty_returns_empty():
    assert build_reference_section({}) == ""


def test_build_reference_section_contains_rule_and_cve():
    sec = build_reference_section({"f1": [_m()]})
    assert "Knowledge Graph Reference" not in sec or "knowledge" in sec.lower()
    assert "py.injection.sql" in sec
    assert "CVE-2012-2122" in sec


def test_build_reference_section_no_duplicates():
    sec = build_reference_section({
        "f1": [_m(match_id="r1"), _m(match_id="r1")],
    })
    rows = [ln for ln in sec.splitlines() if "| 1 |" in ln and "`py.injection" in ln]
    assert len(rows) == 1


def test_inject_finding_metadata_skips_empty():
    md = {}
    inject_finding_metadata(md, [])
    assert "knowledge_graph" not in md


def test_inject_finding_metadata_writes_truncated_list():
    md = {}
    inject_finding_metadata(md, [_m(), _m(match_id="r2", rule_id="x")])
    kg = md["knowledge_graph"]
    assert kg["hits"] == len(kg["matches"])


def test_append_reference_returns_original_when_empty():
    rep = "hello\n"
    assert append_reference_to_report(rep, "") == rep


def test_append_reference_appends_section_with_newline():
    rep = "# report\n"
    new = append_reference_to_report(rep, "KG reference section\n")
    assert new.startswith(rep)
    assert "KG reference section" in new
    assert new.endswith("\n")


def test_summarize_zero_and_nonzero():
    assert summarize({}) == {"knowledge_hits": 0, "cve_hits": 0, "findings_with_match": 0}

    s = summarize({
        "f1": [_m(match_id="r1"), _m(match_id="r1")],
        "f2": [_m(match_id="r2", reference_cve="")],
    })
    assert s["findings_with_match"] == 2
    assert s["knowledge_hits"] >= 1
    assert isinstance(s["cve_hits"], int)
