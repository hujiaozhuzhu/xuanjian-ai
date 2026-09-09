"""
test_kg_query_plugin —— 知识图谱查询插件单元测试

覆盖：
- _infer_category    rule_id → category
- score_match        相似度评分（分类/CWE/严重度/语言/规则/时间衰减）
- KnowledgeQueryPlugin.match()    fallback 与归档候选的混合召回 + topK + 去重
- KnowledgeQueryPlugin.batch_match()
- all_fallback_categories / fallback 内置知识访问
"""

import asyncio
from typing import List

import pytest

from fp_sentinel.knowledge_graph.features.query_plugin import (  # noqa: E402
    KnowledgeMatch,
    KnowledgeQueryPlugin,
    _CATEGORY_INDEX,
    _infer_category,
    all_fallback_categories,
    fallback,
    score_match,
)


# ──────────────────── _infer_category ────────────────────

class TestInferCategory:
    def test_sqli_by_injection_rule(self):
        assert _infer_category("py.injection.sql") == "sqli"
        assert _infer_category("java.lang.security.audit.sql-injection") == "sqli"

    def test_xss_by_innerhtml(self):
        assert _infer_category("js.xss.innerhtml") == "xss"

    def test_command_variants(self):
        assert _infer_category("py.injection.command") == "cmd"
        assert _infer_category("py.os.system") == "cmd"

    def test_pickle(self):
        assert _infer_category("py.deserialization.pickle") == "pickle"

    def test_explicit_category_wins(self):
        assert _infer_category("anything", explicit="jwt") == "jwt"

    def test_unknown_falls_back_to_head(self):
        assert _infer_category("abc.def.ghi") == "abc"


# ──────────────────── score_match ────────────────────

class TestScoreMatch:
    def test_perfect_category_match(self):
        s = score_match(
            finding_category="sqli", finding_cwe=None, finding_severity=None,
            finding_language=None, finding_rule_id=None,
            record={"category": "sqli", "archived_at": ""},
        )
        assert 0.49 < s < 0.61  # 0.50 + 少量时间衰减

    def test_cwe_boosts(self):
        s = score_match(
            finding_category=None, finding_cwe="CWE-89", finding_severity=None,
            finding_language=None, finding_rule_id=None,
            record={"cwe": "CWE-89", "archived_at": ""},
        )
        assert s >= 0.30

    def test_severity_match_small_boost(self):
        base = score_match(
            finding_category="xss", finding_cwe=None, finding_severity="HIGH",
            finding_language=None, finding_rule_id=None,
            record={"category": "xss", "archived_at": ""},
        )
        added = score_match(
            finding_category="xss", finding_cwe=None, finding_severity="HIGH",
            finding_language=None, finding_rule_id=None,
            record={"category": "xss", "severity": "HIGH", "archived_at": ""},
        )
        assert added > base

    def test_language_boosts(self):
        base = score_match(
            finding_category="ssrf", finding_cwe=None, finding_severity=None,
            finding_language="python", finding_rule_id=None,
            record={"category": "ssrf", "archived_at": ""},
        )
        added = score_match(
            finding_category="ssrf", finding_cwe=None, finding_severity=None,
            finding_language="python", finding_rule_id=None,
            record={"category": "ssrf", "language": "python", "archived_at": ""},
        )
        assert added > base

    def test_rule_id_match_boosts(self):
        base = score_match(
            finding_category="secret", finding_cwe=None,
            finding_severity=None, finding_language=None,
            finding_rule_id="py.crypto.hardcoded_key",
            record={"category": "secret", "rule_id": "py.crypto.other", "archived_at": ""},
        )
        added = score_match(
            finding_category="secret", finding_cwe=None,
            finding_severity=None, finding_language=None,
            finding_rule_id="py.crypto.hardcoded_key",
            record={"category": "secret", "rule_id": "py.crypto.hardcoded_key", "archived_at": ""},
        )
        assert added > base

    def test_score_bounded(self):
        s = score_match(
            finding_category="sqli", finding_cwe="CWE-89", finding_severity="CRITICAL",
            finding_language="java", finding_rule_id="r",
            record={"category": "sqli", "cwe": "CWE-89", "severity": "CRITICAL",
                    "language": "java", "rule_id": "r", "archived_at": ""},
        )
        assert 0.05 <= s <= 1.0


# ──────────────────── KnowledgeQueryPlugin.match ────────────────────

def _sample_archive(rule_id="py.injection.sql", **kw) -> dict:
    base = {
        "id": "rec-1", "rule_id": rule_id, "severity": "HIGH",
        "file_path": "app.py", "line_start": 10, "archived_at": "",
        "category": "sqli", "language": "python",
        "fix_title": "fix", "fix_diff": "diff",
        "reference_cve": "CVE-2012-2122", "incident_note": "note",
    }
    base.update(kw)
    return base


async def _rule_archive(*, category=None, cwe=None, language=None, limit=50) -> List[dict]:
    if category == "sqli":
        return [_sample_archive()]
    return []


@pytest.mark.asyncio
async def test_match_fallback_only_when_archive_fn_none():
    plugin = KnowledgeQueryPlugin(archive_fn=None, top_k=5)
    matches = await plugin.match(rule_id="py.injection.sql", category=None, cwe="CWE-89",
                                 severity="HIGH", language="python")
    assert isinstance(matches, list)
    assert len(matches) >= 1
    assert any(m.reference_cve == "CVE-2012-2122" for m in matches)


@pytest.mark.asyncio
async def test_match_returns_list_of_knowledge_match():
    plugin = KnowledgeQueryPlugin(archive_fn=_rule_archive, top_k=5)
    matches = await plugin.match(rule_id="py.injection.sql")
    for m in matches:
        assert isinstance(m, KnowledgeMatch)
        assert 0.0 <= m.similarity <= 1.0


@pytest.mark.asyncio
async def test_match_respects_top_k():
    async def big_archive(*, category=None, cwe=None, language=None, limit=50):
        return [_sample_archive(rule_id=f"r{i}", category="sqli") for i in range(30)]

    plugin = KnowledgeQueryPlugin(archive_fn=big_archive, top_k=3)
    matches = await plugin.match(rule_id="r0", category="sqli")
    assert len(matches) <= 3


@pytest.mark.asyncio
async def test_match_dedup_keeps_highest_similarity():
    async def dup_archive(*, category=None, cwe=None, language=None, limit=50):
        return [_sample_archive(rule_id="r", category="sqli"),
                _sample_archive(rule_id="r", category="sqli")]

    plugin = KnowledgeQueryPlugin(archive_fn=dup_archive, top_k=5)
    matches = await plugin.match(rule_id="r", category="sqli")
    assert len(matches) == 1


@pytest.mark.asyncio
async def test_match_archive_failure_falls_back_to_fallback():
    async def boom(*, category=None, cwe=None, language=None, limit=50):
        raise RuntimeError("sqlite down")

    plugin = KnowledgeQueryPlugin(archive_fn=boom, top_k=5)
    matches = await plugin.match(rule_id="py.injection.sql")
    # 内置 fallback 应仍能命中 sqli
    assert len(matches) >= 1
    assert matches[0].category == "sqli"


@pytest.mark.asyncio
async def test_match_min_score_filters_low_archive_but_keeps_fallback():
    # archive 候选总分约 0.50；min_score=0.60 会把全部归档候选滤掉
    async def low_archive(*, category=None, cwe=None, language=None, limit=50):
        return [_sample_archive(category="ssrf",
                                rule_id="totally.different.rule",
                                cwe="CWE-000")]

    plugin = KnowledgeQueryPlugin(archive_fn=low_archive, top_k=5, min_score=0.60)
    matches = await plugin.match(rule_id="py.injection.sql", category="sqli",
                                 language="python")
    # 归档候选被过滤，但内置 fallback 仍命中 sqli
    assert len(matches) >= 1
    assert matches[0].category == "sqli"


# ──────────────────── batch_match ────────────────────

@pytest.mark.asyncio
async def test_batch_match_attaches_matches_per_finding():
    plugin = KnowledgeQueryPlugin(archive_fn=None, top_k=3)
    findings = [
        {"id": "f1", "rule_id": "py.injection.sql", "severity": "HIGH", "cwe": "CWE-89"},
        {"id": "f2", "rule_id": "weird.rule", "severity": "LOW"},
    ]
    out = await plugin.batch_match(findings)
    assert "f1" in out
    assert len(out["f1"]) >= 1  # sqli 必被 fallback 命中

    # f2 没有已知 category，不应出现在字典里
    assert "f2" not in out


@pytest.mark.asyncio
async def test_batch_match_handles_pydantic_finding():
    from fp_sentinel.models import Finding, Severity

    plugin = KnowledgeQueryPlugin(archive_fn=None, top_k=3)
    findings = [
        Finding(scanner="semgrep", rule_id="py.injection.sql",
                severity=Severity.HIGH, file_path="app.py", line_start=1, cwe="CWE-89"),
    ]
    out = await plugin.batch_match(findings)
    assert len(out) == 1
    for fid, matches in out.items():
        assert fid  # 非空 fid
        for m in matches:
            assert m.category == "sqli"


@pytest.mark.asyncio
async def test_batch_match_empty_findings():
    plugin = KnowledgeQueryPlugin(archive_fn=None)
    assert await plugin.batch_match([]) == {}


@pytest.mark.asyncio
async def test_batch_match_graceful_when_archive_fn_returns_bad_type():
    async def bad(*, category=None, cwe=None, language=None, limit=50):
        return "not a list"

    plugin = KnowledgeQueryPlugin(archive_fn=bad)
    out = await plugin.batch_match([{"id": "a", "rule_id": "py.injection.sql"}])
    # 不应崩溃
    assert isinstance(out, dict)


# ──────────────────── fallback helpers ────────────────────

class TestFallback:
    def test_all_fallback_categories_nonempty(self):
        cats = all_fallback_categories()
        assert "sqli" in cats and "xss" in cats

    def test_fallback_returns_known_dict(self):
        r = fallback("sqli")
        assert r is not None
        assert r["category"] == "sqli"
        assert r["reference_cve"].startswith("CVE")

    def test_fallback_unknown_is_none(self):
        assert fallback("nosuchcategory") is None

    def test_all_builtin_entries_have_required_keys(self):
        for cat, entry in _CATEGORY_INDEX.items():
            assert "category" in entry
            assert "reference_cve" in entry
            assert "fix_diff" in entry
            assert entry["category"] == cat
