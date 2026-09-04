"""
P1 画像数据模型与 SQLite 新表测试
"""

import pytest

from fp_sentinel.database.connection import Database
from fp_sentinel.models import Finding, Severity
from fp_sentinel.profile.models import (
    AttributionRecord,
    ProfileRepo,
    alias_hash,
    decrypt_name,
    encrypt_name,
    ensure_profile_tables,
    get_profile_key,
)


async def _make_db(tmp_path):
    db = Database(str(tmp_path / "profile.db"))
    await db.connect()
    await db.initialize()
    await ensure_profile_tables(db)
    return db


@pytest.mark.asyncio
async def test_ensure_profile_tables_creates_new_tables_only(tmp_path):
    """画像表创建成功，且既有 findings/projects 表不受影响"""
    db = await _make_db(tmp_path)
    try:
        cursor = await db.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row["name"] for row in await cursor.fetchall()}
        assert {"developer_alias", "profile_snapshot", "scan_attribution", "finding_status"} <= tables
        # 既有表仍在
        assert {"projects", "scan_history", "findings", "false_positive_marks"} <= tables
    finally:
        await db.close()


def test_alias_hash_deterministic_and_anonymized():
    """SHA256 别名化：确定性、定长、不泄露明文"""
    h1 = alias_hash("alice@example.com")
    h2 = alias_hash("alice@example.com")
    h3 = alias_hash("bob@example.com")
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 16
    assert all(c in "0123456789abcdef" for c in h1)
    assert "alice" not in h1 and "example.com" not in h1


def test_name_encryption_roundtrip_and_no_plaintext():
    """display_name 本地加密：可解密还原，密文不含明文；密钥文件与数据库同目录"""
    import os
    import tempfile

    db_file = os.path.join(tempfile.mkdtemp(), "data.db")
    key = get_profile_key(db_file)
    key_file = os.path.join(os.path.dirname(db_file), "profile.key")
    assert os.path.exists(key_file)

    enc = encrypt_name("zhangsan@example.com", key)
    assert "zhangsan" not in enc and "example.com" not in enc
    assert decrypt_name(enc, key) == "zhangsan@example.com"
    assert decrypt_name(enc, b"wrong-key") is None


@pytest.mark.asyncio
async def test_profile_repo_attribution_roundtrip(tmp_path):
    db = await _make_db(tmp_path)
    try:
        repo = ProfileRepo(db)
        rec = AttributionRecord(
            finding_fingerprint="fp-001",
            alias_hash=alias_hash("a@x.com"),
            file="src/app.py",
            line=10,
            committed_at="2026-07-01T00:00:00+00:00",
        )
        await repo.save_attributions([rec])
        got = await repo.list_attribution(fingerprints=["fp-001"])
        assert len(got) == 1
        assert got[0].alias_hash == rec.alias_hash
        assert got[0].file == "src/app.py"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_record_fix_and_list(tmp_path):
    from datetime import datetime, timezone

    db = await _make_db(tmp_path)
    try:
        repo = ProfileRepo(db)
        now = datetime.now(timezone.utc)
        await repo.record_fix("fp-x", now)
        await repo.record_fix("fp-y", now)
        await repo.record_fix("fp-x", now)  # upsert 不重复
        fixes = await repo.list_fixes()
        assert set(fixes.keys()) == {"fp-x", "fp-y"}
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_forget_alias_keeps_findings_untouched(tmp_path):
    """forget 只删画像库数据，findings 表不受影响"""
    from fp_sentinel.database.repositories import FindingRepo

    db = await _make_db(tmp_path)
    try:
        repo = ProfileRepo(db)
        ah = alias_hash("carol@example.com")
        await repo.upsert_alias(ah)
        await repo.save_attribution(
            AttributionRecord(finding_fingerprint="fp-1", alias_hash=ah, file="a.py")
        )
        await repo.save_snapshot(ah, "2026-08", {"total": 1})

        finding_repo = FindingRepo(db)
        await finding_repo.create(
            Finding(
                scanner="semgrep", rule_id="r1", severity=Severity.HIGH,
                file_path="a.py", line_start=1, message="m", fingerprint="fp-1",
            )
        )

        deleted = await repo.forget_alias(ah)
        assert sum(deleted.values()) >= 3
        assert await repo.list_alias_hashes() == []
        assert await repo.list_attribution() == []
        # findings 完好
        assert await finding_repo.count() == 1
    finally:
        await db.close()
