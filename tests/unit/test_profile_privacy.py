"""
P5 隐私控制测试：forget 生效、DB 无明文、无绩效导出接口、报告声明
"""

import os

import pytest
import pytest_asyncio

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


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "privacy.db"))
    await database.connect()
    await database.initialize()
    await ensure_profile_tables(database)
    yield database
    await database.close()


@pytest.mark.asyncio
async def test_forget_alias_and_query_empty(db):
    """forget 后该别名的 alias/snapshot/attribution 查询为空"""
    repo = ProfileRepo(db)
    ah = alias_hash("dave@example.com")
    await repo.upsert_alias(ah)
    await repo.save_attribution(AttributionRecord(finding_fingerprint="fp1", alias_hash=ah))
    await repo.save_snapshot(ah, "2026-08", {"total": 1})

    assert await repo.get_alias(ah) is not None
    deleted = await repo.forget_alias(ah)
    assert all(v > 0 for v in deleted.values())
    assert await repo.get_alias(ah) is None
    assert await repo.list_snapshots(ah) == []
    remaining = await repo.list_attribution()
    assert all(r.alias_hash != ah for r in remaining)


@pytest.mark.asyncio
async def test_db_stores_no_plaintext_email_or_name(db):
    """画像库中不落明文 email/姓名：只有别名摘要 + 加密姓名"""
    repo = ProfileRepo(db)
    key = get_profile_key(db.db_path)
    ah = alias_hash("eve@example.com")
    await repo.upsert_alias(ah, display_name_encrypted=encrypt_name("Eve Adams", key))
    await repo.save_attribution(
        AttributionRecord(finding_fingerprint="fp-e1", alias_hash=ah, file="a.py")
    )

    # 原始dump整库检查（含 WAL 均不可见明文——此处检查查询结果）
    cursor = await db.conn.execute("SELECT * FROM developer_alias")
    rows = [dict(r) for r in await cursor.fetchall()]
    blob = repr(rows)
    assert "eve@example.com" not in blob
    assert "Eve Adams" not in blob
    assert rows[0]["display_name_encrypted"]

    cursor = await db.conn.execute("SELECT * FROM scan_attribution")
    attr_blob = repr([dict(r) for r in await cursor.fetchall()])
    assert "eve@example.com" not in attr_blob

    # 仅 reveal 流程可解密
    assert decrypt_name(rows[0]["display_name_encrypted"], key) == "Eve Adams"


def test_no_performance_export_interface():
    """红线：不实现任何画像评分导出为绩效格式的接口"""
    import fp_sentinel.cli.profile_commands as cli_mod
    import fp_sentinel.profile.analyzer as analyzer_mod
    import fp_sentinel.profile.models as models_mod
    import fp_sentinel.reporting.profile_report as report_mod

    banned = ("export_performance", "performance_export", "export_score",
              "hr_report", "kpi", "performance_review")
    for mod in (cli_mod, analyzer_mod, models_mod, report_mod):
        names = dir(mod)
        for b in banned:
            assert b not in names, f"{mod.__name__} 不应包含绩效导出接口 {b}"


@pytest.mark.asyncio
async def test_reveal_helper_is_gated(db):
    """模块层 reveal 双条件：环境变量缺失时不可 reveal"""
    from fp_sentinel.reporting.profile_report import check_reveal_allowed

    saved = os.environ.pop("FP_SENTINEL_REVEAL", None)
    try:
        assert check_reveal_allowed(True) is False
        os.environ["FP_SENTINEL_REVEAL"] = "1"
        assert check_reveal_allowed(True) is True
    finally:
        if saved is not None:
            os.environ["FP_SENTINEL_REVEAL"] = saved
        else:
            os.environ.pop("FP_SENTINEL_REVEAL", None)
