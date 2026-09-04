"""
P6 profile CLI 命令组测试（直接驱动 profile_app，不修改 cli/__init__.py）
"""

import pytest
from typer.testing import CliRunner

from fp_sentinel.cli.profile_commands import profile_app
from fp_sentinel.database.connection import Database
from fp_sentinel.models import Finding, Severity
from fp_sentinel.profile.models import (
    ProfileRepo,
    alias_hash,
    ensure_profile_tables,
)

runner = CliRunner()


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    """隔离数据库（XUANJIAN_DB_PATH 环境变量覆盖）"""
    db_file = tmp_path / "cli-profile.db"
    monkeypatch.setenv("XUANJIAN_DB_PATH", str(db_file))
    monkeypatch.delenv("FP_SENTINEL_REVEAL", raising=False)
    return db_file


def test_profile_app_exists_and_has_commands():
    """profile_app 已暴露且包含全部子命令"""
    from typer import Typer

    assert isinstance(profile_app, Typer)
    names = [c.name for c in profile_app.registered_commands]
    assert {"team", "me", "forget", "scan", "build", "mark-fixed"} <= set(names)


def test_profile_me_empty_db(isolated_db):
    result = runner.invoke(profile_app, ["me"])
    assert result.exit_code == 0
    assert "画像库为空" in result.output


def test_profile_forget_removes_alias(isolated_db, tmp_path):
    """forget 命令端到端：入库 → forget → 查询为空"""

    import asyncio

    async def seed():
        db = Database(str(isolated_db))
        await db.connect()
        await db.initialize()
        await ensure_profile_tables(db)
        repo = ProfileRepo(db)
        ah = alias_hash("frank@example.com")
        await repo.upsert_alias(ah)
        await repo.save_snapshot(ah, "2026-08", {"total": 2})
        await db.close()

    asyncio.run(seed())

    # email 形式删除
    result = runner.invoke(profile_app, ["forget", "frank@example.com", "--yes"])
    assert result.exit_code == 0, result.output
    assert "已删除" in result.output

    async def check():
        db = Database(str(isolated_db))
        await db.connect()
        await db.initialize()
        await ensure_profile_tables(db)
        repo = ProfileRepo(db)
        hashes = await repo.list_alias_hashes()
        snaps = await repo.list_snapshots(alias_hash("frank@example.com"))
        await db.close()
        return hashes, snaps

    hashes, snaps = asyncio.run(check())
    assert hashes == []
    assert snaps == []


def test_profile_forget_declines_without_confirm(isolated_db, monkeypatch):
    result = runner.invoke(profile_app, ["forget", "someone@example.com"], input="n\n")
    assert result.exit_code == 0
    assert "已取消" in result.output


def test_profile_team_generates_report(isolated_db, tmp_path):
    """team 命令：生成报告文件（输出目录白名单内）"""
    out_dir = tmp_path / "reports"
    result = runner.invoke(
        profile_app,
        ["team", "--month", "2026-08", "--kloc", "2.0", "--output", str(out_dir)],
    )
    assert result.exit_code == 0, result.output
    report = out_dir / "profile-team-2026-08.md"
    assert report.exists()
    content = report.read_text(encoding="utf-8")
    assert "隐私声明" in content
    assert "团队健康度" in content
    assert "本地保护非强加密" in content


def test_profile_mark_fixed(isolated_db):
    """mark-fixed：记录修复时间，供修复速度维度使用"""
    import asyncio
    from datetime import datetime, timezone

    fp = "fp-fixed-1"

    async def seed():
        db = Database(str(isolated_db))
        await db.connect()
        await db.initialize()
        await ensure_profile_tables(db)
        from fp_sentinel.database.repositories import FindingRepo

        repo = FindingRepo(db)
        f = Finding(
            scanner="semgrep", rule_id="r1", severity=Severity.HIGH,
            file_path="a.py", line_start=1, message="m",
            fingerprint=fp, created_at=datetime.now(timezone.utc),
        )
        await repo.create(f)
        await db.close()
        return f.id

    fid = asyncio.run(seed())
    result = runner.invoke(profile_app, ["mark-fixed", fid])
    assert result.exit_code == 0, result.output

    async def check():
        db = Database(str(isolated_db))
        await db.connect()
        await db.initialize()
        await ensure_profile_tables(db)
        fixes = await ProfileRepo(db).list_fixes()
        await db.close()
        return fixes

    fixes = asyncio.run(check())
    assert fp in fixes
