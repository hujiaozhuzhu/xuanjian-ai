"""
v2.5.1 P1: 企业级功能统一初始化模块测试

覆盖:
- initialize_enterprise_database() 初始化主数据库 + 管理员账号
- initialize_all_enterprise_dbs() 初始化主库 + 通知库
- 幂等性（重复调用不会报错或重复创建）
"""

import os
import tempfile
from pathlib import Path

import pytest
import aiosqlite

from fp_sentinel.database.enterprise_init import (
    DEFAULT_ADMIN_USERNAME,
    create_default_admin,
    initialize_all_enterprise_dbs,
    initialize_enterprise_database,
)


class TestInitializeEnterpriseDatabase:
    """initialize_enterprise_database() 测试"""

    @pytest.mark.asyncio
    async def test_creates_main_tables(self, tmp_path):
        db_path = str(tmp_path / "test_data.db")
        result = await initialize_enterprise_database(db_path, create_admin=False)

        assert result["status"] == "initialized"
        assert result["db_path"] == db_path
        assert "projects" in result["tables_created"]
        assert "users" in result["tables_created"]
        assert "et_tasks" in result["tables_created"]

    @pytest.mark.asyncio
    async def test_creates_default_admin(self, tmp_path):
        db_path = str(tmp_path / "test_admin.db")
        result = await initialize_enterprise_database(db_path, create_admin=True)

        assert result["admin_created"] is True
        assert result["admin_username"] == DEFAULT_ADMIN_USERNAME
        assert result["admin_id"] is not None

    @pytest.mark.asyncio
    async def test_admin_exists_in_db(self, tmp_path):
        db_path = str(tmp_path / "test_admin_verify.db")
        await initialize_enterprise_database(db_path, create_admin=True)

        conn = await aiosqlite.connect(db_path)
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM users WHERE username = ?", (DEFAULT_ADMIN_USERNAME,)
        )
        row = await cursor.fetchone()
        await conn.close()
        assert row[0] == 1

    @pytest.mark.asyncio
    async def test_idempotent(self, tmp_path):
        """重复调用不会报错，状态返回 already_initialized"""
        db_path = str(tmp_path / "test_idempotent.db")

        result1 = await initialize_enterprise_database(db_path, create_admin=True)
        assert result1["admin_created"] is True

        result2 = await initialize_enterprise_database(db_path, create_admin=True)
        assert result2["status"] == "already_initialized"
        assert result2["admin_created"] is False

    @pytest.mark.asyncio
    async def test_no_admin_option(self, tmp_path):
        db_path = str(tmp_path / "test_no_admin.db")
        result = await initialize_enterprise_database(db_path, create_admin=False)

        assert result["admin_created"] is False
        assert result["admin_id"] is None

    @pytest.mark.asyncio
    async def test_permission_definitions_seeded(self, tmp_path):
        db_path = str(tmp_path / "test_perm.db")
        await initialize_enterprise_database(db_path, create_admin=False)

        conn = await aiosqlite.connect(db_path)
        cursor = await conn.execute("SELECT COUNT(*) FROM permission_definitions")
        row = await cursor.fetchone()
        await conn.close()
        assert row[0] > 0

    @pytest.mark.asyncio
    async def test_directory_auto_created(self, tmp_path):
        nested = tmp_path / "deep" / "nested" / "dir"
        db_path = str(nested / "data.db")
        result = await initialize_enterprise_database(db_path)

        assert os.path.exists(db_path)
        assert result["status"] in ("initialized", "already_initialized")

    @pytest.mark.asyncio
    async def test_expands_tilde(self):
        db_path = "~/__test_enterprise_init_temp.db"
        result = await initialize_enterprise_database(db_path, create_admin=True)
        expanded = os.path.expanduser(db_path)
        try:
            assert result["db_path"] == expanded
            assert os.path.exists(expanded)
        finally:
            if os.path.exists(expanded):
                os.unlink(expanded)


class TestInitializeAllEnterpriseDbs:
    """initialize_all_enterprise_dbs() 测试"""

    @pytest.mark.asyncio
    async def test_initializes_both_databases(self, tmp_path):
        main_db = str(tmp_path / "main.db")
        notify_db = str(tmp_path / "notify.db")
        result = await initialize_all_enterprise_dbs(
            main_db_path=main_db,
            notify_db_path=notify_db,
        )

        assert "main" in result
        assert "notify" in result
        assert os.path.exists(main_db)
        assert os.path.exists(notify_db)

    @pytest.mark.asyncio
    async def test_notify_tables_created(self, tmp_path):
        main_db = str(tmp_path / "main.db")
        notify_db = str(tmp_path / "notify.db")
        await initialize_all_enterprise_dbs(
            main_db_path=main_db,
            notify_db_path=notify_db,
        )

        conn = await aiosqlite.connect(notify_db)
        cursor = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = {row[0] for row in await cursor.fetchall()}
        await conn.close()

        assert "notify_channels" in tables
        assert "notify_rules" in tables
        assert "notify_records" in tables


class TestCreateDefaultAdmin:
    """create_default_admin() 函数级测试"""

    @pytest.mark.asyncio
    async def test_creates_admin_with_role(self, tmp_path):
        db_path = str(tmp_path / "admin_role.db")
        await initialize_enterprise_database(db_path, create_admin=False)

        conn = await aiosqlite.connect(db_path)
        admin_id, created = await create_default_admin(conn)
        await conn.close()

        assert created is True
        assert admin_id is not None

    @pytest.mark.asyncio
    async def test_second_call_returns_existing(self, tmp_path):
        db_path = str(tmp_path / "admin_dup.db")
        await initialize_enterprise_database(db_path, create_admin=True)

        conn = await aiosqlite.connect(db_path)
        admin_id, created = await create_default_admin(conn)
        await conn.close()

        # 已有 admin 时不再创建
        assert created is False
