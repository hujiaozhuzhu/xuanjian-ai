"""
企业权限管理模块测试 — permissions.py 单元测试
覆盖 PermissionChecker 的全局角色检查、项目级覆盖、审计日志联动。
"""

import pytest
import pytest_asyncio

from fp_sentinel.database.connection import Database
from fp_sentinel.enterprise_perm import ensure_perm_tables
from fp_sentinel.enterprise_perm.models import Permission, Role, AuditResult
from fp_sentinel.enterprise_perm.permissions import (
    PermissionChecker,
    PermissionDeniedError,
)
from fp_sentinel.enterprise_perm.repo import AuditRepo, ProjectRoleRepo, UserRepo


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "perm.db"))
    await database.connect()
    await database.initialize()
    await ensure_perm_tables(database)
    yield database
    await database.close()


# ─────────────────────── PermissionChecker 测试 ───────────────────────

async def _insert_project(db, project_id="p1", name="test-project", path="/tmp/test"):
    """辅助：在 projects 表中插入一条记录（用于 FK 约束）"""
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    await db.conn.execute(
        "INSERT OR IGNORE INTO projects (id, name, path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (project_id, name, path, now, now),
    )
    await db.conn.commit()


class TestPermissionChecker:

    @pytest.mark.asyncio
    async def test_admin_can_scan(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        admin = await user_repo.create("admin_user", role=Role.ADMIN)
        result = await checker.check(admin.id, Permission.SCAN_RUN)
        assert result.allowed is True
        assert result.role == Role.ADMIN

    @pytest.mark.asyncio
    async def test_developer_can_scan(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        dev = await user_repo.create("dev_user", role=Role.DEVELOPER)
        result = await checker.check(dev.id, Permission.SCAN_RUN)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_developer_cannot_manage_perm(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        dev = await user_repo.create("dev_user", role=Role.DEVELOPER)
        result = await checker.check(dev.id, Permission.PERM_MANAGE)
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_developer_cannot_view_all_scans(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        dev = await user_repo.create("dev_user", role=Role.DEVELOPER)
        result = await checker.check(dev.id, Permission.SCAN_VIEW_ALL)
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_security_engineer_can_view_all_scans(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        se = await user_repo.create("se_user", role=Role.SECURITY_ENGINEER)
        result = await checker.check(se.id, Permission.SCAN_VIEW_ALL)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_security_engineer_cannot_manage_perm(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        se = await user_repo.create("se_user", role=Role.SECURITY_ENGINEER)
        result = await checker.check(se.id, Permission.PERM_MANAGE)
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_nonexistent_user_denied(self, db):
        checker = PermissionChecker(db)
        result = await checker.check("fake-id", Permission.SCAN_RUN)
        assert result.allowed is False
        assert result.role is None

    @pytest.mark.asyncio
    async def test_inactive_user_denied(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        user = await user_repo.create("inactive_user", role=Role.ADMIN)
        await user_repo.deactivate(user.id)
        result = await checker.check(user.id, Permission.SCAN_RUN)
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_project_role_overrides_global(self, db):
        await _insert_project(db, "proj-1")
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        project_role_repo = ProjectRoleRepo(db)
        # 开发者全局角色
        dev = await user_repo.create("dev_user", role=Role.DEVELOPER)
        # 但在该项目上授予 SECURITY_ENGINEER
        await project_role_repo.grant(dev.id, "proj-1", Role.SECURITY_ENGINEER)
        # 不带项目ID检查 -> 使用全局角色 -> 不允许
        result_global = await checker.check(dev.id, Permission.SCAN_VIEW_ALL)
        assert result_global.allowed is False
        assert result_global.source == "global"
        # 带项目ID检查 -> 使用项目角色 -> 允许
        result_project = await checker.check(dev.id, Permission.SCAN_VIEW_ALL, project_id="proj-1")
        assert result_project.allowed is True
        assert result_project.source == "project"

    @pytest.mark.asyncio
    async def test_project_role_lower_permission(self, db):
        await _insert_project(db, "proj-1")
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        project_role_repo = ProjectRoleRepo(db)
        # 安全工程师全局
        se = await user_repo.create("se_user", role=Role.SECURITY_ENGINEER)
        # 但在该项目上降低为开发者
        await project_role_repo.grant(se.id, "proj-1", Role.DEVELOPER)
        result = await checker.check(se.id, Permission.SCAN_VIEW_ALL, project_id="proj-1")
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_allowed_writes_audit_log(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        audit_repo = AuditRepo(db)
        user = await user_repo.create("admin", role=Role.ADMIN)
        await checker.check(user.id, Permission.SCAN_RUN, log_allowed=True)
        entries = await audit_repo.list_entries(user_id=user.id)
        assert len(entries) >= 1
        assert entries[0].result == AuditResult.ALLOWED.value

    @pytest.mark.asyncio
    async def test_denied_writes_audit_log(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        audit_repo = AuditRepo(db)
        user = await user_repo.create("dev", role=Role.DEVELOPER)
        await checker.check(user.id, Permission.PERM_MANAGE)
        entries = await audit_repo.list_entries(user_id=user.id)
        denied = [e for e in entries if e.result == AuditResult.DENIED.value]
        assert len(denied) >= 1

    @pytest.mark.asyncio
    async def test_nonexistent_user_writes_denied_audit(self, db):
        checker = PermissionChecker(db)
        audit_repo = AuditRepo(db)
        await checker.check("fake-id", Permission.SCAN_RUN)
        entries = await audit_repo.list_entries()
        denied = [e for e in entries if e.result == AuditResult.DENIED.value]
        assert len(denied) >= 1

    @pytest.mark.asyncio
    async def test_admin_kg_manage(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        admin = await user_repo.create("admin", role=Role.ADMIN)
        result = await checker.check(admin.id, Permission.KG_MANAGE)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_security_engineer_kg_manage(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        se = await user_repo.create("se", role=Role.SECURITY_ENGINEER)
        result = await checker.check(se.id, Permission.KG_MANAGE)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_developer_kg_manage_denied(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        dev = await user_repo.create("dev", role=Role.DEVELOPER)
        result = await checker.check(dev.id, Permission.KG_MANAGE)
        assert result.allowed is False

    @pytest.mark.asyncio
    async def test_admin_audit_view(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        admin = await user_repo.create("admin", role=Role.ADMIN)
        result = await checker.check(admin.id, Permission.AUDIT_VIEW)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_developer_audit_view_denied(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        dev = await user_repo.create("dev", role=Role.DEVELOPER)
        result = await checker.check(dev.id, Permission.AUDIT_VIEW)
        assert result.allowed is False


class TestPermissionCheckerRequire:

    @pytest.mark.asyncio
    async def test_require_passes(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        admin = await user_repo.create("admin", role=Role.ADMIN)
        # Should not raise
        await checker.require(admin.id, Permission.SCAN_RUN)

    @pytest.mark.asyncio
    async def test_require_raises(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        dev = await user_repo.create("dev", role=Role.DEVELOPER)
        with pytest.raises(PermissionDeniedError):
            await checker.require(dev.id, Permission.PERM_MANAGE)

    @pytest.mark.asyncio
    async def test_require_nonexistent_raises(self, db):
        checker = PermissionChecker(db)
        with pytest.raises(PermissionDeniedError):
            await checker.require("nonexistent", Permission.SCAN_RUN)


class TestPermissionCheckerBatch:

    @pytest.mark.asyncio
    async def test_check_batch_admin(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        admin = await user_repo.create("admin", role=Role.ADMIN)
        results = await checker.check_batch(
            admin.id,
            [Permission.SCAN_RUN, Permission.PERM_MANAGE, Permission.PROJECT_MANAGE],
        )
        assert results[Permission.SCAN_RUN] is True
        assert results[Permission.PERM_MANAGE] is True
        assert results[Permission.PROJECT_MANAGE] is True

    @pytest.mark.asyncio
    async def test_check_batch_developer(self, db):
        checker = PermissionChecker(db)
        user_repo = UserRepo(db)
        dev = await user_repo.create("dev", role=Role.DEVELOPER)
        results = await checker.check_batch(
            dev.id,
            [Permission.SCAN_RUN, Permission.SCAN_VIEW_ALL, Permission.PERM_MANAGE],
        )
        assert results[Permission.SCAN_RUN] is True
        assert results[Permission.SCAN_VIEW_ALL] is False
        assert results[Permission.PERM_MANAGE] is False