"""
企业权限管理模块测试 — repo.py 单元测试
覆盖 UserRepo / ProjectRoleRepo / AuditRepo 的 CRUD 操作。
"""

import pytest
import pytest_asyncio

from fp_sentinel.database.connection import Database
from fp_sentinel.enterprise_perm import ensure_perm_tables
from fp_sentinel.enterprise_perm.models import (
    AuditAction,
    AuditResult,
    Permission,
    Role,
)
from fp_sentinel.enterprise_perm.repo import (
    AuditRepo,
    ProjectRoleRepo,
    UserRepo,
)


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(str(tmp_path / "perm.db"))
    await database.connect()
    await database.initialize()
    await ensure_perm_tables(database)
    yield database
    await database.close()


# ─────────────────────── UserRepo 测试 ───────────────────────

class TestUserRepo:
    @pytest.mark.asyncio
    async def test_create_user(self, db):
        repo = UserRepo(db)
        user = await repo.create("alice", role=Role.ADMIN, display_name="Alice Smith")
        assert user.id is not None
        assert user.username == "alice"
        assert user.role == Role.ADMIN
        assert user.is_active is True

    @pytest.mark.asyncio
    async def test_create_default_role(self, db):
        repo = UserRepo(db)
        user = await repo.create("bob")
        assert user.role == Role.DEVELOPER

    @pytest.mark.asyncio
    async def test_create_normalizes_username(self, db):
        repo = UserRepo(db)
        user = await repo.create("  Alice  ")
        assert user.username == "alice"

    @pytest.mark.asyncio
    async def test_create_duplicate_username(self, db):
        repo = UserRepo(db)
        await repo.create("alice")
        with pytest.raises(Exception):
            await repo.create("alice")

    @pytest.mark.asyncio
    async def test_get_by_id(self, db):
        repo = UserRepo(db)
        created = await repo.create("alice", role=Role.ADMIN)
        fetched = await repo.get_by_id(created.id)
        assert fetched is not None
        assert fetched.username == "alice"
        assert fetched.role == Role.ADMIN

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self, db):
        repo = UserRepo(db)
        result = await repo.get_by_id("nonexistent-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_by_username(self, db):
        repo = UserRepo(db)
        await repo.create("alice")
        fetched = await repo.get_by_username("alice")
        assert fetched is not None
        assert fetched.username == "alice"

    @pytest.mark.asyncio
    async def test_get_by_username_case_insensitive(self, db):
        repo = UserRepo(db)
        await repo.create("alice")
        fetched = await repo.get_by_username("ALICE")
        assert fetched is not None

    @pytest.mark.asyncio
    async def test_get_by_username_not_found(self, db):
        repo = UserRepo(db)
        result = await repo.get_by_username("nobody")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_all(self, db):
        repo = UserRepo(db)
        await repo.create("alice", role=Role.ADMIN)
        await repo.create("bob", role=Role.DEVELOPER)
        await repo.create("charlie", role=Role.SECURITY_ENGINEER)
        users = await repo.list_all()
        assert len(users) == 3

    @pytest.mark.asyncio
    async def test_list_all_active_only(self, db):
        repo = UserRepo(db)
        u = await repo.create("inactive_user")
        await repo.deactivate(u.id)
        await repo.create("active_user")
        users = await repo.list_all(active_only=True)
        assert len(users) == 1
        assert users[0].username == "active_user"

    @pytest.mark.asyncio
    async def test_list_all_inactive(self, db):
        repo = UserRepo(db)
        u = await repo.create("inactive_user")
        await repo.deactivate(u.id)
        await repo.create("active_user")
        users = await repo.list_all(active_only=False)
        assert len(users) == 2

    @pytest.mark.asyncio
    async def test_list_by_role(self, db):
        repo = UserRepo(db)
        await repo.create("admin1", role=Role.ADMIN)
        await repo.create("admin2", role=Role.ADMIN)
        await repo.create("dev1", role=Role.DEVELOPER)
        admins = await repo.list_by_role(Role.ADMIN)
        assert len(admins) == 2
        devs = await repo.list_by_role(Role.DEVELOPER)
        assert len(devs) == 1

    @pytest.mark.asyncio
    async def test_update_role(self, db):
        repo = UserRepo(db)
        user = await repo.create("alice", role=Role.DEVELOPER)
        updated = await repo.update_role(user.id, Role.SECURITY_ENGINEER)
        assert updated is True
        fetched = await repo.get_by_id(user.id)
        assert fetched.role == Role.SECURITY_ENGINEER

    @pytest.mark.asyncio
    async def test_update_role_nonexistent(self, db):
        repo = UserRepo(db)
        result = await repo.update_role("nonexistent", Role.ADMIN)
        assert result is False

    @pytest.mark.asyncio
    async def test_deactivate_and_activate(self, db):
        repo = UserRepo(db)
        user = await repo.create("alice")
        assert user.is_active is True
        result = await repo.deactivate(user.id)
        assert result is True
        fetched = await repo.get_by_id(user.id)
        assert fetched.is_active is False
        result = await repo.activate(user.id)
        assert result is True
        fetched = await repo.get_by_id(user.id)
        assert fetched.is_active is True

    @pytest.mark.asyncio
    async def test_delete_user(self, db):
        repo = UserRepo(db)
        user = await repo.create("alice")
        result = await repo.delete(user.id)
        assert result is True
        fetched = await repo.get_by_id(user.id)
        assert fetched is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, db):
        repo = UserRepo(db)
        result = await repo.delete("nonexistent-id")
        assert result is False

    @pytest.mark.asyncio
    async def test_count_by_role(self, db):
        repo = UserRepo(db)
        await repo.create("admin1", role=Role.ADMIN)
        await repo.create("admin2", role=Role.ADMIN)
        await repo.create("dev1", role=Role.DEVELOPER)
        counts = await repo.count_by_role()
        assert counts["admin"] == 2
        assert counts["developer"] == 1


# ─────────────────────── ProjectRoleRepo 测试 ───────────────────────

async def _insert_project(db, project_id="p1", name="test-project", path="/tmp/test"):
    """辅助：在 projects 表中插入一条记录（用于 FK 约束）"""
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    await db.conn.execute(
        "INSERT OR IGNORE INTO projects (id, name, path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (project_id, name, path, now, now),
    )
    await db.conn.commit()


class TestProjectRoleRepo:
    @pytest.mark.asyncio
    async def test_grant_and_get(self, db):
        await _insert_project(db, "p1")
        repo = ProjectRoleRepo(db)
        # 先创建用户以满足 FK 约束
        import datetime as _dt
        now = _dt.datetime.now(_dt.timezone.utc).isoformat()
        await db.conn.execute(
            "INSERT OR IGNORE INTO users (id, username, role, is_active, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)",
            ("u1", "user1", "developer", now, now),
        )
        await db.conn.commit()
        pr = await repo.grant("u1", "p1", Role.SECURITY_ENGINEER, granted_by="admin")
        assert pr.user_id == "u1"
        assert pr.project_id == "p1"
        assert pr.role == Role.SECURITY_ENGINEER

        fetched = await repo.get_project_role("u1", "p1")
        assert fetched is not None
        assert fetched.role == Role.SECURITY_ENGINEER

    @pytest.mark.asyncio
    async def test_grant_overwrite(self, db):
        await _insert_project(db, "p1")
        user = await UserRepo(db).create("u1_user")
        repo = ProjectRoleRepo(db)
        await repo.grant(user.id, "p1", Role.DEVELOPER)
        await repo.grant(user.id, "p1", Role.ADMIN)
        fetched = await repo.get_project_role(user.id, "p1")
        assert fetched.role == Role.ADMIN

    @pytest.mark.asyncio
    async def test_revoke(self, db):
        await _insert_project(db, "p1")
        user = await UserRepo(db).create("u1_revoke")
        repo = ProjectRoleRepo(db)
        await repo.grant(user.id, "p1", Role.SECURITY_ENGINEER)
        result = await repo.revoke(user.id, "p1")
        assert result is True
        fetched = await repo.get_project_role(user.id, "p1")
        assert fetched is None

    @pytest.mark.asyncio
    async def test_revoke_nonexistent(self, db):
        repo = ProjectRoleRepo(db)
        result = await repo.revoke("u1", "p1")
        assert result is False

    @pytest.mark.asyncio
    async def test_get_project_role_not_found(self, db):
        repo = ProjectRoleRepo(db)
        result = await repo.get_project_role("u1", "p1")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_user_projects(self, db):
        await _insert_project(db, "p1", path="/tmp/test-p1")
        await _insert_project(db, "p2", path="/tmp/test-p2")
        user = await UserRepo(db).create("u1_projects")
        repo = ProjectRoleRepo(db)
        await repo.grant(user.id, "p1", Role.ADMIN)
        await repo.grant(user.id, "p2", Role.DEVELOPER)
        projects = await repo.get_user_projects(user.id)
        assert len(projects) == 2

    @pytest.mark.asyncio
    async def test_get_project_users(self, db):
        await _insert_project(db, "p1")
        user1 = await UserRepo(db).create("u1_pusers")
        user2 = await UserRepo(db).create("u2_pusers")
        repo = ProjectRoleRepo(db)
        await repo.grant(user1.id, "p1", Role.ADMIN)
        await repo.grant(user2.id, "p1", Role.DEVELOPER)
        users = await repo.get_project_users("p1")
        assert len(users) == 2


# ─────────────────────── AuditRepo 测试 ───────────────────────

class TestAuditRepo:
    @pytest.mark.asyncio
    async def test_log_basic(self, db):
        repo = AuditRepo(db)
        entry = await repo.log(
            action=AuditAction.USER_CREATE.value,
            result=AuditResult.SUCCESS.value,
            user_id="u1",
            username="alice",
        )
        assert entry.id is not None
        assert entry.action == "user.create"
        assert entry.result == "success"

    @pytest.mark.asyncio
    async def test_log_with_details(self, db):
        repo = AuditRepo(db)
        entry = await repo.log(
            action=AuditAction.PERM_DENIED.value,
            result=AuditResult.DENIED.value,
            details={"reason": "test", "permission": "scan:run"},
        )
        assert entry.details is not None
        assert "test" in entry.details

    @pytest.mark.asyncio
    async def test_log_list_entries(self, db):
        repo = AuditRepo(db)
        await repo.log(action="a1", result="success", username="u1")
        await repo.log(action="a2", result="denied", username="u2")
        await repo.log(action="a3", result="allowed", username="u3")
        entries = await repo.list_entries()
        assert len(entries) == 3

    @pytest.mark.asyncio
    async def test_log_list_entries_with_user_filter(self, db):
        repo = AuditRepo(db)
        await repo.log(action="a1", result="success", user_id="u1", username="alice")
        await repo.log(action="a2", result="denied", user_id="u2", username="bob")
        entries = await repo.list_entries(user_id="u1")
        assert len(entries) == 1
        assert entries[0].username == "alice"

    @pytest.mark.asyncio
    async def test_log_list_entries_with_action_filter(self, db):
        repo = AuditRepo(db)
        await repo.log(action="perm.check", result="allowed", username="u1")
        await repo.log(action="perm.denied", result="denied", username="u2")
        entries = await repo.list_entries(action="perm.check")
        assert len(entries) == 1

    @pytest.mark.asyncio
    async def test_log_list_entries_with_result_filter(self, db):
        repo = AuditRepo(db)
        await repo.log(action="a1", result="allowed", username="u1")
        await repo.log(action="a2", result="denied", username="u2")
        entries = await repo.list_entries(result_filter="denied")
        assert len(entries) == 1
        assert entries[0].result == "denied"

    @pytest.mark.asyncio
    async def test_log_list_limit(self, db):
        repo = AuditRepo(db)
        for i in range(10):
            await repo.log(action=f"action_{i}", result="success")
        entries = await repo.list_entries(limit=5)
        assert len(entries) == 5

    @pytest.mark.asyncio
    async def test_log_count(self, db):
        repo = AuditRepo(db)
        await repo.log(action="a1", result="success")
        await repo.log(action="a2", result="denied")
        count = await repo.count()
        assert count == 2

    @pytest.mark.asyncio
    async def test_log_count_with_user(self, db):
        repo = AuditRepo(db)
        await repo.log(action="a1", result="success", user_id="u1", username="alice")
        await repo.log(action="a2", result="success", user_id="u2", username="bob")
        count = await repo.count(user_id="u1")
        assert count == 1

    @pytest.mark.asyncio
    async def test_log_count_with_action(self, db):
        repo = AuditRepo(db)
        await repo.log(action="perm.check", result="allowed")
        await repo.log(action="perm.denied", result="denied")
        count = await repo.count(action="perm.check")
        assert count == 1

    @pytest.mark.asyncio
    async def test_get_action_stats(self, db):
        repo = AuditRepo(db)
        await repo.log(action="perm.check", result="allowed")
        await repo.log(action="perm.check", result="allowed")
        await repo.log(action="perm.denied", result="denied")
        stats = await repo.get_action_stats()
        assert stats["perm.check"] == 2
        assert stats["perm.denied"] == 1