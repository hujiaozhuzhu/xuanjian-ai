"""
企业权限管理模块测试 — models.py 单元测试
覆盖枚举、pydantic模型、权限矩阵、辅助函数。
"""

import pytest

from fp_sentinel.enterprise_perm.models import (
    ROLE_PERMISSIONS,
    AuditAction,
    AuditEntry,
    AuditResult,
    Permission,
    PermissionCheckResult,
    ProjectRole,
    Role,
    RoleInfo,
    User,
    normalize_username,
)


# ─────────────────────── 枚举测试 ───────────────────────

class TestRole:
    def test_role_values(self):
        assert Role.ADMIN == "admin"
        assert Role.SECURITY_ENGINEER == "security_engineer"
        assert Role.DEVELOPER == "developer"

    def test_role_from_value(self):
        assert Role("admin") == Role.ADMIN
        assert Role("security_engineer") == Role.SECURITY_ENGINEER
        assert Role("developer") == Role.DEVELOPER

    def test_role_invalid(self):
        with pytest.raises(ValueError):
            Role("invalid_role")


class TestPermission:
    def test_all_permissions_exist(self):
        expected = {
            "scan:run", "scan:view_all", "scan:delete",
            "report:generate", "report:view_all", "report:delete",
            "kg:query", "kg:manage",
            "fp:mark", "fp:manage",
            "perm:manage", "audit:view", "project:manage",
        }
        actual = {p.value for p in Permission}
        assert actual == expected

    def test_permission_from_value(self):
        assert Permission("scan:run") == Permission.SCAN_RUN

    def test_permission_invalid(self):
        with pytest.raises(ValueError):
            Permission("nonexistent:perm")


class TestAuditAction:
    def test_audit_action_values(self):
        assert AuditAction.USER_CREATE == "user.create"
        assert AuditAction.PERM_DENIED == "perm.denied"
        assert AuditAction.PROJECT_GRANT == "project.grant"

    def test_audit_action_invalid(self):
        with pytest.raises(ValueError):
            AuditAction("unknown.action")


class TestAuditResult:
    def test_audit_result_values(self):
        assert AuditResult.ALLOWED == "allowed"
        assert AuditResult.DENIED == "denied"
        assert AuditResult.SUCCESS == "success"
        assert AuditResult.FAILURE == "failure"

    def test_audit_result_invalid(self):
        with pytest.raises(ValueError):
            AuditResult("unknown")


# ─────────────────────── 权限矩阵测试 ───────────────────────

class TestRolePermissions:
    def test_admin_has_all_permissions(self):
        admin_perms = ROLE_PERMISSIONS[Role.ADMIN]
        all_perms = set(Permission)
        assert admin_perms == all_perms

    def test_security_engineer_permissions(self):
        se_perms = ROLE_PERMISSIONS[Role.SECURITY_ENGINEER]
        assert Permission.SCAN_RUN in se_perms
        assert Permission.SCAN_VIEW_ALL in se_perms
        assert Permission.REPORT_GENERATE in se_perms
        assert Permission.REPORT_VIEW_ALL in se_perms
        assert Permission.KG_QUERY in se_perms
        assert Permission.KG_MANAGE in se_perms
        assert Permission.FP_MARK in se_perms
        assert Permission.FP_MANAGE in se_perms
        assert Permission.AUDIT_VIEW in se_perms
        # 管理员专属权限不应有
        assert Permission.PERM_MANAGE not in se_perms
        assert Permission.PROJECT_MANAGE not in se_perms
        assert Permission.SCAN_DELETE not in se_perms
        assert Permission.REPORT_DELETE not in se_perms

    def test_developer_minimal_permissions(self):
        dev_perms = ROLE_PERMISSIONS[Role.DEVELOPER]
        assert Permission.SCAN_RUN in dev_perms
        assert Permission.REPORT_GENERATE in dev_perms
        assert Permission.KG_QUERY in dev_perms
        assert Permission.FP_MARK in dev_perms
        # 不应有
        assert Permission.SCAN_VIEW_ALL not in dev_perms
        assert Permission.SCAN_DELETE not in dev_perms
        assert Permission.REPORT_VIEW_ALL not in dev_perms
        assert Permission.KG_MANAGE not in dev_perms
        assert Permission.PERM_MANAGE not in dev_perms
        assert Permission.AUDIT_VIEW not in dev_perms
        assert Permission.PROJECT_MANAGE not in dev_perms

    def test_admin_has_more_than_security_engineer(self):
        assert len(ROLE_PERMISSIONS[Role.ADMIN]) > len(ROLE_PERMISSIONS[Role.SECURITY_ENGINEER])

    def test_security_engineer_has_more_than_developer(self):
        assert len(ROLE_PERMISSIONS[Role.SECURITY_ENGINEER]) > len(ROLE_PERMISSIONS[Role.DEVELOPER])


# ─────────────────────── Pydantic 模型测试 ───────────────────────

class TestUser:
    def test_create_minimal(self):
        u = User(id="u1", username="alice")
        assert u.id == "u1"
        assert u.username == "alice"
        assert u.role == Role.DEVELOPER
        assert u.is_active is True
        assert u.display_name is None

    def test_create_full(self):
        u = User(id="u2", username="bob", display_name="Bob Smith",
                 role=Role.SECURITY_ENGINEER, is_active=False)
        assert u.role == Role.SECURITY_ENGINEER
        assert u.is_active is False
        assert u.display_name == "Bob Smith"

    def test_model_dump(self):
        u = User(id="u1", username="alice", role=Role.ADMIN)
        d = u.model_dump()
        assert d["username"] == "alice"
        assert d["role"] == "admin"

    def test_model_dump_json(self):
        u = User(id="u1", username="alice", role=Role.ADMIN)
        j = u.model_dump_json()
        assert "alice" in j
        assert "admin" in j


class TestProjectRole:
    def test_create(self):
        pr = ProjectRole(id="pr1", user_id="u1", project_id="p1", role=Role.ADMIN)
        assert pr.user_id == "u1"
        assert pr.project_id == "p1"
        assert pr.role == Role.ADMIN
        assert pr.granted_by is None

    def test_create_with_granted_by(self):
        pr = ProjectRole(id="pr1", user_id="u1", project_id="p1",
                         role=Role.DEVELOPER, granted_by="admin_id")
        assert pr.granted_by == "admin_id"


class TestAuditEntry:
    def test_create(self):
        e = AuditEntry(action="test.action", result="success")
        assert e.action == "test.action"
        assert e.result == "success"
        assert e.id is None
        assert e.ip_address == "127.0.0.1"

    def test_create_full(self):
        e = AuditEntry(id=1, user_id="u1", username="alice",
                       action="perm.check", result="allowed",
                       resource_type="permission", resource_id="scan:run",
                       details='{"source": "global"}')
        assert e.id == 1
        assert e.username == "alice"
        assert e.details == '{"source": "global"}'


class TestPermissionCheckResult:
    def test_allowed(self):
        r = PermissionCheckResult(allowed=True, user_id="u1",
                                  permission=Permission.SCAN_RUN,
                                  role=Role.ADMIN, source="global")
        assert r.allowed is True
        assert r.source == "global"

    def test_denied(self):
        r = PermissionCheckResult(allowed=False, user_id="u1",
                                  permission=Permission.PERM_MANAGE,
                                  role=Role.DEVELOPER, source="global")
        assert r.allowed is False

    def test_project_source(self):
        r = PermissionCheckResult(allowed=True, user_id="u1",
                                  permission=Permission.SCAN_RUN,
                                  role=Role.SECURITY_ENGINEER, source="project")
        assert r.source == "project"


class TestRoleInfo:
    def test_create(self):
        ri = RoleInfo(role=Role.ADMIN,
                      permissions=[Permission.SCAN_RUN, Permission.PERM_MANAGE],
                      user_count=3)
        assert ri.role == Role.ADMIN
        assert len(ri.permissions) == 2
        assert ri.user_count == 3

    def test_empty(self):
        ri = RoleInfo(role=Role.DEVELOPER)
        assert ri.permissions == []
        assert ri.user_count == 0


# ─────────────────────── 辅助函数测试 ───────────────────────

class TestNormalizeUsername:
    def test_lowercase(self):
        assert normalize_username("Alice") == "alice"

    def test_trim(self):
        assert normalize_username("  alice  ") == "alice"

    def test_none(self):
        assert normalize_username(None) == ""

    def test_empty(self):
        assert normalize_username("") == ""

    def test_already_clean(self):
        assert normalize_username("bob_smith") == "bob_smith"

    def test_unicode(self):
        result = normalize_username("UserÄ")
        assert result == "userä"  # Python .lower() converts Ä -> ä