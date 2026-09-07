"""
企业权限管理 — 数据模型与SQLite表定义

三级角色权限体系（管理员、安全工程师、普通开发者），支持基于项目的访问控制，
权限粒度到扫描、报告、知识图谱等核心功能，所有权限操作有审计日志。

安全红线声明（对应迭代计划 S1/S2/S3/S6/S7）：
- 权限数据仅存储于本地 SQLite，禁止任何网络上传；
- 本模块仅提供查询、校验、标记接口，不外发用户身份信息；
- 审计日志本地存储，禁止任何外网传输；
- 本模块只增不改既有表结构，不影响已有机核一/核二/核三模块。
"""

import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ─────────────────────── 枚举定义 ───────────────────────

class Role(str, Enum):
    """三级角色"""
    ADMIN = "admin"
    SECURITY_ENGINEER = "security_engineer"
    DEVELOPER = "developer"


class Permission(str, Enum):
    """权限枚举（粒度到核心功能）"""
    # 扫描类
    SCAN_RUN = "scan:run"
    SCAN_VIEW_ALL = "scan:view_all"
    SCAN_DELETE = "scan:delete"
    # 报告类
    REPORT_GENERATE = "report:generate"
    REPORT_VIEW_ALL = "report:view_all"
    REPORT_DELETE = "report:delete"
    # 知识图谱类
    KG_QUERY = "kg:query"
    KG_MANAGE = "kg:manage"
    # 误报标记类
    FP_MARK = "fp:mark"
    FP_MANAGE = "fp:manage"
    # 权限管理类
    PERM_MANAGE = "perm:manage"
    # 审计类
    AUDIT_VIEW = "audit:view"
    # 项目管理类
    PROJECT_MANAGE = "project:manage"


class AuditAction(str, Enum):
    """审计操作类型"""
    USER_CREATE = "user.create"
    USER_DELETE = "user.delete"
    USER_ROLE_CHANGE = "user.role_change"
    PROJECT_GRANT = "project.grant"
    PROJECT_REVOKE = "project.revoke"
    PERM_CHECK = "perm.check"
    PERM_DENIED = "perm.denied"
    PERM_GRANT = "perm.grant"
    ROLE_ASSIGN = "role.assign"
    ROLE_REVOKE = "role.revoke"


class AuditResult(str, Enum):
    """审计操作结果"""
    ALLOWED = "allowed"
    DENIED = "denied"
    SUCCESS = "success"
    FAILURE = "failure"


# ─────────────────────── 权限矩阵 ───────────────────────

ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {
        Permission.SCAN_RUN, Permission.SCAN_VIEW_ALL, Permission.SCAN_DELETE,
        Permission.REPORT_GENERATE, Permission.REPORT_VIEW_ALL, Permission.REPORT_DELETE,
        Permission.KG_QUERY, Permission.KG_MANAGE,
        Permission.FP_MARK, Permission.FP_MANAGE,
        Permission.PERM_MANAGE,
        Permission.AUDIT_VIEW,
        Permission.PROJECT_MANAGE,
    },
    Role.SECURITY_ENGINEER: {
        Permission.SCAN_RUN, Permission.SCAN_VIEW_ALL,
        Permission.REPORT_GENERATE, Permission.REPORT_VIEW_ALL,
        Permission.KG_QUERY, Permission.KG_MANAGE,
        Permission.FP_MARK, Permission.FP_MANAGE,
        Permission.AUDIT_VIEW,
    },
    Role.DEVELOPER: {
        Permission.SCAN_RUN,
        Permission.REPORT_GENERATE,
        Permission.KG_QUERY,
        Permission.FP_MARK,
    },
}


# ─────────────────────── SQLite 表定义（只增不改） ───────────────────────

PERM_SCHEMA_SQL = """
-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    display_name    TEXT,
    role            TEXT NOT NULL DEFAULT 'developer',
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 项目级角色覆盖表（用户在某项目上的角色，覆盖全局角色）
CREATE TABLE IF NOT EXISTS user_project_roles (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    project_id      TEXT NOT NULL,
    role            TEXT NOT NULL,
    granted_by      TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    UNIQUE(user_id, project_id)
);

-- 审计日志表
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT,
    username        TEXT,
    action          TEXT NOT NULL,
    resource_type   TEXT,
    resource_id     TEXT,
    result          TEXT NOT NULL,
    details         TEXT,
    ip_address      TEXT DEFAULT '127.0.0.1',
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 权限定义表（角色到权限映射，用于运行时校验）
CREATE TABLE IF NOT EXISTS permission_definitions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    role            TEXT NOT NULL,
    permission      TEXT NOT NULL,
    description     TEXT,
    UNIQUE(role, permission)
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_upr_user_id ON user_project_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_upr_project_id ON user_project_roles(project_id);
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_result ON audit_log(result);
CREATE INDEX IF NOT EXISTS idx_perm_def_role ON permission_definitions(role);
"""


# ─────────────────────── Pydantic 模型 ───────────────────────

class User(BaseModel):
    """系统用户"""
    id: str = Field(..., description="用户唯一ID")
    username: str = Field(..., description="用户名（唯一标识）")
    display_name: Optional[str] = Field(None, description="显示名")
    role: Role = Field(default=Role.DEVELOPER, description="全局角色")
    is_active: bool = Field(default=True, description="是否激活")
    created_at: Optional[datetime] = Field(None, description="创建时间")
    updated_at: Optional[datetime] = Field(None, description="更新时间")


class ProjectRole(BaseModel):
    """项目级角色覆盖"""
    id: str = Field(..., description="记录唯一ID")
    user_id: str = Field(..., description="用户ID")
    project_id: str = Field(..., description="项目ID")
    role: Role = Field(..., description="项目角色")
    granted_by: Optional[str] = Field(None, description="授权人用户ID")
    created_at: Optional[datetime] = Field(None, description="创建时间")


class AuditEntry(BaseModel):
    """审计日志条目"""
    id: Optional[int] = Field(None, description="记录ID")
    user_id: Optional[str] = Field(None, description="操作用户ID")
    username: Optional[str] = Field(None, description="操作用户名")
    action: str = Field(..., description="操作类型")
    resource_type: Optional[str] = Field(None, description="资源类型")
    resource_id: Optional[str] = Field(None, description="资源ID")
    result: str = Field(..., description="操作结果(allowed/denied/success/failure)")
    details: Optional[str] = Field(None, description="详情JSON")
    ip_address: str = Field(default="127.0.0.1", description="IP地址")
    timestamp: Optional[datetime] = Field(None, description="操作时间")


class PermissionCheckResult(BaseModel):
    """权限检查结果"""
    allowed: bool = Field(..., description="是否允许")
    user_id: str = Field(..., description="用户ID")
    permission: Permission = Field(..., description="请求的权限")
    role: Optional[Role] = Field(None, description="判定所用的角色")
    source: str = Field("global", description="角色来源：global/project")


class RoleInfo(BaseModel):
    """角色信息"""
    role: Role = Field(..., description="角色")
    permissions: List[Permission] = Field(default_factory=list, description="权限列表")
    user_count: int = Field(0, description="该角色的用户数量")


# ─────────────────────── 辅助函数 ───────────────────────

def _gen_id() -> str:
    """生成唯一ID"""
    return str(uuid.uuid4())


def normalize_username(username: str) -> str:
    """规范化用户名（小写+去空白）"""
    return (username or "").strip().lower()
