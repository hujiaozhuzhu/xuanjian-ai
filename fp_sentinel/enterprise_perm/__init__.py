"""
企业权限管理模块（Enterprise Permission Management）

三级角色权限体系：管理员、安全工程师、普通开发者。
支持基于项目的访问控制，权限粒度到扫描、报告、知识图谱等核心功能。
所有权限操作有审计日志。

安全红线：
- S1: 数据仅本地 SQLite，禁止网络上传
- S3: 只增不改既有表结构
- S6: 用户身份本地哈希化，不外发明文
- S7: 操作仅本地，不外发
"""

__version__ = "3.1.0"

from .models import (
    PERM_SCHEMA_SQL,
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

__version__ = "2.5.0"

__all__ = [
    # 枚举
    "Role",
    "Permission",
    "AuditAction",
    "AuditResult",
    # 模型
    "User",
    "ProjectRole",
    "AuditEntry",
    "PermissionCheckResult",
    "RoleInfo",
    # 常量
    "ROLE_PERMISSIONS",
    "PERM_SCHEMA_SQL",
    # 辅助
    "normalize_username",
    # 初始化函数
    "ensure_perm_tables",
]


async def ensure_perm_tables(db) -> None:
    """在既有 Database 上创建权限管理新增表（幂等，只增不改）"""
    from .models import PERM_SCHEMA_SQL
    await db.conn.executescript(PERM_SCHEMA_SQL)
    await db.conn.commit()
