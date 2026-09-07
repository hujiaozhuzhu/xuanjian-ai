"""
企业权限管理 — 数据仓库层

提供 User / ProjectRole / AuditEntry 的 CRUD 操作，
遵循只增不改原则，不影响既有表。
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiosqlite

from ..database.connection import Database
from .models import (
    AuditEntry,
    ProjectRole,
    Role,
    User,
    normalize_username,
)

logger = logging.getLogger(__name__)


def _gen_id() -> str:
    """生成唯一ID"""
    return str(uuid.uuid4())


def _now() -> str:
    """当前 UTC 时间 ISO 格式"""
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────── UserRepo ───────────────────────

class UserRepo:
    """用户仓库"""

    def __init__(self, db: Database):
        self.db = db

    async def create(
        self,
        username: str,
        role: Role = Role.DEVELOPER,
        display_name: Optional[str] = None,
    ) -> User:
        """创建用户"""
        username = normalize_username(username)
        user_id = _gen_id()
        now = _now()
        await self.db.conn.execute(
            """INSERT INTO users (id, username, display_name, role, is_active, created_at, updated_at)
               VALUES (?, ?, ?, ?, 1, ?, ?)""",
            (user_id, username, display_name, role.value, now, now),
        )
        await self.db.conn.commit()
        return User(
            id=user_id, username=username, display_name=display_name,
            role=role, is_active=True,
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
        )

    async def get_by_id(self, user_id: str) -> Optional[User]:
        """按 ID 获取用户"""
        cursor = await self.db.conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        )
        row = await cursor.fetchone()
        return self._row_to_user(row) if row else None

    async def get_by_username(self, username: str) -> Optional[User]:
        """按用户名获取用户"""
        cursor = await self.db.conn.execute(
            "SELECT * FROM users WHERE username = ?", (normalize_username(username),)
        )
        row = await cursor.fetchone()
        return self._row_to_user(row) if row else None

    async def list_all(self, active_only: bool = True) -> List[User]:
        """列出所有用户"""
        query = "SELECT * FROM users"
        if active_only:
            query += " WHERE is_active = 1"
        query += " ORDER BY created_at"
        cursor = await self.db.conn.execute(query)
        rows = await cursor.fetchall()
        return [self._row_to_user(r) for r in rows]

    async def list_by_role(self, role: Role) -> List[User]:
        """按角色列出用户"""
        cursor = await self.db.conn.execute(
            "SELECT * FROM users WHERE role = ? AND is_active = 1 ORDER BY created_at",
            (role.value,),
        )
        rows = await cursor.fetchall()
        return [self._row_to_user(r) for r in rows]

    async def update_role(self, user_id: str, new_role: Role) -> bool:
        """更新用户角色"""
        cursor = await self.db.conn.execute(
            "UPDATE users SET role = ?, updated_at = ? WHERE id = ?",
            (new_role.value, _now(), user_id),
        )
        await self.db.conn.commit()
        return cursor.rowcount > 0

    async def deactivate(self, user_id: str) -> bool:
        """停用用户"""
        cursor = await self.db.conn.execute(
            "UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?",
            (_now(), user_id),
        )
        await self.db.conn.commit()
        return cursor.rowcount > 0

    async def activate(self, user_id: str) -> bool:
        """激活用户"""
        cursor = await self.db.conn.execute(
            "UPDATE users SET is_active = 1, updated_at = ? WHERE id = ?",
            (_now(), user_id),
        )
        await self.db.conn.commit()
        return cursor.rowcount > 0

    async def delete(self, user_id: str) -> bool:
        """删除用户"""
        cursor = await self.db.conn.execute(
            "DELETE FROM users WHERE id = ?", (user_id,)
        )
        await self.db.conn.commit()
        return cursor.rowcount > 0

    async def count_by_role(self) -> Dict[str, int]:
        """按角色统计用户数"""
        cursor = await self.db.conn.execute(
            "SELECT role, COUNT(*) as cnt FROM users WHERE is_active = 1 GROUP BY role"
        )
        rows = await cursor.fetchall()
        return {row["role"]: row["cnt"] for row in rows}

    def _row_to_user(self, row: aiosqlite.Row) -> User:
        d = dict(row)
        for field in ("created_at", "updated_at"):
            if d.get(field) and isinstance(d[field], str):
                try:
                    d[field] = datetime.fromisoformat(d[field])
                except ValueError:
                    d[field] = None
        return User(**d)


# ─────────────────────── ProjectRoleRepo ───────────────────────

class ProjectRoleRepo:
    """项目级角色仓库"""

    def __init__(self, db: Database):
        self.db = db

    async def grant(
        self,
        user_id: str,
        project_id: str,
        role: Role,
        granted_by: Optional[str] = None,
    ) -> ProjectRole:
        """授予用户在某项目上的角色（覆盖式）"""
        record_id = _gen_id()
        now = _now()
        await self.db.conn.execute(
            """INSERT INTO user_project_roles (id, user_id, project_id, role, granted_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(user_id, project_id) DO UPDATE SET
                 role = excluded.role,
                 granted_by = excluded.granted_by""",
            (record_id, user_id, project_id, role.value, granted_by, now),
        )
        await self.db.conn.commit()
        return ProjectRole(
            id=record_id, user_id=user_id, project_id=project_id,
            role=role, granted_by=granted_by,
            created_at=datetime.fromisoformat(now),
        )

    async def revoke(self, user_id: str, project_id: str) -> bool:
        """撤销用户在某项目上的角色"""
        cursor = await self.db.conn.execute(
            "DELETE FROM user_project_roles WHERE user_id = ? AND project_id = ?",
            (user_id, project_id),
        )
        await self.db.conn.commit()
        return cursor.rowcount > 0

    async def get_project_role(self, user_id: str, project_id: str) -> Optional[ProjectRole]:
        """获取用户在某项目上的角色"""
        cursor = await self.db.conn.execute(
            "SELECT * FROM user_project_roles WHERE user_id = ? AND project_id = ?",
            (user_id, project_id),
        )
        row = await cursor.fetchone()
        return self._row_to_project_role(row) if row else None

    async def get_user_projects(self, user_id: str) -> List[ProjectRole]:
        """获取用户的所有项目角色"""
        cursor = await self.db.conn.execute(
            "SELECT * FROM user_project_roles WHERE user_id = ? ORDER BY created_at",
            (user_id,),
        )
        rows = await cursor.fetchall()
        return [self._row_to_project_role(r) for r in rows]

    async def get_project_users(self, project_id: str) -> List[ProjectRole]:
        """获取某项目的所有用户角色"""
        cursor = await self.db.conn.execute(
            "SELECT * FROM user_project_roles WHERE project_id = ? ORDER BY created_at",
            (project_id,),
        )
        rows = await cursor.fetchall()
        return [self._row_to_project_role(r) for r in rows]

    def _row_to_project_role(self, row: aiosqlite.Row) -> ProjectRole:
        d = dict(row)
        if d.get("created_at") and isinstance(d["created_at"], str):
            try:
                d["created_at"] = datetime.fromisoformat(d["created_at"])
            except ValueError:
                d["created_at"] = None
        return ProjectRole(**d)


# ─────────────────────── AuditRepo ───────────────────────

class AuditRepo:
    """审计日志仓库"""

    def __init__(self, db: Database):
        self.db = db

    async def log(
        self,
        action: str,
        result: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: str = "127.0.0.1",
    ) -> AuditEntry:
        """记录审计日志"""
        details_json = json.dumps(details, ensure_ascii=False, default=str) if details else None
        cursor = await self.db.conn.execute(
            """INSERT INTO audit_log
               (user_id, username, action, resource_type, resource_id, result, details, ip_address)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, username, action, resource_type, resource_id,
             result, details_json, ip_address),
        )
        await self.db.conn.commit()
        return AuditEntry(
            id=cursor.lastrowid, user_id=user_id, username=username,
            action=action, resource_type=resource_type, resource_id=resource_id,
            result=result, details=details_json, ip_address=ip_address,
            timestamp=datetime.now(timezone.utc),
        )

    async def list_entries(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        result_filter: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEntry]:
        """列出审计日志"""
        clauses = []
        params = []
        if user_id:
            clauses.append("user_id = ?")
            params.append(user_id)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if result_filter:
            clauses.append("result = ?")
            params.append(result_filter)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        query = f"SELECT * FROM audit_log{where} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor = await self.db.conn.execute(query, params)
        rows = await cursor.fetchall()
        return [self._row_to_entry(r) for r in rows]

    async def count(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        result_filter: Optional[str] = None,
    ) -> int:
        """统计审计记录数"""
        clauses = []
        params = []
        if user_id:
            clauses.append("user_id = ?")
            params.append(user_id)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if result_filter:
            clauses.append("result = ?")
            params.append(result_filter)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        cursor = await self.db.conn.execute(
            f"SELECT COUNT(*) FROM audit_log{where}", params
        )
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def get_action_stats(self) -> Dict[str, int]:
        """按操作类型统计"""
        cursor = await self.db.conn.execute(
            "SELECT action, COUNT(*) as cnt FROM audit_log GROUP BY action ORDER BY cnt DESC"
        )
        rows = await cursor.fetchall()
        return {row["action"]: row["cnt"] for row in rows}

    def _row_to_entry(self, row: aiosqlite.Row) -> AuditEntry:
        d = dict(row)
        if d.get("timestamp") and isinstance(d["timestamp"], str):
            try:
                d["timestamp"] = datetime.fromisoformat(d["timestamp"])
            except ValueError:
                d["timestamp"] = None
        return AuditEntry(**d)