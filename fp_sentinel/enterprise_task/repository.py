"""
企业任务管理 - 数据存储层 (Repository)

提供 Task / TaskTransition / TaskComment 的 CRUD 操作
支持按多维度查询与进度统计
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiosqlite

from .models import (
    Task,
    TaskComment,
    TaskPriority,
    TaskQueryParams,
    TaskStatus,
    TaskStats,
    TaskTransition,
    TaskType,
)

logger = logging.getLogger(__name__)


def _generate_id() -> str:
    """生成唯一 ID"""
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────── Schema ───────────────────────

TASK_SCHEMA_SQL = """
-- 任务表
CREATE TABLE IF NOT EXISTS et_tasks (
    id                  TEXT PRIMARY KEY,
    project_id          TEXT NOT NULL,
    project_name        TEXT DEFAULT '',
    task_type           TEXT NOT NULL,
    status              TEXT DEFAULT 'pending',
    priority            TEXT DEFAULT 'P2',
    assigned_to         TEXT,
    assigned_by         TEXT,
    finding_id          TEXT,
    finding_rule_id     TEXT,
    finding_severity    TEXT,
    finding_file_path   TEXT,
    finding_line_start  INTEGER,
    title               TEXT NOT NULL,
    description         TEXT DEFAULT '',
    fix_diff            TEXT,
    fix_commit_hash     TEXT,
    fix_notes           TEXT,
    review_verdict      TEXT,
    review_comment      TEXT,
    reviewed_by         TEXT,
    reviewed_at         TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    due_date            TEXT,
    completed_at        TEXT,
    tags                TEXT DEFAULT '[]',
    metadata            TEXT DEFAULT '{}'
);

-- 任务状态流转记录表
CREATE TABLE IF NOT EXISTS et_task_transitions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         TEXT NOT NULL,
    from_status     TEXT,
    to_status       TEXT NOT NULL,
    operator        TEXT,
    operator_role   TEXT,
    comment         TEXT,
    created_at      TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES et_tasks(id) ON DELETE CASCADE
);

-- 任务评论表
CREATE TABLE IF NOT EXISTS et_task_comments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         TEXT NOT NULL,
    author          TEXT,
    content         TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES et_tasks(id) ON DELETE CASCADE
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_et_tasks_project_id ON et_tasks(project_id);
CREATE INDEX IF NOT EXISTS idx_et_tasks_status ON et_tasks(status);
CREATE INDEX IF NOT EXISTS idx_et_tasks_assigned_to ON et_tasks(assigned_to);
CREATE INDEX IF NOT EXISTS idx_et_tasks_priority ON et_tasks(priority);
CREATE INDEX IF NOT EXISTS idx_et_tasks_task_type ON et_tasks(task_type);
CREATE INDEX IF NOT EXISTS idx_et_tasks_finding_id ON et_tasks(finding_id);
CREATE INDEX IF NOT EXISTS idx_et_tasks_finding_severity ON et_tasks(finding_severity);
CREATE INDEX IF NOT EXISTS idx_et_tasks_created_at ON et_tasks(created_at);
CREATE INDEX IF NOT EXISTS idx_et_tasks_due_date ON et_tasks(due_date);
CREATE INDEX IF NOT EXISTS idx_et_transitions_task_id ON et_task_transitions(task_id);
CREATE INDEX IF NOT EXISTS idx_et_comments_task_id ON et_task_comments(task_id);
"""


# ─────────────────────── TaskRepo ───────────────────────

class TaskRepo:
    """任务仓库"""

    def __init__(self, conn: aiosqlite.Connection):
        self.conn = conn

    async def initialize_schema(self) -> None:
        """初始化任务管理相关表结构"""
        await self.conn.executescript(TASK_SCHEMA_SQL)
        await self.conn.commit()

    async def create(self, task: Task) -> Task:
        """创建任务"""
        if not task.id:
            task.id = _generate_id()
        task.created_at = task.created_at or _now_iso()
        task.updated_at = _now_iso()

        await self.conn.execute(
            """INSERT INTO et_tasks
               (id, project_id, project_name, task_type, status, priority,
                assigned_to, assigned_by, finding_id, finding_rule_id,
                finding_severity, finding_file_path, finding_line_start,
                title, description, fix_diff, fix_commit_hash, fix_notes,
                review_verdict, review_comment, reviewed_by, reviewed_at,
                created_at, updated_at, due_date, completed_at, tags, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task.id, task.project_id, task.project_name, task.task_type.value,
                task.status.value, task.priority.value, task.assigned_to,
                task.assigned_by, task.finding_id, task.finding_rule_id,
                task.finding_severity, task.finding_file_path, task.finding_line_start,
                task.title, task.description, task.fix_diff, task.fix_commit_hash,
                task.fix_notes, task.review_verdict.value if task.review_verdict else None,
                task.review_comment, task.reviewed_by, task.reviewed_at,
                task.created_at, task.updated_at, task.due_date, task.completed_at,
                json.dumps(task.tags), json.dumps(task.metadata),
            ),
        )
        await self.conn.commit()
        return task

    async def bulk_create(self, tasks: List[Task]) -> List[Task]:
        """批量创建任务"""
        created = []
        for task in tasks:
            t = await self.create(task)
            created.append(t)
        return created

    async def get_by_id(self, task_id: str) -> Optional[Task]:
        """按 ID 获取任务"""
        cursor = await self.conn.execute(
            "SELECT * FROM et_tasks WHERE id = ?", (task_id,)
        )
        row = await cursor.fetchone()
        return self._row_to_task(row) if row else None

    async def update(self, task_id: str, **kwargs) -> bool:
        """更新任务字段。返回 True 表示有行被更新，False 表示无匹配行或无字段。"""
        allowed = {
            "status", "priority", "assigned_to", "assigned_by", "title",
            "description", "fix_diff", "fix_commit_hash", "fix_notes",
            "review_verdict", "review_comment", "reviewed_by", "reviewed_at",
            "due_date", "completed_at", "finding_rule_id", "finding_severity",
            "finding_file_path", "finding_line_start", "project_name",
        }
        fields = {k: v for k, v in kwargs.items() if k in allowed}
        if not fields:
            return False

        # 序列化枚举值
        for key in ("status", "priority", "review_verdict"):
            if key in fields and hasattr(fields[key], "value"):
                fields[key] = fields[key].value

        fields["updated_at"] = _now_iso()

        # 处理 tags 和 metadata
        if "tags" in fields and isinstance(fields["tags"], list):
            fields["tags"] = json.dumps(fields["tags"])
        if "metadata" in fields and isinstance(fields["metadata"], dict):
            fields["metadata"] = json.dumps(fields["metadata"])

        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [task_id]
        cursor = await self.conn.execute(
            f"UPDATE et_tasks SET {set_clause} WHERE id = ?", values
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def list_tasks(self, params: TaskQueryParams) -> List[Task]:
        """按条件查询任务列表"""
        clauses = []
        params_list: list = []

        if params.project_id:
            clauses.append("project_id = ?")
            params_list.append(params.project_id)
        if params.status:
            clauses.append("status = ?")
            params_list.append(params.status.value if hasattr(params.status, "value") else params.status)
        if params.task_type:
            clauses.append("task_type = ?")
            params_list.append(params.task_type.value if hasattr(params.task_type, "value") else params.task_type)
        if params.priority:
            clauses.append("priority = ?")
            params_list.append(params.priority.value if hasattr(params.priority, "value") else params.priority)
        if params.assigned_to:
            clauses.append("assigned_to = ?")
            params_list.append(params.assigned_to)
        if params.finding_severity:
            clauses.append("finding_severity = ?")
            params_list.append(params.finding_severity)
        if params.since:
            clauses.append("created_at >= ?")
            params_list.append(params.since)
        if params.until:
            clauses.append("created_at <= ?")
            params_list.append(params.until)

        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        query = f"SELECT * FROM et_tasks{where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params_list.extend([params.limit, params.offset])

        cursor = await self.conn.execute(query, params_list)
        rows = await cursor.fetchall()
        return [self._row_to_task(r) for r in rows]

    async def count(self, params: TaskQueryParams) -> int:
        """统计符合条件的任务数"""
        clauses = []
        params_list: list = []

        if params.project_id:
            clauses.append("project_id = ?")
            params_list.append(params.project_id)
        if params.status:
            clauses.append("status = ?")
            params_list.append(params.status.value if hasattr(params.status, "value") else params.status)
        if params.task_type:
            clauses.append("task_type = ?")
            params_list.append(params.task_type.value if hasattr(params.task_type, "value") else params.task_type)
        if params.priority:
            clauses.append("priority = ?")
            params_list.append(params.priority.value if hasattr(params.priority, "value") else params.priority)
        if params.assigned_to:
            clauses.append("assigned_to = ?")
            params_list.append(params.assigned_to)

        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        cursor = await self.conn.execute(
            f"SELECT COUNT(*) FROM et_tasks{where}", params_list
        )
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def delete(self, task_id: str) -> bool:
        """删除任务"""
        cursor = await self.conn.execute(
            "DELETE FROM et_tasks WHERE id = ?", (task_id,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def find_by_finding_id(self, finding_id: str) -> Optional[Task]:
        """按 Finding ID 查找任务（避免重复创建）"""
        cursor = await self.conn.execute(
            "SELECT * FROM et_tasks WHERE finding_id = ? AND status NOT IN ('done', 'cancelled') LIMIT 1",
            (finding_id,),
        )
        row = await cursor.fetchone()
        return self._row_to_task(row) if row else None

    async def get_stats(self, project_id: Optional[str] = None) -> TaskStats:
        """获取任务进度统计"""
        base_clauses: list = []
        base_params: list = []
        if project_id:
            base_clauses.append("project_id = ?")
            base_params.append(project_id)

        def _build_where(additional_clauses: list) -> tuple:
            """构建 WHERE 子句和参数"""
            all_clauses = list(base_clauses)
            all_clauses.extend(additional_clauses)
            where = " WHERE " + " AND ".join(all_clauses) if all_clauses else ""
            params = list(base_params)
            return where, params

        # 总数
        where, params = _build_where([])
        cursor = await self.conn.execute(
            f"SELECT COUNT(*) FROM et_tasks{where}", params
        )
        row = await cursor.fetchone()
        total = row[0] if row else 0

        # 按状态分组
        where, params = _build_where([])
        cursor = await self.conn.execute(
            f"SELECT status, COUNT(*) as cnt FROM et_tasks{where} GROUP BY status",
            params,
        )
        rows = await cursor.fetchall()
        by_status = {r["status"]: r["cnt"] for r in rows}

        # 按优先级分组
        where, params = _build_where([])
        cursor = await self.conn.execute(
            f"SELECT priority, COUNT(*) as cnt FROM et_tasks{where} GROUP BY priority",
            params,
        )
        rows = await cursor.fetchall()
        by_priority = {r["priority"]: r["cnt"] for r in rows}

        # 按类型分组
        where, params = _build_where([])
        cursor = await self.conn.execute(
            f"SELECT task_type, COUNT(*) as cnt FROM et_tasks{where} GROUP BY task_type",
            params,
        )
        rows = await cursor.fetchall()
        by_type = {r["task_type"]: r["cnt"] for r in rows}

        # 按指派人分组（仅统计有指派人的）
        where, params = _build_where([
            "assigned_to IS NOT NULL AND assigned_to != ''"
        ])
        cursor = await self.conn.execute(
            f"SELECT assigned_to, COUNT(*) as cnt FROM et_tasks{where} GROUP BY assigned_to",
            params,
        )
        rows = await cursor.fetchall()
        by_assignee = {r["assigned_to"]: r["cnt"] for r in rows}

        # 按严重度分组（仅统计有关联严重度的）
        where, params = _build_where([
            "finding_severity IS NOT NULL AND finding_severity != ''"
        ])
        cursor = await self.conn.execute(
            f"SELECT finding_severity, COUNT(*) as cnt FROM et_tasks{where} GROUP BY finding_severity",
            params,
        )
        rows = await cursor.fetchall()
        by_severity = {r["finding_severity"]: r["cnt"] for r in rows}

        # 完成率
        done_count = by_status.get("done", 0)
        cancelled_count = by_status.get("cancelled", 0)
        active_total = total - cancelled_count
        completion_rate = done_count / active_total if active_total > 0 else 0.0

        # 逾期数
        now = _now_iso()
        where, params = _build_where([
            "due_date IS NOT NULL",
            "status NOT IN ('done', 'cancelled')",
        ])
        params.append(now)
        cursor = await self.conn.execute(
            f"SELECT COUNT(*) FROM et_tasks{where} AND due_date < ?", params,
        )
        row = await cursor.fetchone()
        overdue_count = row[0] if row else 0

        # 平均解决耗时（小时）
        where, params = _build_where([
            "completed_at IS NOT NULL",
            "status = 'done'",
        ])
        cursor = await self.conn.execute(
            f"SELECT created_at, completed_at FROM et_tasks{where}", params,
        )
        resolution_rows = await cursor.fetchall()
        avg_hours = 0.0
        if resolution_rows:
            total_hours = 0.0
            for r in resolution_rows:
                try:
                    start = datetime.fromisoformat(r["created_at"])
                    end = datetime.fromisoformat(r["completed_at"])
                    total_hours += (end - start).total_seconds() / 3600.0
                except (ValueError, TypeError):
                    continue
            avg_hours = total_hours / len(resolution_rows)

        # 项目名称
        project_name = ""
        if project_id:
            cursor = await self.conn.execute(
                "SELECT DISTINCT project_name FROM et_tasks WHERE project_id = ? AND project_name != '' LIMIT 1",
                (project_id,),
            )
            row = await cursor.fetchone()
            if row:
                project_name = row["project_name"]

        return TaskStats(
            project_id=project_id,
            project_name=project_name,
            total_tasks=total,
            by_status=by_status,
            by_priority=by_priority,
            by_type=by_type,
            by_assignee=by_assignee,
            by_severity=by_severity,
            done_count=done_count,
            cancelled_count=cancelled_count,
            overdue_count=overdue_count,
            completion_rate=round(completion_rate, 4),
            avg_resolution_hours=round(avg_hours, 2),
        )

    @staticmethod
    def _row_to_task(row: aiosqlite.Row) -> Task:
        """行数据转为 Task 模型"""
        from .models import ReviewVerdict
        d = dict(row)

        # 反序列化 tags (JSON array)
        if isinstance(d.get("tags"), str):
            try:
                d["tags"] = json.loads(d["tags"])
            except json.JSONDecodeError:
                d["tags"] = []
        if not isinstance(d.get("tags"), list):
            d["tags"] = []

        # 反序列化 metadata (JSON object)
        if isinstance(d.get("metadata"), str):
            try:
                d["metadata"] = json.loads(d["metadata"])
            except json.JSONDecodeError:
                d["metadata"] = {}

        # 映射枚举
        if "task_type" in d and isinstance(d["task_type"], str):
            try:
                d["task_type"] = TaskType(d["task_type"])
            except ValueError:
                d["task_type"] = TaskType.SCAN
        if "status" in d and isinstance(d["status"], str):
            try:
                d["status"] = TaskStatus(d["status"])
            except ValueError:
                d["status"] = TaskStatus.PENDING
        if "priority" in d and isinstance(d["priority"], str):
            try:
                d["priority"] = TaskPriority(d["priority"])
            except ValueError:
                d["priority"] = TaskPriority.P2
        rv = d.get("review_verdict")
        if rv and isinstance(rv, str):
            try:
                d["review_verdict"] = ReviewVerdict(rv)
            except ValueError:
                d["review_verdict"] = None

        return Task(**d)


# ─────────────────────── TaskTransitionRepo ───────────────────────

class TaskTransitionRepo:
    """任务状态流转记录仓库"""

    def __init__(self, conn: aiosqlite.Connection):
        self.conn = conn

    async def record(
        self,
        task_id: str,
        to_status: str,
        from_status: Optional[str] = None,
        operator: Optional[str] = None,
        operator_role: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> TaskTransition:
        """记录状态流转"""
        now = _now_iso()
        await self.conn.execute(
            """INSERT INTO et_task_transitions
               (task_id, from_status, to_status, operator, operator_role, comment, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (task_id, from_status, to_status, operator, operator_role, comment, now),
        )
        await self.conn.commit()
        return TaskTransition(
            task_id=task_id, from_status=from_status, to_status=to_status,
            operator=operator, operator_role=operator_role, comment=comment,
            created_at=now,
        )

    async def list_by_task(self, task_id: str) -> List[TaskTransition]:
        """获取任务的所有流转记录"""
        cursor = await self.conn.execute(
            "SELECT * FROM et_task_transitions WHERE task_id = ? ORDER BY id ASC",
            (task_id,),
        )
        rows = await cursor.fetchall()
        return [self._row_to_transition(r) for r in rows]

    async def list_all(self, limit: int = 100, offset: int = 0) -> List[TaskTransition]:
        """获取最近的流转记录"""
        cursor = await self.conn.execute(
            "SELECT * FROM et_task_transitions ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return [self._row_to_transition(r) for r in rows]

    @staticmethod
    def _row_to_transition(row: aiosqlite.Row) -> TaskTransition:
        d = dict(row)
        if d.get("created_at") and isinstance(d["created_at"], str):
            d["created_at"] = d["created_at"]
        return TaskTransition(**d)


# ─────────────────────── TaskCommentRepo ───────────────────────

class TaskCommentRepo:
    """任务评论仓库"""

    def __init__(self, conn: aiosqlite.Connection):
        self.conn = conn

    async def add(
        self, task_id: str, content: str, author: Optional[str] = None
    ) -> TaskComment:
        """添加评论"""
        now = _now_iso()
        await self.conn.execute(
            """INSERT INTO et_task_comments (task_id, author, content, created_at)
               VALUES (?, ?, ?, ?)""",
            (task_id, author, content, now),
        )
        await self.conn.commit()
        return TaskComment(task_id=task_id, author=author, content=content, created_at=now)

    async def list_by_task(self, task_id: str) -> List[TaskComment]:
        """获取任务的所有评论"""
        cursor = await self.conn.execute(
            "SELECT * FROM et_task_comments WHERE task_id = ? ORDER BY id ASC",
            (task_id,),
        )
        rows = await cursor.fetchall()
        return [TaskComment(**dict(r)) for r in rows]

    async def delete(self, comment_id: int) -> bool:
        """删除评论"""
        cursor = await self.conn.execute(
            "DELETE FROM et_task_comments WHERE id = ?", (comment_id,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0
