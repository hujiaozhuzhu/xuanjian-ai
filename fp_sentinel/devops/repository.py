"""
DevSecOps 对接模块 - 数据存储层 (Repository)

提供 FindingTicketMapping / SyncRecord 的 CRUD 操作，
支持按多维度查询与同步流水追溯。

安全红线:
- S1: 纯本地 SQLite
- S2: 不修改任何外部系统
- S7: 数据落 ~/.xuanjian/
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiosqlite

from .models import FindingTicketMapping, SyncRecord, SyncStatus, TicketStatus

logger = logging.getLogger(__name__)


def _generate_id() -> str:
    """生成唯一 ID"""
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────── Schema ───────────────────────

SCHEMA_SQL = """
-- 发现 ↔ 外部工单映射表
CREATE TABLE IF NOT EXISTS do_finding_ticket_mapping (
    id                      TEXT PRIMARY KEY,
    finding_id              TEXT NOT NULL,
    finding_fingerprint     TEXT DEFAULT '',
    provider                TEXT NOT NULL,
    ticket_id               TEXT NOT NULL,
    ticket_key              TEXT DEFAULT '',
    ticket_url              TEXT DEFAULT '',
    ticket_status           TEXT DEFAULT 'open',
    project_id              TEXT DEFAULT '',
    repository_url          TEXT DEFAULT '',
    commit_hash             TEXT DEFAULT '',
    branch                  TEXT DEFAULT '',
    sync_status             TEXT DEFAULT 'pending',
    sync_direction          TEXT DEFAULT 'pending',
    severity                TEXT DEFAULT '',
    rule_id                 TEXT DEFAULT '',
    title                   TEXT DEFAULT '',
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    last_sync_at            TEXT,
    metadata                TEXT DEFAULT '{}'
);

-- 同步操作流水表
CREATE TABLE IF NOT EXISTS do_sync_record (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    mapping_id              TEXT NOT NULL,
    finding_id              TEXT NOT NULL,
    provider                TEXT NOT NULL,
    sync_direction          TEXT NOT NULL,
    status                  TEXT NOT NULL,
    ticket_id               TEXT DEFAULT '',
    ticket_key              TEXT DEFAULT '',
    request_payload         TEXT DEFAULT '',
    response_summary        TEXT DEFAULT '',
    error_message           TEXT DEFAULT '',
    attempt_count           INTEGER DEFAULT 1,
    created_at              TEXT NOT NULL,
    FOREIGN KEY (mapping_id) REFERENCES do_finding_ticket_mapping(id) ON DELETE CASCADE
);

-- Pipeline 卡点评估结果记录表
CREATE TABLE IF NOT EXISTS do_pipeline_gate_record (
    id                      TEXT PRIMARY KEY,
    provider                TEXT NOT NULL,
    project_id              TEXT NOT NULL,
    commit_hash             TEXT DEFAULT '',
    branch                  TEXT DEFAULT '',
    verdict                 TEXT NOT NULL,
    total_findings          INTEGER DEFAULT 0,
    critical_count          INTEGER DEFAULT 0,
    high_count              INTEGER DEFAULT 0,
    medium_count            INTEGER DEFAULT 0,
    low_count               INTEGER DEFAULT 0,
    info_count              INTEGER DEFAULT 0,
    violations_json         TEXT DEFAULT '[]',
    warnings_json           TEXT DEFAULT '[]',
    summary                 TEXT DEFAULT '',
    suggested_actions_json  TEXT DEFAULT '[]',
    evaluated_at            TEXT NOT NULL
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_doa_mapping_finding_id       ON do_finding_ticket_mapping(finding_id);
CREATE INDEX IF NOT EXISTS idx_doa_mapping_provider         ON do_finding_ticket_mapping(provider);
CREATE INDEX IF NOT EXISTS idx_doa_mapping_ticket_id        ON do_finding_ticket_mapping(ticket_id);
CREATE INDEX IF NOT EXISTS idx_doa_mapping_ticket_status    ON do_finding_ticket_mapping(ticket_status);
CREATE INDEX IF NOT EXISTS idx_doa_mapping_project_id       ON do_finding_ticket_mapping(project_id);
CREATE INDEX IF NOT EXISTS idx_doa_mapping_sync_status      ON do_finding_ticket_mapping(sync_status);
CREATE INDEX IF NOT EXISTS idx_doa_mapping_fingerprint      ON do_finding_ticket_mapping(finding_fingerprint);
CREATE INDEX IF NOT EXISTS idx_doa_sync_mapping_id          ON do_sync_record(mapping_id);
CREATE INDEX IF NOT EXISTS idx_doa_sync_finding_id          ON do_sync_record(finding_id);
CREATE INDEX IF NOT EXISTS idx_doa_sync_status              ON do_sync_record(status);
CREATE INDEX IF NOT EXISTS idx_doa_sync_created             ON do_sync_record(created_at);
CREATE INDEX IF NOT EXISTS idx_doa_gate_project_id          ON do_pipeline_gate_record(project_id);
CREATE INDEX IF NOT EXISTS idx_doa_gate_commit_hash         ON do_pipeline_gate_record(commit_hash);
CREATE INDEX IF NOT EXISTS idx_doa_gate_verdict             ON do_pipeline_gate_record(verdict);
CREATE INDEX IF NOT EXISTS idx_doa_gate_evaluated_at        ON do_pipeline_gate_record(evaluated_at);
"""


# ─────────────────────── FindingTicketMappingRepo ───────────────────────

class FindingTicketMappingRepo:
    """发现 ↔ 工单映射仓库"""

    def __init__(self, conn: aiosqlite.Connection):
        self.conn = conn

    async def initialize_schema(self) -> None:
        """初始化 Schema"""
        await self.conn.executescript(SCHEMA_SQL)
        await self.conn.commit()

    async def create(self, mapping: FindingTicketMapping) -> FindingTicketMapping:
        """创建映射"""
        if not mapping.id:
            mapping.id = _generate_id()
        mapping.created_at = mapping.created_at or _now_iso()
        mapping.updated_at = _now_iso()

        await self.conn.execute(
            """INSERT INTO do_finding_ticket_mapping
               (id, finding_id, finding_fingerprint, provider, ticket_id, ticket_key,
                ticket_url, ticket_status, project_id, repository_url, commit_hash, branch,
                sync_status, sync_direction, severity, rule_id, title,
                created_at, updated_at, last_sync_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                mapping.id, mapping.finding_id, mapping.finding_fingerprint,
                mapping.provider.value, mapping.ticket_id, mapping.ticket_key,
                mapping.ticket_url, mapping.ticket_status.value, mapping.project_id,
                mapping.repository_url, mapping.commit_hash, mapping.branch,
                mapping.sync_status.value, mapping.sync_direction.value,
                mapping.severity, mapping.rule_id, mapping.title,
                mapping.created_at, mapping.updated_at, mapping.last_sync_at,
                json.dumps(mapping.metadata),
            ),
        )
        await self.conn.commit()
        return mapping

    async def get_by_id(self, mapping_id: str) -> Optional[FindingTicketMapping]:
        """按 ID 查询"""
        cursor = await self.conn.execute(
            "SELECT * FROM do_finding_ticket_mapping WHERE id = ?", (mapping_id,)
        )
        row = await cursor.fetchone()
        return self._row_to_mapping(row) if row else None

    async def get_by_finding_id(self, finding_id: str, provider: Optional[str] = None) -> Optional[FindingTicketMapping]:
        """按 Finding ID 查找映射"""
        if provider:
            cursor = await self.conn.execute(
                "SELECT * FROM do_finding_ticket_mapping WHERE finding_id = ? AND provider = ? "
                "ORDER BY updated_at DESC LIMIT 1",
                (finding_id, provider),
            )
        else:
            cursor = await self.conn.execute(
                "SELECT * FROM do_finding_ticket_mapping WHERE finding_id = ? "
                "ORDER BY updated_at DESC LIMIT 1",
                (finding_id,),
            )
        row = await cursor.fetchone()
        return self._row_to_mapping(row) if row else None

    async def get_by_ticket_id(self, ticket_id: str, provider: Optional[str] = None) -> Optional[FindingTicketMapping]:
        """按工单 ID 查找映射"""
        if provider:
            cursor = await self.conn.execute(
                "SELECT * FROM do_finding_ticket_mapping WHERE ticket_id = ? AND provider = ? LIMIT 1",
                (ticket_id, provider),
            )
        else:
            cursor = await self.conn.execute(
                "SELECT * FROM do_finding_ticket_mapping WHERE ticket_id = ? LIMIT 1",
                (ticket_id,),
            )
        row = await cursor.fetchone()
        return self._row_to_mapping(row) if row else None

    async def list_mappings(
        self,
        provider: Optional[str] = None,
        ticket_status: Optional[str] = None,
        sync_status: Optional[str] = None,
        project_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[FindingTicketMapping]:
        """多维度查询映射列表"""
        clauses = []
        params_list: list = []

        if provider:
            clauses.append("provider = ?")
            params_list.append(provider)
        if ticket_status:
            clauses.append("ticket_status = ?")
            params_list.append(ticket_status)
        if sync_status:
            clauses.append("sync_status = ?")
            params_list.append(sync_status)
        if project_id:
            clauses.append("project_id = ?")
            params_list.append(project_id)

        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        query = f"SELECT * FROM do_finding_ticket_mapping{where} ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        params_list.extend([limit, offset])

        cursor = await self.conn.execute(query, params_list)
        rows = await cursor.fetchall()
        return [self._row_to_mapping(r) for r in rows]

    async def count(
        self,
        provider: Optional[str] = None,
        ticket_status: Optional[str] = None,
        sync_status: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> int:
        """统计映射数"""
        clauses = []
        params_list: list = []
        if provider:
            clauses.append("provider = ?")
            params_list.append(provider)
        if ticket_status:
            clauses.append("ticket_status = ?")
            params_list.append(ticket_status)
        if sync_status:
            clauses.append("sync_status = ?")
            params_list.append(sync_status)
        if project_id:
            clauses.append("project_id = ?")
            params_list.append(project_id)

        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        cursor = await self.conn.execute(
            f"SELECT COUNT(*) FROM do_finding_ticket_mapping{where}", params_list
        )
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def update(self, mapping_id: str, **kwargs) -> bool:
        """更新"""
        allowed = {
            "ticket_status", "sync_status", "sync_direction", "ticket_url",
            "ticket_key", "title", "commit_hash", "branch", "last_sync_at",
            "metadata", "repository_url",
        }
        fields = {k: v for k, v in kwargs.items() if k in allowed}
        if not fields:
            return False

        # 序列化枚举 (sync_direction 也是 SyncDirection 类型，有 value 属性)
        for key in ("ticket_status", "sync_status", "sync_direction"):
            if key in fields and hasattr(fields[key], "value"):
                fields[key] = fields[key].value

        if "metadata" in fields and isinstance(fields["metadata"], dict):
            fields["metadata"] = json.dumps(fields["metadata"])

        fields["updated_at"] = _now_iso()

        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [mapping_id]
        cursor = await self.conn.execute(
            f"UPDATE do_finding_ticket_mapping SET {set_clause} WHERE id = ?", values
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    @staticmethod
    def _row_to_mapping(row: aiosqlite.Row) -> FindingTicketMapping:
        """行转模型 — 使用顶层静态导入避免循环引用"""
        from .models import DevOpsProvider, SyncDirection, SyncStatus, TicketStatus
        d = dict(row)

        # 反序列化 metadata
        if isinstance(d.get("metadata"), str):
            try:
                d["metadata"] = json.loads(d["metadata"])
            except json.JSONDecodeError:
                d["metadata"] = {}

        # 映射枚举 (sync_direction 可能存有旧 SyncStatus 值，需宽容处理)
        _ENUM_MAP = {
            "provider": DevOpsProvider,
            "ticket_status": TicketStatus,
            "sync_status": SyncStatus,
            "sync_direction": SyncDirection,
        }
        for enum_key, enum_cls in _ENUM_MAP.items():
            v = d.get(enum_key)
            if v and isinstance(v, str):
                try:
                    d[enum_key] = enum_cls(v)
                except ValueError:
                    # 旧数据可能存了 SyncStatus 值，对于 sync_direction 宽容降级
                    if enum_key == "sync_direction":
                        d["sync_direction"] = SyncDirection.FINDING_TO_TICKET
                    pass

        return FindingTicketMapping(**d)


# ─────────────────────── SyncRecordRepo ───────────────────────

class SyncRecordRepo:
    """同步操作流水仓库"""

    def __init__(self, conn: aiosqlite.Connection):
        self.conn = conn

    async def create(self, record: SyncRecord) -> SyncRecord:
        """创建记录"""
        now = _now_iso()
        if not record.created_at:
            record.created_at = now

        await self.conn.execute(
            """INSERT INTO do_sync_record
               (mapping_id, finding_id, provider, sync_direction, status,
                ticket_id, ticket_key, request_payload, response_summary,
                error_message, attempt_count, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.mapping_id, record.finding_id,
                record.provider.value if hasattr(record.provider, "value") else record.provider,
                record.sync_direction.value if hasattr(record.sync_direction, "value") else record.sync_direction,
                record.status.value if hasattr(record.status, "value") else record.status,
                record.ticket_id, record.ticket_key, record.request_payload,
                record.response_summary, record.error_message,
                record.attempt_count, record.created_at,
            ),
        )
        await self.conn.commit()

        cursor = await self.conn.execute("SELECT last_insert_rowid()")
        row = await cursor.fetchone()
        if row:
            record.id = row[0]
        return record

    async def list_by_mapping(self, mapping_id: str, limit: int = 100) -> List[SyncRecord]:
        """按映射 ID 查流水"""
        cursor = await self.conn.execute(
            "SELECT * FROM do_sync_record WHERE mapping_id = ? ORDER BY id DESC LIMIT ?",
            (mapping_id, limit),
        )
        rows = await cursor.fetchall()
        return [self._row_to_record(r) for r in rows]

    async def list_all(self, limit: int = 100, offset: int = 0) -> List[SyncRecord]:
        """获取最近流水"""
        cursor = await self.conn.execute(
            "SELECT * FROM do_sync_record ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return [self._row_to_record(r) for r in rows]

    async def count_by_status(self) -> Dict[str, int]:
        """按状态分组统计"""
        cursor = await self.conn.execute(
            "SELECT status, COUNT(*) as cnt FROM do_sync_record GROUP BY status"
        )
        rows = await cursor.fetchall()
        return {r["status"]: r["cnt"] for r in rows}

    @staticmethod
    def _row_to_record(row: aiosqlite.Row) -> SyncRecord:
        """行转模型 — 使用静态导入避免动态 __import__"""
        from .models import DevOpsProvider, SyncDirection, SyncStatus
        d = dict(row)
        _ENUM_MAP = {
            "provider": DevOpsProvider,
            "sync_direction": SyncDirection,
            "status": SyncStatus,
        }
        for enum_key, enum_cls in _ENUM_MAP.items():
            v = d.get(enum_key)
            if v and isinstance(v, str):
                try:
                    d[enum_key] = enum_cls(v)
                except (ValueError, KeyError):
                    pass
        return SyncRecord(**d)


# ─────────────────────── PipelineGateRecordRepo ───────────────────────

class PipelineGateRecordRepo:
    """Pipeline 卡点评估记录仓库"""

    def __init__(self, conn: aiosqlite.Connection):
        self.conn = conn

    async def save_result(self, result) -> None:
        """保存评估结果"""
        gate_id = _generate_id()
        now = _now_iso()
        await self.conn.execute(
            """INSERT INTO do_pipeline_gate_record
               (id, provider, project_id, commit_hash, branch, verdict,
                total_findings, critical_count, high_count, medium_count,
                low_count, info_count, violations_json, warnings_json,
                summary, suggested_actions_json, evaluated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                gate_id,
                result.provider.value if hasattr(result.provider, "value") else result.provider,
                result.project_id, result.commit_hash, result.branch,
                result.verdict.value, result.total_findings,
                result.critical_count, result.high_count, result.medium_count,
                result.low_count, result.info_count,
                json.dumps([v.model_dump() for v in result.violations]),
                json.dumps([w.model_dump() for w in result.warnings]),
                result.summary,
                json.dumps(result.suggested_actions),
                now,
            ),
        )
        await self.conn.commit()

    async def list_by_project(self, project_id: str, limit: int = 50) -> List[dict]:
        """按项目查评估记录"""
        cursor = await self.conn.execute(
            "SELECT * FROM do_pipeline_gate_record WHERE project_id = ? ORDER BY evaluated_at DESC LIMIT ?",
            (project_id, limit),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_latest_by_commit(self, project_id: str, commit_hash: str) -> Optional[dict]:
        """按 commit hash 查最新评估"""
        cursor = await self.conn.execute(
            "SELECT * FROM do_pipeline_gate_record WHERE project_id = ? AND commit_hash = ? "
            "ORDER BY evaluated_at DESC LIMIT 1",
            (project_id, commit_hash),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
