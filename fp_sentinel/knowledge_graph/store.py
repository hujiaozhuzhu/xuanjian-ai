"""
知识图谱归档存储 (SQLite 后端，零网络)

负责：
- 初始化 schema (kg_snapshots / kg_fix_records + 索引)
- archive_snapshot / archive_records    自动归档写入
- search_snapshots / search_records      按项目 / 版本 / 漏洞类型 / 时间范围检索
- stats()                                主要统计信息
- purge()                                过期数据清理 (S5 红线语义)

与 fp_sentinel.database.connection 风格一致：使用 aiosqlite + WAL，对外提供
异步上下文管理器。独立于主 findings 数据库，避免干扰已有的扫描流水线。
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional

import aiosqlite

from .models import ArchiveQuery, FixRecord, FixSnapshot


logger = logging.getLogger(__name__)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS kg_snapshots (
    id                 TEXT PRIMARY KEY,
    project_name       TEXT NOT NULL,
    project_path       TEXT NOT NULL,
    version            TEXT DEFAULT 'unversioned',
    language           TEXT,
    scanner            TEXT,
    total_findings     INTEGER DEFAULT 0,
    by_severity        TEXT DEFAULT '{}',
    by_category        TEXT DEFAULT '{}',
    duration_seconds   REAL DEFAULT 0.0,
    report_kind        TEXT DEFAULT 'compliance',
    report_text        TEXT DEFAULT '',
    fix_cve_hits       INTEGER DEFAULT 0,
    fix_knowledge_hits INTEGER DEFAULT 0,
    archived_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_kg_snap_project   ON kg_snapshots(project_name);
CREATE INDEX IF NOT EXISTS idx_kg_snap_ppath     ON kg_snapshots(project_path);
CREATE INDEX IF NOT EXISTS idx_kg_snap_version   ON kg_snapshots(version);
CREATE INDEX IF NOT EXISTS idx_kg_snap_time      ON kg_snapshots(archived_at);

CREATE TABLE IF NOT EXISTS kg_fix_records (
    id              TEXT PRIMARY KEY,
    snapshot_id     TEXT NOT NULL,
    finding_id      TEXT,
    project_name    TEXT NOT NULL,
    project_path    TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    line_start      INTEGER DEFAULT 0,
    line_end        INTEGER,
    code_snippet    TEXT DEFAULT '',
    message         TEXT DEFAULT '',
    category        TEXT,
    language        TEXT,
    cwe             TEXT,
    owasp           TEXT,
    scanner         TEXT,
    confidence      REAL DEFAULT 0.0,
    fix_title       TEXT DEFAULT '',
    fix_diff        TEXT DEFAULT '',
    fix_effort_minutes INTEGER DEFAULT 0,
    reference_cve   TEXT DEFAULT '',
    incident_note   TEXT DEFAULT '',
    archived_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (snapshot_id) REFERENCES kg_snapshots(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_kg_rec_snapshot ON kg_fix_records(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_kg_rec_rule     ON kg_fix_records(rule_id);
CREATE INDEX IF NOT EXISTS idx_kg_rec_category ON kg_fix_records(category);
CREATE INDEX IF NOT EXISTS idx_kg_rec_cwe      ON kg_fix_records(cwe);
CREATE INDEX IF NOT EXISTS idx_kg_rec_project  ON kg_fix_records(project_name);
CREATE INDEX IF NOT EXISTS idx_kg_rec_time     ON kg_fix_records(archived_at);
CREATE INDEX IF NOT EXISTS idx_kg_rec_severity ON kg_fix_records(severity);
"""


def _generate_id() -> str:
    return str(uuid.uuid4())


class KnowledgeStore:
    """知识图谱归档存储 —— 单 SQLite 文件 + aiosqlite + WAL。"""

    def __init__(self, db_path: str, wal_mode: bool = True):
        # 对 ":memory:" 特殊处理：aiosqlite 无法解析含 ":"
        self._is_memory = db_path.strip().lower().startswith(":memory:")
        if self._is_memory:
            self.db_path = ":memory:"
        else:
            self.db_path = os.path.abspath(os.path.expanduser(db_path))
        self.wal_mode = wal_mode
        self._conn: Optional[aiosqlite.Connection] = None

    # ────── 连接管理 ──────
    async def connect(self) -> None:
        if not self._is_memory:
            os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        if self.wal_mode and not self._is_memory:
            await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute("PRAGMA busy_timeout=5000")
        logger.info("Knowledge store connected: %s", self.db_path)

    async def initialize(self) -> None:
        if self._conn is None:
            raise RuntimeError("not connected")
        await self._conn.executescript(SCHEMA_SQL)
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("not connected")
        return self._conn

    async def __aenter__(self):
        await self.connect()
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        return False

    # ────── 写入 ──────
    async def archive_snapshot(self, snapshot: FixSnapshot) -> FixSnapshot:
        if not snapshot.id:
            snapshot.id = _generate_id()
        await self.conn.execute(
            """INSERT INTO kg_snapshots
               (id, project_name, project_path, version, language, scanner,
                total_findings, by_severity, by_category, duration_seconds,
                report_kind, report_text, fix_cve_hits, fix_knowledge_hits, archived_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                snapshot.id,
                snapshot.project_name,
                snapshot.project_path,
                snapshot.version,
                snapshot.language or "",
                snapshot.scanner,
                snapshot.total_findings,
                json.dumps(snapshot.by_severity or {}),
                json.dumps(snapshot.by_category or {}),
                snapshot.duration_seconds,
                snapshot.report_kind,
                snapshot.report_text,
                snapshot.fix_cve_hits,
                snapshot.fix_knowledge_hits,
                snapshot.archived_at,
            ),
        )
        await self.conn.commit()
        return snapshot

    async def archive_records(
        self,
        snapshot_id: str,
        records: List[FixRecord],
    ) -> List[FixRecord]:
        rows = []
        out: List[FixRecord] = []
        for r in records:
            if not r.id:
                r.id = _generate_id()
            r.snapshot_id = snapshot_id
            d = r.to_row()
            out.append(r)
            rows.append(
                (
                    d["id"], snapshot_id, d["finding_id"],
                    d["project_name"], d["project_path"],
                    d["rule_id"], d["severity"], d["file_path"],
                    d["line_start"], d["line_end"],
                    d["code_snippet"], d["message"],
                    d["category"], d["language"], d["cwe"], d["owasp"],
                    d["scanner"], d["confidence"],
                    d["fix_title"], d["fix_diff"],
                    d["fix_effort_minutes"], d["reference_cve"],
                    d["incident_note"], d["archived_at"],
                )
            )
        if rows:
            await self.conn.executemany(
                """INSERT INTO kg_fix_records
                   (id, snapshot_id, finding_id,
                    project_name, project_path,
                    rule_id, severity, file_path,
                    line_start, line_end,
                    code_snippet, message,
                    category, language, cwe, owasp,
                    scanner, confidence,
                    fix_title, fix_diff,
                    fix_effort_minutes, reference_cve,
                    incident_note, archived_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )
            await self.conn.commit()
        return out

    # ────── 查询 ──────
    async def search_snapshots(
        self,
        query: ArchiveQuery,
    ) -> List[FixSnapshot]:
        clauses: List[str] = []
        params: List[Any] = []
        self._apply_snapshot_filters(clauses, params, query)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            f"SELECT * FROM kg_snapshots{where}"
            f" ORDER BY archived_at DESC, id DESC LIMIT ? OFFSET ?"
        )
        params.extend([query.limit, query.offset])
        cur = await self.conn.execute(sql, params)
        rows = await cur.fetchall()
        return [self._row_to_snapshot(r) for r in rows]

    async def count_snapshots(self, query: ArchiveQuery) -> int:
        clauses: List[str] = []
        params: List[Any] = []
        self._apply_snapshot_filters(clauses, params, query)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cur = await self.conn.execute(
            f"SELECT COUNT(*) FROM kg_snapshots{where}", params
        )
        row = await cur.fetchone()
        return int(row[0]) if row else 0

    async def get_snapshot(self, snapshot_id: str) -> Optional[FixSnapshot]:
        cur = await self.conn.execute(
            "SELECT * FROM kg_snapshots WHERE id = ?", (snapshot_id,)
        )
        row = await cur.fetchone()
        return self._row_to_snapshot(row) if row else None

    async def search_records(
        self,
        query: ArchiveQuery,
        *,
        snapshot_id: Optional[str] = None,
    ) -> List[FixRecord]:
        clauses: List[str] = []
        params: List[Any] = []
        self._apply_record_filters(clauses, params, query)
        if snapshot_id:
            clauses.append("snapshot_id = ?")
            params.append(snapshot_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            f"SELECT * FROM kg_fix_records{where}"
            f" ORDER BY archived_at DESC, id DESC LIMIT ? OFFSET ?"
        )
        params.extend([query.limit, query.offset])
        cur = await self.conn.execute(sql, params)
        rows = await cur.fetchall()
        return [self._row_to_record(r) for r in rows]

    async def count_records(
        self,
        query: ArchiveQuery,
        *,
        snapshot_id: Optional[str] = None,
    ) -> int:
        clauses: List[str] = []
        params: List[Any] = []
        self._apply_record_filters(clauses, params, query)
        if snapshot_id:
            clauses.append("snapshot_id = ?")
            params.append(snapshot_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cur = await self.conn.execute(
            f"SELECT COUNT(*) FROM kg_fix_records{where}", params
        )
        row = await cur.fetchone()
        return int(row[0]) if row else 0

    # ────── 统计与清理 ──────
    async def stats(self) -> Dict[str, Any]:
        cur = await self.conn.execute("SELECT COUNT(*) FROM kg_snapshots")
        snap_n = (await cur.fetchone())[0]
        cur = await self.conn.execute("SELECT COUNT(*) FROM kg_fix_records")
        rec_n = (await cur.fetchone())[0]
        cur = await self.conn.execute(
            "SELECT COUNT(*) FROM kg_fix_records WHERE reference_cve <> ''"
        )
        cve_n = (await cur.fetchone())[0]
        cur = await self.conn.execute(
            "SELECT COUNT(DISTINCT project_name) FROM kg_snapshots"
        )
        proj_n = (await cur.fetchone())[0]
        cur = await self.conn.execute(
            "SELECT COALESCE(SUM(total_findings), 0) FROM kg_snapshots"
        )
        total_findings = (await cur.fetchone())[0]
        return {
            "snapshots": int(snap_n),
            "records": int(rec_n),
            "projects": int(proj_n),
            "cve_hits": int(cve_n),
            "total_findings": int(total_findings),
        }

    async def purge(self, days: int = 90) -> int:
        """清理超过 N 天的记录（含引用级联删除）—— S5 红线语义。"""
        cutoff = ""
        try:
            from datetime import datetime, timedelta, timezone

            cutoff = (
                __import__("datetime").datetime.now(timezone.utc)
                - timedelta(days=days)
            ).isoformat()
        except Exception:  # noqa: BLE001
            return 0
        cur = await self.conn.execute(
            "DELETE FROM kg_snapshots WHERE archived_at < ?", (cutoff,)
        )
        await self.conn.commit()
        return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

    # ────── 行映射 ──────
    @staticmethod
    def _row_to_snapshot(row: aiosqlite.Row) -> FixSnapshot:
        d = dict(row)
        for k in ("by_severity", "by_category"):
            v = d.get(k)
            if isinstance(v, str):
                try:
                    d[k] = json.loads(v)
                except json.JSONDecodeError:
                    d[k] = {}
        return FixSnapshot(**{k: d.get(k) for k in d})

    @staticmethod
    def _row_to_record(row: aiosqlite.Row) -> FixRecord:
        d = dict(row)
        return FixRecord(**{k: d.get(k) for k in d})

    # ────── 共用过滤条件 ──────
    @staticmethod
    def _apply_snapshot_filters(
        clauses: List[str], params: List[Any], q: ArchiveQuery
    ) -> None:
        if q.project_name:
            clauses.append("project_name = ?"); params.append(q.project_name)
        if q.project_path:
            clauses.append("project_path = ?"); params.append(q.project_path)
        if q.version:
            clauses.append("version = ?"); params.append(q.version)
        if q.since:
            clauses.append("archived_at >= ?"); params.append(q.since)
        if q.until:
            clauses.append("archived_at <= ?"); params.append(q.until)

    @staticmethod
    def _apply_record_filters(
        clauses: List[str], params: List[Any], q: ArchiveQuery
    ) -> None:
        if q.project_name:
            clauses.append("project_name = ?"); params.append(q.project_name)
        if q.project_path:
            clauses.append("project_path = ?"); params.append(q.project_path)
        if q.category:
            clauses.append("category = ?"); params.append(q.category)
        if q.cwe:
            clauses.append("cwe = ?"); params.append(q.cwe)
        if q.language:
            clauses.append("language = ?"); params.append(q.language)
        if q.severity:
            clauses.append("severity = ?"); params.append(q.severity)
        if q.rule_id:
            # rule_id 支持前缀匹配（例如 py.injection.*）
            clauses.append("rule_id LIKE ? ESCAPE '\\'")
            params.append(q.rule_id.replace("%", "\\%").replace("_", "\\_") + "%")
        if q.since:
            clauses.append("archived_at >= ?"); params.append(q.since)
        if q.until:
            clauses.append("archived_at <= ?"); params.append(q.until)


def default_kg_db_path() -> str:
    """默认知识图谱数据库路径：与主 ~/.xuanjian/data.db 同目录下的 kg_archive.db"""
    return os.path.join(
        os.path.expanduser("~"), ".xuanjian", "kg_archive.db"
    )


def open_store(db_path: Optional[str] = None) -> KnowledgeStore:
    """构建 KnowledgeStore 实例（不连接，由 async with 接管）。"""
    return KnowledgeStore(db_path or default_kg_db_path())
