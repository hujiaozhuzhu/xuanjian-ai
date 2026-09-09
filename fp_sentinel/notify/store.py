"""
企业通知模块 — SQLite 持久化存储

负责：
- 初始化 schema (notify_channels / notify_rules / notify_records + 索引)
- 渠道 CRUD / 规则 CRUD / 记录写入与查询
- 重复抑制查询（按 finding_id + 时间窗口）
- 清理过期推送记录

与 fp_sentinel.database.connection 风格一致：使用 aiosqlite + WAL，对外提供
异步上下文管理器。独立于主 findings 数据库，不干扰已有的扫描流水线。
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import aiosqlite

from .models import (
    IMChannel,
    IMChannelType,
    NotifyEvent,
    NotifyFrequency,
    NotifyRecord,
    NotifyRule,
    NotifyStatus,
)


logger = logging.getLogger(__name__)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS notify_channels (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    channel_type    TEXT NOT NULL,
    webhook_url     TEXT NOT NULL,
    secret          TEXT DEFAULT '',
    enabled         INTEGER DEFAULT 1,
    timeout_seconds INTEGER DEFAULT 10,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_nc_enabled ON notify_channels(enabled);

CREATE TABLE IF NOT EXISTS notify_rules (
    id                          TEXT PRIMARY KEY,
    name                        TEXT NOT NULL,
    enabled                     INTEGER DEFAULT 1,
    min_severity                TEXT DEFAULT 'HIGH',
    events                      TEXT DEFAULT '[]',
    channels                    TEXT DEFAULT '[]',
    frequency                   TEXT DEFAULT 'realtime',
    rule_id_patterns            TEXT DEFAULT '[]',
    path_patterns               TEXT DEFAULT '[]',
    suppress_duplicates_minutes INTEGER DEFAULT 60,
    created_at                  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at                  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_nr_enabled ON notify_rules(enabled);

CREATE TABLE IF NOT EXISTS notify_records (
    id              TEXT PRIMARY KEY,
    channel_id      TEXT,
    rule_id         TEXT,
    event           TEXT,
    finding_id      TEXT,
    status          TEXT DEFAULT 'pending',
    title           TEXT DEFAULT '',
    content         TEXT DEFAULT '',
    error_message   TEXT,
    retry_count     INTEGER DEFAULT 0,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent_at         TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_nrec_status   ON notify_records(status);
CREATE INDEX IF NOT EXISTS idx_nrec_finding  ON notify_records(finding_id);
CREATE INDEX IF NOT EXISTS idx_nrec_channel  ON notify_records(channel_id);
CREATE INDEX IF NOT EXISTS idx_nrec_created  ON notify_records(created_at);
"""


def _generate_id() -> str:
    return str(uuid.uuid4())


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class NotifyStore:
    """企业通知存储 —— 单 SQLite 文件 + aiosqlite + WAL。"""

    def __init__(self, db_path: str, wal_mode: bool = True):
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
        logger.info("Notify store connected: %s", self.db_path)

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

    # ════════════════════ 渠道 CRUD ════════════════════

    async def create_channel(self, channel: IMChannel) -> IMChannel:
        if not channel.id:
            channel.id = _generate_id()
        channel.created_at = _now_utc()
        channel.updated_at = _now_utc()
        await self.conn.execute(
            """INSERT INTO notify_channels
               (id, name, channel_type, webhook_url, secret, enabled,
                timeout_seconds, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                channel.id, channel.name, channel.channel_type.value,
                channel.webhook_url, channel.secret or "",
                int(channel.enabled), channel.timeout_seconds,
                channel.created_at.isoformat(), channel.updated_at.isoformat(),
            ),
        )
        await self.conn.commit()
        return channel

    async def update_channel(self, channel: IMChannel) -> IMChannel:
        if not channel.id:
            raise ValueError("channel id required for update")
        channel.updated_at = _now_utc()
        await self.conn.execute(
            """UPDATE notify_channels SET
                   name = ?, channel_type = ?, webhook_url = ?, secret = ?,
                   enabled = ?, timeout_seconds = ?, updated_at = ?
               WHERE id = ?""",
            (
                channel.name, channel.channel_type.value,
                channel.webhook_url, channel.secret or "",
                int(channel.enabled), channel.timeout_seconds,
                channel.updated_at.isoformat(), channel.id,
            ),
        )
        await self.conn.commit()
        return channel

    async def delete_channel(self, channel_id: str) -> bool:
        cur = await self.conn.execute(
            "DELETE FROM notify_channels WHERE id = ?", (channel_id,)
        )
        await self.conn.commit()
        return cur.rowcount is not None and cur.rowcount > 0

    async def get_channel(self, channel_id: str) -> Optional[IMChannel]:
        cur = await self.conn.execute(
            "SELECT * FROM notify_channels WHERE id = ?", (channel_id,)
        )
        row = await cur.fetchone()
        return self._row_to_channel(row) if row else None

    async def list_channels(self, enabled_only: bool = False) -> List[IMChannel]:
        sql = "SELECT * FROM notify_channels"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY created_at DESC"
        cur = await self.conn.execute(sql)
        rows = await cur.fetchall()
        return [self._row_to_channel(r) for r in rows]

    # ════════════════════ 规则 CRUD ════════════════════

    async def create_rule(self, rule: NotifyRule) -> NotifyRule:
        if not rule.id:
            rule.id = _generate_id()
        rule.created_at = _now_utc()
        rule.updated_at = _now_utc()
        await self.conn.execute(
            """INSERT INTO notify_rules
               (id, name, enabled, min_severity, events, channels,
                frequency, rule_id_patterns, path_patterns,
                suppress_duplicates_minutes, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rule.id, rule.name, int(rule.enabled), rule.min_severity,
                json.dumps([e.value for e in rule.events]),
                json.dumps(rule.channels), rule.frequency.value,
                json.dumps(rule.rule_id_patterns),
                json.dumps(rule.path_patterns),
                rule.suppress_duplicates_minutes,
                rule.created_at.isoformat(), rule.updated_at.isoformat(),
            ),
        )
        await self.conn.commit()
        return rule

    async def update_rule(self, rule: NotifyRule) -> NotifyRule:
        if not rule.id:
            raise ValueError("rule id required for update")
        rule.updated_at = _now_utc()
        await self.conn.execute(
            """UPDATE notify_rules SET
                   name = ?, enabled = ?, min_severity = ?, events = ?,
                   channels = ?, frequency = ?, rule_id_patterns = ?,
                   path_patterns = ?, suppress_duplicates_minutes = ?,
                   updated_at = ?
               WHERE id = ?""",
            (
                rule.name, int(rule.enabled), rule.min_severity,
                json.dumps([e.value for e in rule.events]),
                json.dumps(rule.channels), rule.frequency.value,
                json.dumps(rule.rule_id_patterns),
                json.dumps(rule.path_patterns),
                rule.suppress_duplicates_minutes,
                rule.updated_at.isoformat(), rule.id,
            ),
        )
        await self.conn.commit()
        return rule

    async def delete_rule(self, rule_id: str) -> bool:
        cur = await self.conn.execute(
            "DELETE FROM notify_rules WHERE id = ?", (rule_id,)
        )
        await self.conn.commit()
        return cur.rowcount is not None and cur.rowcount > 0

    async def get_rule(self, rule_id: str) -> Optional[NotifyRule]:
        cur = await self.conn.execute(
            "SELECT * FROM notify_rules WHERE id = ?", (rule_id,)
        )
        row = await cur.fetchone()
        return self._row_to_rule(row) if row else None

    async def list_rules(self, enabled_only: bool = False) -> List[NotifyRule]:
        sql = "SELECT * FROM notify_rules"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY created_at DESC"
        cur = await self.conn.execute(sql)
        rows = await cur.fetchall()
        return [self._row_to_rule(r) for r in rows]

    # ════════════════════ 推送记录 ════════════════════

    async def create_record(self, record: NotifyRecord) -> NotifyRecord:
        if not record.id:
            record.id = _generate_id()
        record.created_at = _now_utc()
        await self.conn.execute(
            """INSERT INTO notify_records
               (id, channel_id, rule_id, event, finding_id, status,
                title, content, error_message, retry_count, created_at, sent_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.id,
                record.channel_id,
                record.rule_id,
                record.event.value if record.event else None,
                record.finding_id,
                record.status.value if record.status else None,
                record.title, record.content,
                record.error_message, record.retry_count,
                record.created_at.isoformat(),
                record.sent_at.isoformat() if record.sent_at else None,
            ),
        )
        await self.conn.commit()
        return record

    async def update_record_status(
        self,
        record_id: str,
        status: NotifyStatus,
        error_message: Optional[str] = None,
        retry_count: Optional[int] = None,
        sent_at: Optional[datetime] = None,
    ) -> None:
        sets = ["status = ?"]
        params: List[Any] = [status.value]
        if error_message is not None:
            sets.append("error_message = ?"); params.append(error_message)
        if retry_count is not None:
            sets.append("retry_count = ?"); params.append(retry_count)
        if sent_at is not None:
            sets.append("sent_at = ?"); params.append(sent_at.isoformat())
        params.append(record_id)
        await self.conn.execute(
            f"UPDATE notify_records SET {', '.join(sets)} WHERE id = ?",
            params,
        )
        await self.conn.commit()

    async def list_records(
        self,
        status_filter: Optional[NotifyStatus] = None,
        channel_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[NotifyRecord]:
        clauses: List[str] = []
        params: List[Any] = []
        if status_filter is not None:
            clauses.append("status = ?"); params.append(status_filter.value)
        if channel_id is not None:
            clauses.append("channel_id = ?"); params.append(channel_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM notify_records{where} ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        cur = await self.conn.execute(sql, params)
        rows = await cur.fetchall()
        return [self._row_to_record(r) for r in rows]

    async def count_recent_by_finding(
        self,
        finding_id: str,
        window_minutes: int,
    ) -> int:
        """查询某 finding 在给定时间窗口内已发送的通知数（重复抑制用）"""
        cutoff = (_now_utc() - timedelta(minutes=window_minutes)).isoformat()
        cur = await self.conn.execute(
            """SELECT COUNT(*) FROM notify_records
               WHERE finding_id = ? AND created_at >= ?
                     AND status IN ('sent', 'pending')""",
            (finding_id, cutoff),
        )
        row = await cur.fetchone()
        return int(row[0]) if row else 0

    async def purge_records(self, days: int = 90) -> int:
        """清理超过 N 天的推送记录（S5 红线语义）"""
        cutoff = (_now_utc() - timedelta(days=days)).isoformat()
        cur = await self.conn.execute(
            "DELETE FROM notify_records WHERE created_at < ?", (cutoff,)
        )
        await self.conn.commit()
        return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

    async def stats(self) -> Dict[str, Any]:
        """统计信息"""
        cur = await self.conn.execute("SELECT COUNT(*) FROM notify_channels WHERE enabled = 1")
        channels = (await cur.fetchone())[0]
        cur = await self.conn.execute("SELECT COUNT(*) FROM notify_rules WHERE enabled = 1")
        rules = (await cur.fetchone())[0]
        cur = await self.conn.execute("SELECT COUNT(*) FROM notify_records")
        total = (await cur.fetchone())[0]
        cur = await self.conn.execute(
            "SELECT COUNT(*) FROM notify_records WHERE status = 'sent'"
        )
        sent = (await cur.fetchone())[0]
        cur = await self.conn.execute(
            "SELECT COUNT(*) FROM notify_records WHERE status = 'failed'"
        )
        failed = (await cur.fetchone())[0]
        return {
            "channels": int(channels),
            "rules": int(rules),
            "records_total": int(total),
            "records_sent": int(sent),
            "records_failed": int(failed),
        }

    # ────── 行映射 ──────

    @staticmethod
    def _row_to_channel(row: aiosqlite.Row) -> IMChannel:
        d = dict(row)
        return IMChannel(
            id=d["id"], name=d["name"],
            channel_type=IMChannelType(d["channel_type"]),
            webhook_url=d["webhook_url"],
            secret=d.get("secret") or None,
            enabled=bool(d.get("enabled", 1)),
            timeout_seconds=int(d.get("timeout_seconds", 10)),
            created_at=datetime.fromisoformat(d["created_at"]) if d.get("created_at") else None,
            updated_at=datetime.fromisoformat(d["updated_at"]) if d.get("updated_at") else None,
        )

    @staticmethod
    def _row_to_rule(row: aiosqlite.Row) -> NotifyRule:
        d = dict(row)
        events_raw = d.get("events", "[]")
        try:
            events = [NotifyEvent(e) for e in json.loads(events_raw)]
        except (json.JSONDecodeError, ValueError):
            events = []
        channels_raw = d.get("channels", "[]")
        try:
            channels = json.loads(channels_raw)
        except json.JSONDecodeError:
            channels = []
        rid_pat_raw = d.get("rule_id_patterns", "[]")
        try:
            rid_pat = json.loads(rid_pat_raw)
        except json.JSONDecodeError:
            rid_pat = []
        path_pat_raw = d.get("path_patterns", "[]")
        try:
            path_pat = json.loads(path_pat_raw)
        except json.JSONDecodeError:
            path_pat = []
        return NotifyRule(
            id=d["id"], name=d["name"],
            enabled=bool(d.get("enabled", 1)),
            min_severity=d.get("min_severity", "HIGH"),
            events=events, channels=channels,
            frequency=NotifyFrequency(d.get("frequency", "realtime")),
            rule_id_patterns=rid_pat, path_patterns=path_pat,
            suppress_duplicates_minutes=int(d.get("suppress_duplicates_minutes", 60)),
            created_at=datetime.fromisoformat(d["created_at"]) if d.get("created_at") else None,
            updated_at=datetime.fromisoformat(d["updated_at"]) if d.get("updated_at") else None,
        )

    @staticmethod
    def _row_to_record(row: aiosqlite.Row) -> NotifyRecord:
        d = dict(row)
        event_val = d.get("event")
        try:
            event = NotifyEvent(event_val) if event_val else None
        except ValueError:
            event = None
        status_val = d.get("status")
        try:
            status = NotifyStatus(status_val) if status_val else NotifyStatus.PENDING
        except ValueError:
            status = NotifyStatus.PENDING
        return NotifyRecord(
            id=d["id"],
            channel_id=d.get("channel_id"),
            rule_id=d.get("rule_id"),
            event=event,
            finding_id=d.get("finding_id"),
            status=status,
            title=d.get("title", ""),
            content=d.get("content", ""),
            error_message=d.get("error_message"),
            retry_count=int(d.get("retry_count", 0)),
            created_at=datetime.fromisoformat(d["created_at"]) if d.get("created_at") else None,
            sent_at=datetime.fromisoformat(d["sent_at"]) if d.get("sent_at") else None,
        )


def default_notify_db_path() -> str:
    """默认通知数据库路径"""
    return os.path.join(
        os.path.expanduser("~"), ".xuanjian", "notify.db"
    )


def open_store(db_path: Optional[str] = None) -> NotifyStore:
    """构建 NotifyStore 实例（不连接，由 async with 接管）"""
    return NotifyStore(db_path or default_notify_db_path())
