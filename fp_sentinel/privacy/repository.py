"""
玄鉴 v3.0 — 隐私计算协同审计模块 数据存储层

SQLite (WAL) 持久化，独立于主数据库和知识图谱数据库。
存储：联邦训练记录、规则共享记录、审计日志、协同任务记录。

安全红线：
- S7: 数据库路径固定于 ~/.xuanjian/privacy_audit.db
- S1: 纯本地存储，零网络
- 不包含原始代码、漏洞数据，仅存储脱敏/加密后的元数据
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional

import aiosqlite

logger = logging.getLogger(__name__)


PRIVACY_SCHEMA_SQL = """
-- 联邦训练记录
CREATE TABLE IF NOT EXISTS fed_training_records (
    id                  TEXT PRIMARY KEY,
    task_id             TEXT NOT NULL,
    model_architecture  TEXT NOT NULL,
    total_rounds        INTEGER DEFAULT 0,
    final_accuracy      REAL DEFAULT 0.0,
    final_loss          REAL DEFAULT 0.0,
    total_privacy_loss  REAL DEFAULT 0.0,
    participant_count   INTEGER DEFAULT 0,
    model_hash          TEXT DEFAULT '',
    compliance_passed   INTEGER DEFAULT 1,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    round_results_json  TEXT DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_fed_task_id ON fed_training_records(task_id);
CREATE INDEX IF NOT EXISTS idx_fed_created ON fed_training_records(created_at);

-- 规则共享记录
CREATE TABLE IF NOT EXISTS rule_share_records (
    id                  TEXT PRIMARY KEY,
    rule_id             TEXT NOT NULL,
    rule_name           TEXT NOT NULL,
    category            TEXT NOT NULL,
    cwe                 TEXT,
    severity            TEXT DEFAULT 'MEDIUM',
    scope               TEXT DEFAULT 'team',
    sensitivity         TEXT DEFAULT 'medium',
    source_team_hash    TEXT DEFAULT '',
    signature           TEXT DEFAULT '',
    package_id          TEXT DEFAULT '',
    shared_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_rule_share_sig ON rule_share_records(signature);
CREATE INDEX IF NOT EXISTS idx_rule_share_cat ON rule_share_records(category);
CREATE INDEX IF NOT EXISTS idx_rule_share_pkg ON rule_share_records(package_id);

-- 数据传输审计日志
CREATE TABLE IF NOT EXISTS transfer_audit_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    transfer_type       TEXT NOT NULL,
    source_node         TEXT NOT NULL,
    destination_node    TEXT NOT NULL,
    encryption_verified INTEGER DEFAULT 0,
    plaintext_detected  INTEGER DEFAULT 0,
    data_size_bytes     INTEGER DEFAULT 0,
    compliance_passed   INTEGER DEFAULT 1,
    transfer_timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_type ON transfer_audit_log(transfer_type);
CREATE INDEX IF NOT EXISTS idx_audit_compliance ON transfer_audit_log(compliance_passed);
CREATE INDEX IF NOT EXISTS idx_audit_time ON transfer_audit_log(transfer_timestamp);

-- 协同任务记录
CREATE TABLE IF NOT EXISTS collab_task_records (
    id                      TEXT PRIMARY KEY,
    title                   TEXT NOT NULL,
    description             TEXT DEFAULT '',
    status                  TEXT DEFAULT 'draft',
    creator                 TEXT DEFAULT '',
    visibility              TEXT DEFAULT 'team_team',
    total_findings_count    INTEGER DEFAULT 0,
    aggregated_result_hash  TEXT DEFAULT '',
    team_count              INTEGER DEFAULT 0,
    scan_started_at         TIMESTAMP,
    scan_completed_at       TIMESTAMP,
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    permissions_json        TEXT DEFAULT '[]',
    tags_json               TEXT DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_collab_status ON collab_task_records(status);
CREATE INDEX IF NOT EXISTS idx_collab_created ON collab_task_records(created_at);

-- 合规报告记录
CREATE TABLE IF NOT EXISTS compliance_report_records (
    id                  TEXT PRIMARY KEY,
    overall_passed      INTEGER DEFAULT 0,
    standards_checked_json TEXT DEFAULT '[]',
    passed_count        INTEGER DEFAULT 0,
    failed_count        INTEGER DEFAULT 0,
    risk_level          TEXT DEFAULT 'low',
    summary             TEXT DEFAULT '',
    report_hash         TEXT DEFAULT '',
    generated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_compliance_passed ON compliance_report_records(overall_passed);
CREATE INDEX IF NOT EXISTS idx_compliance_time ON compliance_report_records(generated_at);
"""


def _gen_id() -> str:
    return str(uuid.uuid4())


class PrivacyRepository:
    """隐私计算审计数据库 —— 单 SQLite 文件 + aiosqlite + WAL。"""

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
        logger.info("Privacy repository connected: %s", self.db_path)

    async def initialize(self) -> None:
        if self._conn is None:
            raise RuntimeError("not connected")
        await self._conn.executescript(PRIVACY_SCHEMA_SQL)
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

    async def __aexit__(self, exc_type, exc_val, exc_tb):  # pragma: no cover — exercised via async with
        await self.close()
        return False

    # ────── 联邦训练记录 CRUD ──────
    async def save_training_record(
        self,
        task_id: str,
        model_architecture: str,
        total_rounds: int,
        final_accuracy: float,
        final_loss: float,
        total_privacy_loss: float,
        participant_count: int,
        model_hash: str,
        compliance_passed: bool,
        round_results: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        record_id = _gen_id()
        await self.conn.execute(
            """INSERT INTO fed_training_records
               (id, task_id, model_architecture, total_rounds, final_accuracy,
                final_loss, total_privacy_loss, participant_count, model_hash,
                compliance_passed, round_results_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record_id, task_id, model_architecture, total_rounds,
                final_accuracy, final_loss, total_privacy_loss,
                participant_count, model_hash,
                1 if compliance_passed else 0,
                json.dumps(round_results or []),
            ),
        )
        await self.conn.commit()
        return record_id

    async def get_training_record(self, record_id: str) -> Optional[Dict[str, Any]]:
        cur = await self.conn.execute(
            "SELECT * FROM fed_training_records WHERE id = ?", (record_id,)
        )
        row = await cur.fetchone()
        if not row:
            return None
        d = dict(row)
        d["compliance_passed"] = bool(d.get("compliance_passed"))
        d["round_results"] = json.loads(d.pop("round_results_json", "[]") or "[]")
        return d

    async def list_training_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        cur = await self.conn.execute(
            "SELECT * FROM fed_training_records ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        rows = await cur.fetchall()
        results = []
        for row in rows:
            d = dict(row)
            d["compliance_passed"] = bool(d.get("compliance_passed"))
            results.append(d)
        return results

    # ────── 规则共享记录 CRUD ──────
    async def save_rule_share(
        self,
        rule_id: str,
        rule_name: str,
        category: str,
        signature: str,
        scope: str = "team",
        sensitivity: str = "medium",
        cwe: Optional[str] = None,
        severity: str = "MEDIUM",
        source_team_hash: str = "",
        package_id: str = "",
    ) -> str:
        record_id = _gen_id()
        await self.conn.execute(
            """INSERT INTO rule_share_records
               (id, rule_id, rule_name, category, cwe, severity, scope,
                sensitivity, source_team_hash, signature, package_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record_id, rule_id, rule_name, category, cwe or "",
                severity, scope, sensitivity, source_team_hash,
                signature, package_id,
            ),
        )
        await self.conn.commit()
        return record_id

    async def list_rule_shares(
        self, category: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        if category:
            cur = await self.conn.execute(
                "SELECT * FROM rule_share_records WHERE category = ? ORDER BY shared_at DESC LIMIT ?",
                (category, limit),
            )
        else:
            cur = await self.conn.execute(
                "SELECT * FROM rule_share_records ORDER BY shared_at DESC LIMIT ?",
                (limit,),
            )
        return [dict(r) for r in await cur.fetchall()]

    # ────── 审计日志 CRUD ──────
    async def save_audit_log(
        self,
        transfer_type: str,
        source_node: str,
        destination_node: str,
        encryption_verified: bool,
        plaintext_detected: bool,
        data_size_bytes: int,
        compliance_passed: bool,
    ) -> int:
        cur = await self.conn.execute(
            """INSERT INTO transfer_audit_log
               (transfer_type, source_node, destination_node,
                encryption_verified, plaintext_detected,
                data_size_bytes, compliance_passed)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                transfer_type, source_node, destination_node,
                1 if encryption_verified else 0,
                1 if plaintext_detected else 0,
                data_size_bytes,
                1 if compliance_passed else 0,
            ),
        )
        await self.conn.commit()
        return cur.lastrowid or 0

    async def list_audit_logs(
        self, compliance_filter: Optional[bool] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        if compliance_filter is not None:
            cur = await self.conn.execute(
                "SELECT * FROM transfer_audit_log WHERE compliance_passed = ? ORDER BY transfer_timestamp DESC LIMIT ?",
                (1 if compliance_filter else 0, limit),
            )
        else:
            cur = await self.conn.execute(
                "SELECT * FROM transfer_audit_log ORDER BY transfer_timestamp DESC LIMIT ?",
                (limit,),
            )
        rows = await cur.fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["encryption_verified"] = bool(d.get("encryption_verified"))
            d["plaintext_detected"] = bool(d.get("plaintext_detected"))
            d["compliance_passed"] = bool(d.get("compliance_passed"))
            results.append(d)
        return results

    async def get_audit_stats(self) -> Dict[str, Any]:
        cur = await self.conn.execute("SELECT COUNT(*) FROM transfer_audit_log")
        total = (await cur.fetchone())[0]
        cur = await self.conn.execute(
            "SELECT COUNT(*) FROM transfer_audit_log WHERE compliance_passed = 1"
        )
        passed = (await cur.fetchone())[0]
        cur = await self.conn.execute(
            "SELECT COUNT(*) FROM transfer_audit_log WHERE plaintext_detected = 1"
        )
        plaintext = (await cur.fetchone())[0]
        return {
            "total_transfers": int(total),
            "compliant": int(passed),
            "non_compliant": int(total - passed),
            "plaintext_detected_count": int(plaintext),
        }

    # ────── 协同任务 CRUD ──────
    async def save_collab_task(
        self,
        task_id: str,
        title: str,
        description: str,
        status: str,
        creator: str,
        visibility: str,
        total_findings: int,
        result_hash: str,
        team_count: int,
        permissions: Optional[List[Dict[str, Any]]] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        await self.conn.execute(
            """INSERT INTO collab_task_records
               (id, title, description, status, creator, visibility,
                total_findings_count, aggregated_result_hash, team_count,
                permissions_json, tags_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task_id, title, description, status, creator, visibility,
                total_findings, result_hash, team_count,
                json.dumps(permissions or []),
                json.dumps(tags or []),
            ),
        )
        await self.conn.commit()

    async def update_collab_task_status(
        self, task_id: str, new_status: str, findings_count: Optional[int] = None
    ) -> None:
        if findings_count is not None:
            await self.conn.execute(
                "UPDATE collab_task_records SET status = ?, total_findings_count = ? WHERE id = ?",
                (new_status, findings_count, task_id),
            )
        else:
            await self.conn.execute(
                "UPDATE collab_task_records SET status = ? WHERE id = ?",
                (new_status, task_id),
            )
        await self.conn.commit()

    async def list_collab_tasks(
        self, status_filter: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        if status_filter:
            cur = await self.conn.execute(
                "SELECT * FROM collab_task_records WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status_filter, limit),
            )
        else:
            cur = await self.conn.execute(
                "SELECT * FROM collab_task_records ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        rows = await cur.fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["permissions"] = json.loads(d.pop("permissions_json", "[]") or "[]")
            d["tags"] = json.loads(d.pop("tags_json", "[]") or "[]")
            results.append(d)
        return results

    # ────── 合规报告记录 ──────
    async def save_compliance_report(
        self,
        overall_passed: bool,
        standards: List[str],
        passed_count: int,
        failed_count: int,
        risk_level: str,
        summary: str,
        report_hash: str,
    ) -> str:
        record_id = _gen_id()
        await self.conn.execute(
            """INSERT INTO compliance_report_records
               (id, overall_passed, standards_checked_json, passed_count,
                failed_count, risk_level, summary, report_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record_id,
                1 if overall_passed else 0,
                json.dumps(standards),
                passed_count, failed_count,
                risk_level, summary, report_hash,
            ),
        )
        await self.conn.commit()
        return record_id

    async def list_compliance_reports(
        self, passed_filter: Optional[bool] = None, limit: int = 20
    ) -> List[Dict[str, Any]]:
        if passed_filter is not None:
            cur = await self.conn.execute(
                "SELECT * FROM compliance_report_records WHERE overall_passed = ? ORDER BY generated_at DESC LIMIT ?",
                (1 if passed_filter else 0, limit),
            )
        else:
            cur = await self.conn.execute(
                "SELECT * FROM compliance_report_records ORDER BY generated_at DESC LIMIT ?",
                (limit,),
            )
        rows = await cur.fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["overall_passed"] = bool(d.get("overall_passed"))
            d["standards_checked"] = json.loads(d.pop("standards_checked_json", "[]") or "[]")
            results.append(d)
        return results

    # ────── 统计 ──────
    async def stats(self) -> Dict[str, Any]:
        cur = await self.conn.execute("SELECT COUNT(*) FROM fed_training_records")
        fed_n = (await cur.fetchone())[0]
        cur = await self.conn.execute("SELECT COUNT(*) FROM rule_share_records")
        rule_n = (await cur.fetchone())[0]
        cur = await self.conn.execute("SELECT COUNT(*) FROM transfer_audit_log")
        audit_n = (await cur.fetchone())[0]
        cur = await self.conn.execute("SELECT COUNT(*) FROM collab_task_records")
        collab_n = (await cur.fetchone())[0]
        cur = await self.conn.execute("SELECT COUNT(*) FROM compliance_report_records")
        compliance_n = (await cur.fetchone())[0]
        return {
            "federated_trainings": int(fed_n),
            "rule_shares": int(rule_n),
            "audit_log_entries": int(audit_n),
            "collaborative_tasks": int(collab_n),
            "compliance_reports": int(compliance_n),
        }


def default_privacy_db_path() -> str:
    """默认隐私审计数据库路径：~/.xuanjian/privacy_audit.db"""
    return os.path.join(
        os.path.expanduser("~"), ".xuanjian", "privacy_audit.db"
    )


def open_privacy_repo(db_path: Optional[str] = None) -> PrivacyRepository:
    """构建 PrivacyRepository 实例（不连接）。"""
    return PrivacyRepository(db_path or default_privacy_db_path())
