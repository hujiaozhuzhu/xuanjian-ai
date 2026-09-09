"""
玄鉴 v3.0 — 用户反馈存储引擎 (Feedback Store)

负责用户反馈数据的持久化存储，提供 CRUD 操作
版本: 3.0.0
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiosqlite

from .models import (
    FeedbackSource,
    FeedbackType,
    UserFeedback,
)

logger = logging.getLogger(__name__)


# ─────────────────────── 表结构定义 ───────────────────────

FEEDBACK_SCHEMA_SQL = """
-- 用户反馈表
CREATE TABLE IF NOT EXISTS fp_feedback (
    id              TEXT PRIMARY KEY,
    finding_id      TEXT NOT NULL,
    project_id      TEXT,
    feedback_type   TEXT NOT NULL,
    source          TEXT DEFAULT 'manual',
    confidence      REAL DEFAULT 1.0,
    reason          TEXT,
    marker          TEXT,
    rule_id         TEXT,
    scanner         TEXT,
    fingerprint     TEXT,
    code_snippet    TEXT,
    file_path       TEXT,
    severity        TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 优化记录表
CREATE TABLE IF NOT EXISTS fp_optimization_log (
    id              TEXT PRIMARY KEY,
    feedback_count  INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'pending',
    layer           TEXT,
    rule_id         TEXT,
    adjustment_type TEXT,
    old_value       REAL,
    new_value       REAL,
    fp_rate_before  REAL,
    fp_rate_after   REAL,
    description     TEXT,
    applied_at      TIMESTAMP,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 代码风格画像表
CREATE TABLE IF NOT EXISTS fp_code_style (
    project_id      TEXT PRIMARY KEY,
    common_patterns TEXT DEFAULT '{}',
    framework_hints TEXT DEFAULT '[]',
    package_prefixes TEXT DEFAULT '[]',
    security_patterns TEXT DEFAULT '{}',
    fp_prone_rules  TEXT DEFAULT '{}',
    total_scans     INTEGER DEFAULT 0,
    total_findings  INTEGER DEFAULT 0,
    total_feedbacks INTEGER DEFAULT 0,
    current_fp_rate REAL DEFAULT 0.0,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_feedback_finding_id ON fp_feedback(finding_id);
CREATE INDEX IF NOT EXISTS idx_feedback_project_id ON fp_feedback(project_id);
CREATE INDEX IF NOT EXISTS idx_feedback_type ON fp_feedback(feedback_type);
CREATE INDEX IF NOT EXISTS idx_feedback_fingerprint ON fp_feedback(fingerprint);
CREATE INDEX IF NOT EXISTS idx_feedback_rule_id ON fp_feedback(rule_id);
CREATE INDEX IF NOT EXISTS idx_feedback_created_at ON fp_feedback(created_at);
CREATE INDEX IF NOT EXISTS idx_opt_log_status ON fp_optimization_log(status);
"""


# ─────────────────────── 反馈存储引擎 ───────────────────────

class FeedbackStore:
    """
    用户反馈数据存储引擎

    提供反馈记录的增删改查、批量导入、统计分析等功能
    基于 aiosqlite 异步操作 SQLite 数据库

    使用方式:
        store = FeedbackStore(db_path="./data/fp_optimize.db")
        await store.initialize()
        feedback = await store.add_feedback(finding_id="xxx", feedback_type=FeedbackType.FALSE_POSITIVE)
        stats = await store.get_statistics(project_id="xxx")
    """

    def __init__(self, db_path: str = "~/.xuanjian/fp_optimize.db"):
        """
        Args:
            db_path: SQLite 数据库路径
        """
        import os
        self.db_path = os.path.expanduser(os.path.expandvars(db_path))
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        """建立数据库连接"""
        import os
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute("PRAGMA busy_timeout=5000")

    async def initialize(self) -> None:
        """初始化数据库表结构"""
        if self._conn is None:
            await self.connect()
        await self._conn.executescript(FEEDBACK_SCHEMA_SQL)
        await self._conn.commit()
        logger.info("FP optimize database initialized at %s", self.db_path)

    async def close(self) -> None:
        """关闭数据库连接"""
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def __aenter__(self):
        await self.connect()
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        return False

    @property
    def conn(self) -> aiosqlite.Connection:
        """获取底层连接"""
        if self._conn is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._conn

    # ─────────────── 反馈 CRUD ───────────────

    async def add_feedback(
        self,
        finding_id: str,
        feedback_type: FeedbackType | str,
        project_id: Optional[str] = None,
        source: FeedbackSource | str = FeedbackSource.MANUAL,
        confidence: float = 1.0,
        reason: Optional[str] = None,
        marker: Optional[str] = None,
        rule_id: Optional[str] = None,
        scanner: Optional[str] = None,
        fingerprint: Optional[str] = None,
        code_snippet: Optional[str] = None,
        file_path: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> UserFeedback:
        """
        添加一条用户反馈

        Args:
            finding_id: 关联的发现ID
            feedback_type: 反馈类型 (false_positive/true_positive/unsure)
            project_id: 项目ID
            source: 反馈来源
            confidence: 置信度 (0-1)
            reason: 反馈原因
            marker: 标记人
            rule_id: 规则ID
            scanner: 扫描工具
            fingerprint: 漏洞指纹
            code_snippet: 代码片段
            file_path: 文件路径
            severity: 严重程度

        Returns:
            UserFeedback 创建的反馈记录
        """
        feedback_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        # 标准化枚举值
        if isinstance(feedback_type, FeedbackType):
            feedback_type_str = feedback_type.value
        else:
            feedback_type_str = str(feedback_type)

        if isinstance(source, FeedbackSource):
            source_str = source.value
        else:
            source_str = str(source)

        await self.conn.execute(
            """INSERT INTO fp_feedback
               (id, finding_id, project_id, feedback_type, source, confidence,
                reason, marker, rule_id, scanner, fingerprint, code_snippet,
                file_path, severity, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                feedback_id, finding_id, project_id, feedback_type_str,
                source_str, confidence, reason, marker, rule_id, scanner,
                fingerprint, code_snippet, file_path, severity,
                now.isoformat(),
            ),
        )
        await self.conn.commit()

        return UserFeedback(
            id=feedback_id,
            finding_id=finding_id,
            project_id=project_id,
            feedback_type=FeedbackType(feedback_type_str),
            source=FeedbackSource(source_str),
            confidence=confidence,
            reason=reason,
            marker=marker,
            rule_id=rule_id,
            scanner=scanner,
            fingerprint=fingerprint,
            code_snippet=code_snippet,
            file_path=file_path,
            severity=severity,
            created_at=now,
        )

    async def batch_add_feedbacks(
        self,
        feedbacks: List[Dict[str, Any]],
    ) -> int:
        """
        批量添加反馈

        Args:
            feedbacks: 反馈数据字典列表

        Returns:
            成功添加的数量
        """
        now = datetime.now(timezone.utc).isoformat()
        rows = []
        for fb in feedbacks:
            fid = str(uuid.uuid4())
            ft = fb.get("feedback_type", "unsure")
            if isinstance(ft, FeedbackType):
                ft = ft.value
            src = fb.get("source", "manual")
            if isinstance(src, FeedbackSource):
                src = src.value
            rows.append((
                fid,
                fb.get("finding_id", ""),
                fb.get("project_id"),
                ft,
                src,
                fb.get("confidence", 1.0),
                fb.get("reason"),
                fb.get("marker"),
                fb.get("rule_id"),
                fb.get("scanner"),
                fb.get("fingerprint"),
                fb.get("code_snippet"),
                fb.get("file_path"),
                fb.get("severity"),
                now,
            ))

        await self.conn.executemany(
            """INSERT INTO fp_feedback
               (id, finding_id, project_id, feedback_type, source, confidence,
                reason, marker, rule_id, scanner, fingerprint, code_snippet,
                file_path, severity, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        await self.conn.commit()
        return len(rows)

    async def get_feedback(self, feedback_id: str) -> Optional[UserFeedback]:
        """按ID获取反馈记录"""
        cursor = await self.conn.execute(
            "SELECT * FROM fp_feedback WHERE id = ?", (feedback_id,)
        )
        row = await cursor.fetchone()
        return self._row_to_feedback(row) if row else None

    async def list_feedbacks(
        self,
        project_id: Optional[str] = None,
        feedback_type: Optional[str] = None,
        fingerprint: Optional[str] = None,
        rule_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[UserFeedback]:
        """按条件查询反馈列表"""
        clauses = []
        params: list = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        if feedback_type:
            clauses.append("feedback_type = ?")
            params.append(feedback_type)
        if fingerprint:
            clauses.append("fingerprint = ?")
            params.append(fingerprint)
        if rule_id:
            clauses.append("rule_id = ?")
            params.append(rule_id)

        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        query = f"SELECT * FROM fp_feedback{where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = await self.conn.execute(query, params)
        rows = await cursor.fetchall()
        return [self._row_to_feedback(r) for r in rows]

    async def get_feedback_count(
        self,
        project_id: Optional[str] = None,
        feedback_type: Optional[str] = None,
    ) -> int:
        """统计反馈数量"""
        clauses = []
        params: list = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        if feedback_type:
            clauses.append("feedback_type = ?")
            params.append(feedback_type)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        cursor = await self.conn.execute(
            f"SELECT COUNT(*) FROM fp_feedback{where}", params
        )
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def get_fp_fingerprints(
        self,
        project_id: Optional[str] = None,
    ) -> List[str]:
        """获取已标记为误报的指纹列表"""
        clauses = ["feedback_type = 'false_positive'"]
        params: list = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        where = " WHERE " + " AND ".join(clauses)
        cursor = await self.conn.execute(
            f"SELECT DISTINCT fingerprint FROM fp_feedback{where} AND fingerprint IS NOT NULL",
            params,
        )
        rows = await cursor.fetchall()
        return [row["fingerprint"] for row in rows]

    async def get_fp_prone_rules(
        self,
        project_id: Optional[str] = None,
        min_samples: int = 3,
    ) -> Dict[str, float]:
        """
        获取容易误报的规则及其概率

        Args:
            project_id: 项目ID (None 表示全部)
            min_samples: 最小样本量要求

        Returns:
            规则ID -> 误报概率 (0-1) 的字典
        """
        clauses = []
        params: list = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""

        # 统计各规则的误报率和总反馈数
        clauses = ["rule_id IS NOT NULL"]
        query_params: list = []
        if project_id:
            clauses.append("project_id = ?")
            query_params.append(project_id)
        where = " WHERE " + " AND ".join(clauses)

        cursor = await self.conn.execute(
            f"""SELECT rule_id,
                       COUNT(*) as total,
                       SUM(CASE WHEN feedback_type = 'false_positive' THEN 1 ELSE 0 END) as fp_count
                FROM fp_feedback{where}
                GROUP BY rule_id
                HAVING COUNT(*) >= ?""",
            query_params + [min_samples],
        )
        rows = await cursor.fetchall()

        result = {}
        for row in rows:
            rule_id = row["rule_id"]
            total = row["total"]
            fp_count = row["fp_count"]
            if total > 0 and rule_id:
                result[rule_id] = round(fp_count / total, 4)

        return result

    async def delete_feedback(self, feedback_id: str) -> bool:
        """删除反馈记录"""
        cursor = await self.conn.execute(
            "DELETE FROM fp_feedback WHERE id = ?", (feedback_id,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    # ─────────────── 优化记录 CRUD ───────────────

    async def add_optimization_record(
        self,
        feedback_count: int,
        status: str = "pending",
        layer: Optional[str] = None,
        rule_id: Optional[str] = None,
        adjustment_type: Optional[str] = None,
        old_value: Optional[float] = None,
        new_value: Optional[float] = None,
        fp_rate_before: Optional[float] = None,
        fp_rate_after: Optional[float] = None,
        description: Optional[str] = None,
    ) -> str:
        """添加优化记录"""
        opt_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        await self.conn.execute(
            """INSERT INTO fp_optimization_log
               (id, feedback_count, status, layer, rule_id, adjustment_type,
                old_value, new_value, fp_rate_before, fp_rate_after,
                description, applied_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                opt_id, feedback_count, status, layer, rule_id,
                adjustment_type, old_value, new_value,
                fp_rate_before, fp_rate_after, description,
                now if status == "applied" else None,
                now,
            ),
        )
        await self.conn.commit()
        return opt_id

    async def update_optimization_status(
        self,
        opt_id: str,
        status: str,
        applied_at: Optional[datetime] = None,
    ) -> bool:
        """更新优化记录状态"""
        if applied_at is None and status == "applied":
            applied_at = datetime.now(timezone.utc)
        cursor = await self.conn.execute(
            """UPDATE fp_optimization_log
               SET status = ?, applied_at = ?
               WHERE id = ?""",
            (status, applied_at.isoformat() if applied_at else None, opt_id),
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def list_optimizations(
        self,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """列出优化记录"""
        where = " WHERE status = ?" if status else ""
        params: list = [status] if status else []
        params.extend([limit, offset])
        cursor = await self.conn.execute(
            f"SELECT * FROM fp_optimization_log{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    # ─────────────── 代码风格画像 CRUD ───────────────

    async def save_code_style(self, style_data: Dict[str, Any]) -> str:
        """保存或更新代码风格画像"""
        project_id = style_data.get("project_id", "")
        now = datetime.now(timezone.utc).isoformat()

        # 序列化复杂字段
        common_patterns = json.dumps(style_data.get("common_patterns", {}))
        framework_hints = json.dumps(style_data.get("framework_hints", []))
        package_prefixes = json.dumps(style_data.get("package_prefixes", []))
        security_patterns = json.dumps(style_data.get("security_patterns", {}))
        fp_prone_rules = json.dumps(style_data.get("fp_prone_rules", {}))

        await self.conn.execute(
            """INSERT OR REPLACE INTO fp_code_style
               (project_id, common_patterns, framework_hints, package_prefixes,
                security_patterns, fp_prone_rules, total_scans, total_findings,
                total_feedbacks, current_fp_rate, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                project_id, common_patterns, framework_hints, package_prefixes,
                security_patterns, fp_prone_rules,
                style_data.get("total_scans", 0),
                style_data.get("total_findings", 0),
                style_data.get("total_feedbacks", 0),
                style_data.get("current_fp_rate", 0.0),
                now,
            ),
        )
        await self.conn.commit()
        return project_id

    async def get_code_style(self, project_id: str) -> Optional[Dict[str, Any]]:
        """获取代码风格画像"""
        cursor = await self.conn.execute(
            "SELECT * FROM fp_code_style WHERE project_id = ?", (project_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None

        d = dict(row)
        # 反序列化复杂字段
        for field in ("common_patterns", "security_patterns", "fp_prone_rules"):
            if isinstance(d.get(field), str):
                try:
                    d[field] = json.loads(d[field])
                except json.JSONDecodeError:
                    d[field] = {}
        for field in ("framework_hints", "package_prefixes"):
            if isinstance(d.get(field), str):
                try:
                    d[field] = json.loads(d[field])
                except json.JSONDecodeError:
                    d[field] = []
        return d

    # ─────────────── 统计分析 ───────────────

    async def get_feedback_type_distribution(
        self,
        project_id: Optional[str] = None,
    ) -> Dict[str, int]:
        """按反馈类型统计分布"""
        where = " WHERE project_id = ?" if project_id else ""
        params = [project_id] if project_id else []
        cursor = await self.conn.execute(
            f"""SELECT feedback_type, COUNT(*) as cnt
                FROM fp_feedback{where}
                GROUP BY feedback_type""",
            params,
        )
        rows = await cursor.fetchall()
        return {row["feedback_type"]: row["cnt"] for row in rows}

    async def get_top_fp_rules(
        self,
        project_id: Optional[str] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """获取高频误报规则"""
        clauses = ["rule_id IS NOT NULL"]
        params: list = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        params.append(limit)
        where = " WHERE " + " AND ".join(clauses)
        cursor = await self.conn.execute(
            f"""SELECT rule_id,
                       COUNT(*) as total,
                       SUM(CASE WHEN feedback_type = 'false_positive' THEN 1 ELSE 0 END) as fp_count,
                       ROUND(
                           100.0 * SUM(CASE WHEN feedback_type = 'false_positive' THEN 1 ELSE 0 END) / COUNT(*),
                           1
                       ) as fp_pct
                FROM fp_feedback{where}
                GROUP BY rule_id
                HAVING fp_count > 0
                ORDER BY fp_count DESC
                LIMIT ?""",
            params,
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_top_fp_files(
        self,
        project_id: Optional[str] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """获取高频误报文件"""
        clauses = ["file_path IS NOT NULL AND file_path != ''"]
        params: list = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        params.append(limit)
        where = " WHERE " + " AND ".join(clauses)
        cursor = await self.conn.execute(
            f"""SELECT file_path,
                       COUNT(*) as total,
                       SUM(CASE WHEN feedback_type = 'false_positive' THEN 1 ELSE 0 END) as fp_count
                FROM fp_feedback{where}
                GROUP BY file_path
                HAVING fp_count > 0
                ORDER BY fp_count DESC
                LIMIT ?""",
            params,
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_daily_fp_rate(
        self,
        project_id: Optional[str] = None,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """获取每日误报率趋势"""
        clauses = []
        params: list = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        # 时间过滤：使用负的 days 表示过去的 N 天
        clauses.append("created_at >= datetime('now', ?)")
        params.append(f"-{days} days")

        where = " WHERE " + " AND ".join(clauses)
        cursor = await self.conn.execute(
            f"""SELECT
                    date(created_at) as day,
                    COUNT(*) as total,
                    SUM(CASE WHEN feedback_type = 'false_positive' THEN 1 ELSE 0 END) as fp_count,
                    SUM(CASE WHEN feedback_type = 'true_positive' THEN 1 ELSE 0 END) as tp_count
                FROM fp_feedback{where}
                GROUP BY date(created_at)
                ORDER BY day ASC""",
            params,
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    # ─────────────── 辅助方法 ───────────────

    @staticmethod
    def _row_to_feedback(row: aiosqlite.Row) -> UserFeedback:
        """将数据库行转为 UserFeedback"""
        d = dict(row)
        # 处理 datetime
        if d.get("created_at") and isinstance(d["created_at"], str):
            try:
                d["created_at"] = datetime.fromisoformat(d["created_at"])
            except ValueError:
                d["created_at"] = None
        # 处理枚举
        d["feedback_type"] = FeedbackType(d.get("feedback_type", "unsure"))
        d["source"] = FeedbackSource(d.get("source", "manual"))
        return UserFeedback(**d)
