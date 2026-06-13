"""
SQLite 数据库连接管理

使用 aiosqlite 实现异步数据库操作，支持 WAL 模式
"""

import os
import logging
from typing import Optional

import aiosqlite

logger = logging.getLogger(__name__)

# 数据库 Schema
SCHEMA_SQL = """
-- 项目表
CREATE TABLE IF NOT EXISTS projects (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    path            TEXT NOT NULL UNIQUE,
    language        TEXT DEFAULT 'auto',
    description     TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 扫描历史表
CREATE TABLE IF NOT EXISTS scan_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL UNIQUE,
    project_id      TEXT,
    project_path    TEXT NOT NULL,
    scanner         TEXT NOT NULL,
    language        TEXT,
    total_findings  INTEGER DEFAULT 0,
    duration_seconds REAL DEFAULT 0.0,
    status          TEXT DEFAULT 'completed',
    error_message   TEXT,
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
);

-- 发现(Findings)表
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT,
    scanner         TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    line_start      INTEGER NOT NULL,
    line_end        INTEGER,
    code_snippet    TEXT DEFAULT '',
    message         TEXT NOT NULL,
    category        TEXT,
    language        TEXT,
    fingerprint     TEXT,
    cwe             TEXT,
    owasp           TEXT,
    confidence      REAL DEFAULT 0.0,
    metadata        TEXT DEFAULT '{}',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan_history(scan_id) ON DELETE SET NULL
);

-- 误报标记表
CREATE TABLE IF NOT EXISTS false_positive_marks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      TEXT NOT NULL,
    reason          TEXT NOT NULL,
    marked_by       TEXT DEFAULT 'manual',
    scope           TEXT DEFAULT 'instance',
    confidence      REAL DEFAULT 1.0,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_file_path ON findings(file_path);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_scanner ON findings(scanner);
CREATE INDEX IF NOT EXISTS idx_findings_language ON findings(language);
CREATE INDEX IF NOT EXISTS idx_fp_marks_finding_id ON false_positive_marks(finding_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_project_id ON scan_history(project_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp);
"""


class Database:
    """
    异步 SQLite 数据库连接管理器

    支持 WAL 模式、自动 schema 初始化、上下文管理器用法
    """

    def __init__(self, db_path: str, wal_mode: bool = True):
        """
        Args:
            db_path: 数据库文件路径
            wal_mode: 是否启用 WAL 模式
        """
        self.db_path = os.path.expanduser(db_path)
        self.wal_mode = wal_mode
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        """建立数据库连接"""
        # 确保目录存在
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)

        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row

        # 启用 WAL 模式
        if self.wal_mode:
            await self._conn.execute("PRAGMA journal_mode=WAL")

        # 其他优化
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute("PRAGMA busy_timeout=5000")

        logger.info(f"Connected to database: {self.db_path}")

    async def initialize(self) -> None:
        """初始化 schema（建表、建索引）"""
        if self._conn is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        await self._conn.executescript(SCHEMA_SQL)
        await self._conn.commit()
        logger.info("Database schema initialized")

    async def close(self) -> None:
        """关闭数据库连接"""
        if self._conn:
            await self._conn.close()
            self._conn = None
            logger.info("Database connection closed")

    @property
    def conn(self) -> aiosqlite.Connection:
        """获取底层连接"""
        if self._conn is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._conn

    async def __aenter__(self):
        await self.connect()
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        return False


async def get_database(
    db_path: str = "~/.xuanjian/data.db",
    wal_mode: bool = True,
) -> Database:
    """
    便捷函数：获取已初始化的数据库实例

    用法::

        async with get_database() as db:
            rows = await db.conn.execute("SELECT ...")

    Args:
        db_path: 数据库路径
        wal_mode: WAL 模式

    Returns:
        Database: 已连接并初始化的数据库实例
    """
    database = Database(db_path, wal_mode)
    await database.connect()
    await database.initialize()
    return database
