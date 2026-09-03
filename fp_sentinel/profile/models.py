"""
开发者画像（核三）数据模型与画像库表

安全红线声明（对应迭代计划 S3/S6）：
- 画像数据仅存储于本地 SQLite，禁止任何网络上传；
- 开发者身份默认 SHA256 别名化，不存明文 email；
- display_name 为可选本地弱加密存储（密钥与数据库同目录，**本地保护非强加密**）；
- 画像"删除"仅指删除画像库中该开发者数据，不触碰用户代码与 findings；
- 本模块不提供、也不得实现任何"画像评分导出为绩效格式"的接口。
"""

import base64
import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ..database.connection import Database

logger = logging.getLogger(__name__)

UNKNOWN_ALIAS = "unknown"
DEFAULT_MAX_ATTRIBUTION_RECORDS = 5000


# ─────────────────────── 画像库新增表（只增不改） ───────────────────────

# 注：finding_status 为修复状态记录表（仅新增、不改动既有 findings 表），
# 用于"修复速度"维度（finding 首次发现 → mark 为 fixed 的时间差）。
PROFILE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS developer_alias (
    id                      TEXT PRIMARY KEY,
    alias_hash              TEXT NOT NULL UNIQUE,
    display_name_encrypted  TEXT,
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS profile_snapshot (
    id              TEXT PRIMARY KEY,
    alias_hash      TEXT NOT NULL,
    period          TEXT NOT NULL,
    metrics_json    TEXT NOT NULL DEFAULT '{}',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_attribution (
    id                      TEXT PRIMARY KEY,
    finding_fingerprint     TEXT NOT NULL,
    alias_hash              TEXT NOT NULL,
    file                    TEXT,
    committed_at            TEXT,
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS finding_status (
    id              TEXT PRIMARY KEY,
    fingerprint     TEXT NOT NULL UNIQUE,
    status          TEXT NOT NULL DEFAULT 'fixed',
    marked_at       TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_attribution_fp ON scan_attribution(finding_fingerprint);
CREATE INDEX IF NOT EXISTS idx_scan_attribution_alias ON scan_attribution(alias_hash);
CREATE INDEX IF NOT EXISTS idx_profile_snapshot_alias ON profile_snapshot(alias_hash, period);
CREATE INDEX IF NOT EXISTS idx_finding_status_fp ON finding_status(fingerprint);
"""


async def ensure_profile_tables(db: Database) -> None:
    """在既有 Database 上创建画像库新增表（幂等，只增不改）"""
    await db.conn.executescript(PROFILE_SCHEMA_SQL)
    await db.conn.commit()


# ─────────────────────── pydantic 模型 ───────────────────────

class AttributionRecord(BaseModel):
    """单条归因记录（fingerprint → 别名）"""
    finding_fingerprint: str = Field(..., description="Finding 指纹")
    alias_hash: str = Field(..., description="作者别名（SHA256 摘要，前 16 位）")
    file: Optional[str] = Field(None, description="文件相对路径")
    line: Optional[int] = Field(None, description="归因命中的行号")
    committed_at: Optional[str] = Field(None, description="该行提交时间(ISO)")
    created_at: Optional[str] = Field(None, description="入库时间(ISO)")


class DeveloperProfile(BaseModel):
    """开发者画像（六维度）"""
    alias: str = Field(..., description="别名（SHA256 摘要或 unknown）")
    display_name: Optional[str] = Field(None, description="显示名（仅 reveal 模式解密展示）")
    period: Optional[str] = Field(None, description="统计周期（如 2026-08）")
    total_findings: int = Field(0, description="周期内发现总数")
    scans_contributed: int = Field(0, description="贡献过的扫描日期数")
    vuln_counts_by_cwe: Dict[str, int] = Field(default_factory=dict, description="CWE 分布")
    cwe_top3: List[str] = Field(default_factory=list, description="CWE 偏好 top3")
    avg_fix_hours: Optional[float] = Field(None, description="平均修复时长(小时)，无数据置空不猜")
    fix_pass_rate: Optional[float] = Field(None, description="修复质量(30 天内无复发比例)，无数据置空")
    repeat_rate: float = Field(0.0, description="复犯率（同 fingerprint 重复占比）")
    knowledge_gaps: List[str] = Field(default_factory=list, description="知识盲区（占比>30% 的 CWE）")
    trend: float = Field(0.0, description="成长趋势（月度发现数线性斜率，负值=改善）")


class TeamProfile(BaseModel):
    """团队画像"""
    period: str = Field(..., description="统计周期（如 2026-08 或 all）")
    members: List[DeveloperProfile] = Field(default_factory=list, description="成员画像（匿名）")
    health_score: float = Field(0.0, description="团队健康度 0-100")
    metrics: Dict[str, Any] = Field(default_factory=dict, description="团队四指标与分项得分")
    findings: int = Field(0, description="周期内发现总数")
    coverage: float = Field(0.0, description="归因覆盖率 0-1")
    kloc: Optional[float] = Field(None, description="千行代码数（用于漏洞密度）")


class FindingStatus(BaseModel):
    """Finding 修复状态记录"""
    fingerprint: str = Field(..., description="Finding 指纹")
    status: str = Field("fixed", description="状态（当前仅 fixed）")
    marked_at: Optional[datetime] = Field(None, description="标记时间")


# ─────────────────────── 别名化（S6） ───────────────────────

_ALIAS_SALT = "fp-sentinel:alias:v1"


def alias_hash(identifier: str) -> str:
    """将作者 email/姓名映射为确定性匿名别名（SHA256 前 16 位十六进制）"""
    normalized = (identifier or "").strip().lower()
    return hashlib.sha256((_ALIAS_SALT + normalized).encode("utf-8")).hexdigest()[:16]


# ─────────────────────── display_name 本地弱加密 ───────────────────────

def _keystream(key: bytes, length: int) -> bytes:
    """SHA256 计数器模式 keystream（本地弱加密，非强加密）"""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(key + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(out[:length])


def get_profile_key(db_path: str) -> bytes:
    """获取（必要时生成）本地画像密钥；密钥文件与数据库同目录"""
    key_file = os.path.join(os.path.dirname(os.path.abspath(db_path)), "profile.key")
    if os.path.exists(key_file):
        with open(key_file, "r", encoding="utf-8") as f:
            return bytes.fromhex(f.read().strip())
    key = os.urandom(32)
    with open(key_file, "w", encoding="utf-8") as f:
        f.write(key.hex())
    return key


def encrypt_name(name: str, key: bytes) -> str:
    data = name.encode("utf-8")
    ks = _keystream(key, len(data))
    return base64.b64encode(bytes(a ^ b for a, b in zip(data, ks))).decode("ascii")


def decrypt_name(blob: Optional[str], key: bytes) -> Optional[str]:
    if not blob:
        return None
    try:
        data = base64.b64decode(blob.encode("ascii"))
        ks = _keystream(key, len(data))
        return bytes(a ^ b for a, b in zip(data, ks)).decode("utf-8")
    except Exception:
        return None


# ─────────────────────── ProfileRepo ───────────────────────

def _gen_id() -> str:
    return str(uuid.uuid4())


class ProfileRepo:
    """画像库仓库（developer_alias / profile_snapshot / scan_attribution / finding_status）"""

    def __init__(self, db: Database):
        self.db = db

    # ── developer_alias ──
    async def upsert_alias(self, alias_hash_: str, display_name_encrypted: Optional[str] = None) -> None:
        await self.db.conn.execute(
            """INSERT INTO developer_alias (id, alias_hash, display_name_encrypted)
               VALUES (?, ?, ?)
               ON CONFLICT(alias_hash) DO UPDATE SET
                 display_name_encrypted = COALESCE(excluded.display_name_encrypted, display_name_encrypted)""",
            (_gen_id(), alias_hash_, display_name_encrypted),
        )
        await self.db.conn.commit()

    async def get_alias(self, alias_hash_: str) -> Optional[Dict[str, Any]]:
        cursor = await self.db.conn.execute(
            "SELECT * FROM developer_alias WHERE alias_hash = ?", (alias_hash_,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def list_alias_hashes(self) -> List[str]:
        cursor = await self.db.conn.execute("SELECT alias_hash FROM developer_alias")
        rows = await cursor.fetchall()
        return [r["alias_hash"] for r in rows]

    # ── scan_attribution ──
    async def save_attribution(self, record: AttributionRecord) -> None:
        await self.db.conn.execute(
            """INSERT INTO scan_attribution
               (id, finding_fingerprint, alias_hash, file, committed_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                _gen_id(), record.finding_fingerprint, record.alias_hash,
                record.file, record.committed_at,
                (record.created_at or datetime.now(timezone.utc)).isoformat(),
            ),
        )
        await self.db.conn.commit()

    async def save_attributions(self, records: List[AttributionRecord]) -> int:
        rows = []
        for r in records:
            rows.append((
                _gen_id(), r.finding_fingerprint, r.alias_hash,
                r.file, r.committed_at,
                (r.created_at or datetime.now(timezone.utc)).isoformat(),
            ))
        if not rows:
            return 0
        await self.db.conn.executemany(
            """INSERT INTO scan_attribution
               (id, finding_fingerprint, alias_hash, file, committed_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            rows,
        )
        await self.db.conn.commit()
        return len(rows)

    async def list_attribution(
        self, fingerprints: Optional[List[str]] = None, limit: int = 100000
    ) -> List[AttributionRecord]:
        if fingerprints:
            placeholders = ",".join("?" for _ in fingerprints)
            query = (
                f"SELECT * FROM scan_attribution "
                f"WHERE finding_fingerprint IN ({placeholders}) ORDER BY created_at"
            )
            params: list = list(fingerprints)
        else:
            query = "SELECT * FROM scan_attribution ORDER BY created_at"
            params = []
        query += f" LIMIT {int(limit)}"
        cursor = await self.db.conn.execute(query, params)
        rows = await cursor.fetchall()
        return [
            AttributionRecord(
                finding_fingerprint=r["finding_fingerprint"],
                alias_hash=r["alias_hash"],
                file=r["file"],
                committed_at=r["committed_at"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    # ── profile_snapshot ──
    async def save_snapshot(self, alias_hash_: str, period: str, metrics: Dict[str, Any]) -> None:
        import json as _json
        await self.db.conn.execute(
            "INSERT INTO profile_snapshot (id, alias_hash, period, metrics_json) VALUES (?, ?, ?, ?)",
            (_gen_id(), alias_hash_, period, _json.dumps(metrics, ensure_ascii=False, default=str)),
        )
        await self.db.conn.commit()

    async def list_snapshots(
        self, alias_hash_: Optional[str] = None, period: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        clauses, params = [], []
        if alias_hash_:
            clauses.append("alias_hash = ?")
            params.append(alias_hash_)
        if period:
            clauses.append("period = ?")
            params.append(period)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await self.db.conn.execute(
            f"SELECT * FROM profile_snapshot{where} ORDER BY created_at", params
        )
        return [dict(r) for r in await cursor.fetchall()]

    # ── finding_status（修复状态） ──
    async def record_fix(self, fingerprint: str, marked_at: Optional[datetime] = None) -> None:
        ts = (marked_at or datetime.now(timezone.utc)).isoformat()
        await self.db.conn.execute(
            """INSERT INTO finding_status (id, fingerprint, status, marked_at)
               VALUES (?, ?, 'fixed', ?)
               ON CONFLICT(fingerprint) DO UPDATE SET marked_at = excluded.marked_at""",
            (_gen_id(), fingerprint, ts),
        )
        await self.db.conn.commit()

    async def list_fixes(
        self, fingerprints: Optional[List[str]] = None
    ) -> Dict[str, datetime]:
        """返回 {fingerprint: marked_at}（ISO 字符串解析失败则跳过）"""
        if fingerprints:
            placeholders = ",".join("?" for _ in fingerprints)
            query = f"SELECT fingerprint, marked_at FROM finding_status WHERE fingerprint IN ({placeholders})"
            params: list = list(fingerprints)
        else:
            query = "SELECT fingerprint, marked_at FROM finding_status"
            params = []
        cursor = await self.db.conn.execute(query, params)
        result: Dict[str, datetime] = {}
        for r in await cursor.fetchall():
            try:
                result[r["fingerprint"]] = datetime.fromisoformat(r["marked_at"])
            except (TypeError, ValueError):
                continue
        return result

    # ── forget（S6：仅删除画像库数据，不碰代码与 findings） ──
    async def forget_alias(self, alias_hash_: str) -> Dict[str, int]:
        """删除该别名在画像库中的全部数据（alias/snapshot/attribution）"""
        deleted = {}
        for table, col in (
            ("profile_snapshot", "alias_hash"),
            ("scan_attribution", "alias_hash"),
            ("developer_alias", "alias_hash"),
        ):
            cursor = await self.db.conn.execute(
                f"DELETE FROM {table} WHERE {col} = ?", (alias_hash_,)
            )
            deleted[table] = cursor.rowcount
        await self.db.conn.commit()
        return deleted
