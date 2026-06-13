"""
数据库仓库层

提供 Project / Finding / FalsePositiveMark / ScanHistory 的 CRUD 操作
"""

import json
import uuid
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiosqlite

from .connection import Database
from ..models import (
    Finding,
    FalsePositiveMark,
    Project,
    ScanHistory,
)

logger = logging.getLogger(__name__)


# ─────────────────────── 辅助函数 ───────────────────────

def _row_to_dict(row: aiosqlite.Row) -> Dict[str, Any]:
    """将 aiosqlite.Row 转为字典"""
    return dict(row)


def _generate_id() -> str:
    """生成唯一 ID"""
    return str(uuid.uuid4())


# ─────────────────────── ProjectRepo ───────────────────────

class ProjectRepo:
    """项目仓库"""

    def __init__(self, db: Database):
        self.db = db

    async def create(
        self,
        name: str,
        path: str,
        language: str = "auto",
        description: Optional[str] = None,
    ) -> Project:
        """创建项目"""
        project_id = _generate_id()
        now = datetime.utcnow().isoformat()
        await self.db.conn.execute(
            """INSERT INTO projects (id, name, path, language, description, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (project_id, name, path, language, description, now, now),
        )
        await self.db.conn.commit()
        return Project(
            id=project_id, name=name, path=path, language=language,
            description=description, created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
        )

    async def get_by_id(self, project_id: str) -> Optional[Project]:
        """按 ID 获取项目"""
        cursor = await self.db.conn.execute(
            "SELECT * FROM projects WHERE id = ?", (project_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return self._row_to_project(row)

    async def get_by_path(self, path: str) -> Optional[Project]:
        """按路径获取项目"""
        cursor = await self.db.conn.execute(
            "SELECT * FROM projects WHERE path = ?", (path,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return self._row_to_project(row)

    async def list_all(self) -> List[Project]:
        """列出所有项目"""
        cursor = await self.db.conn.execute(
            "SELECT * FROM projects ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        return [self._row_to_project(r) for r in rows]

    async def update(self, project_id: str, **kwargs) -> bool:
        """更新项目字段"""
        allowed = {"name", "path", "language", "description"}
        fields = {k: v for k, v in kwargs.items() if k in allowed}
        if not fields:
            return False
        fields["updated_at"] = datetime.utcnow().isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [project_id]
        await self.db.conn.execute(
            f"UPDATE projects SET {set_clause} WHERE id = ?", values
        )
        await self.db.conn.commit()
        return True

    async def delete(self, project_id: str) -> bool:
        """删除项目"""
        cursor = await self.db.conn.execute(
            "DELETE FROM projects WHERE id = ?", (project_id,)
        )
        await self.db.conn.commit()
        return cursor.rowcount > 0

    async def get_or_create(
        self, name: str, path: str, language: str = "auto"
    ) -> Project:
        """获取已有项目，不存在则创建"""
        existing = await self.get_by_path(path)
        if existing:
            return existing
        return await self.create(name=name, path=path, language=language)

    @staticmethod
    def _row_to_project(row: aiosqlite.Row) -> Project:
        d = _row_to_dict(row)
        for field in ("created_at", "updated_at"):
            if d.get(field) and isinstance(d[field], str):
                try:
                    d[field] = datetime.fromisoformat(d[field])
                except ValueError:
                    d[field] = None
        return Project(**d)


# ─────────────────────── FindingRepo ───────────────────────

class FindingRepo:
    """发现(Finding)仓库"""

    def __init__(self, db: Database):
        self.db = db

    async def create(self, finding: Finding, scan_id: Optional[str] = None) -> Finding:
        """保存一条 Finding"""
        fid = finding.id or _generate_id()
        metadata_json = json.dumps(finding.metadata or {})
        await self.db.conn.execute(
            """INSERT OR REPLACE INTO findings
               (id, scan_id, scanner, rule_id, severity, file_path,
                line_start, line_end, code_snippet, message, category,
                language, fingerprint, cwe, owasp, confidence, metadata, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                fid, scan_id, finding.scanner, finding.rule_id,
                finding.severity.value, finding.file_path,
                finding.line_start, finding.line_end,
                finding.code_snippet, finding.message,
                finding.category, finding.language,
                finding.fingerprint, finding.cwe, finding.owasp,
                finding.confidence, metadata_json,
                (finding.created_at or datetime.utcnow()).isoformat(),
            ),
        )
        await self.db.conn.commit()
        finding.id = fid
        return finding

    async def bulk_create(
        self, findings: List[Finding], scan_id: Optional[str] = None
    ) -> int:
        """批量保存"""
        rows = []
        for f in findings:
            fid = f.id or _generate_id()
            f.id = fid
            metadata_json = json.dumps(f.metadata or {})
            rows.append((
                fid, scan_id, f.scanner, f.rule_id,
                f.severity.value, f.file_path,
                f.line_start, f.line_end,
                f.code_snippet, f.message,
                f.category, f.language,
                f.fingerprint, f.cwe, f.owasp,
                f.confidence, metadata_json,
                (f.created_at or datetime.utcnow()).isoformat(),
            ))

        await self.db.conn.executemany(
            """INSERT OR REPLACE INTO findings
               (id, scan_id, scanner, rule_id, severity, file_path,
                line_start, line_end, code_snippet, message, category,
                language, fingerprint, cwe, owasp, confidence, metadata, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        await self.db.conn.commit()
        return len(rows)

    async def get_by_id(self, finding_id: str) -> Optional[Finding]:
        """按 ID 获取"""
        cursor = await self.db.conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        )
        row = await cursor.fetchone()
        return self._row_to_finding(row) if row else None

    async def list_findings(
        self,
        scan_id: Optional[str] = None,
        scanner: Optional[str] = None,
        severity: Optional[str] = None,
        file_path: Optional[str] = None,
        language: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Finding]:
        """按条件查询 Finding 列表"""
        clauses = []
        params: list = []
        if scan_id:
            clauses.append("scan_id = ?")
            params.append(scan_id)
        if scanner:
            clauses.append("scanner = ?")
            params.append(scanner)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if file_path:
            clauses.append("file_path LIKE ?")
            params.append(f"%{file_path}%")
        if language:
            clauses.append("language = ?")
            params.append(language)

        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        query = f"SELECT * FROM findings{where} ORDER BY severity, file_path LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = await self.db.conn.execute(query, params)
        rows = await cursor.fetchall()
        return [self._row_to_finding(r) for r in rows]

    async def count(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> int:
        """统计数量"""
        clauses = []
        params: list = []
        if scan_id:
            clauses.append("scan_id = ?")
            params.append(scan_id)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        cursor = await self.db.conn.execute(
            f"SELECT COUNT(*) FROM findings{where}", params
        )
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def get_by_fingerprint(self, fingerprint: str) -> List[Finding]:
        """按指纹查询"""
        cursor = await self.db.conn.execute(
            "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
        )
        rows = await cursor.fetchall()
        return [self._row_to_finding(r) for r in rows]

    async def delete_by_scan_id(self, scan_id: str) -> int:
        """删除某次扫描的所有 Finding"""
        cursor = await self.db.conn.execute(
            "DELETE FROM findings WHERE scan_id = ?", (scan_id,)
        )
        await self.db.conn.commit()
        return cursor.rowcount

    async def get_severity_stats(self, scan_id: Optional[str] = None) -> Dict[str, int]:
        """按严重程度统计"""
        where = " WHERE scan_id = ?" if scan_id else ""
        params = [scan_id] if scan_id else []
        cursor = await self.db.conn.execute(
            f"SELECT severity, COUNT(*) as cnt FROM findings{where} GROUP BY severity",
            params,
        )
        rows = await cursor.fetchall()
        return {row["severity"]: row["cnt"] for row in rows}

    @staticmethod
    def _row_to_finding(row: aiosqlite.Row) -> Finding:
        d = _row_to_dict(row)
        # metadata 以 JSON 字符串存储
        if isinstance(d.get("metadata"), str):
            try:
                d["metadata"] = json.loads(d["metadata"])
            except json.JSONDecodeError:
                d["metadata"] = {}
        if d.get("created_at") and isinstance(d["created_at"], str):
            try:
                d["created_at"] = datetime.fromisoformat(d["created_at"])
            except ValueError:
                d["created_at"] = None
        return Finding(**d)


# ─────────────────────── FPMarkRepo ───────────────────────

class FPMarkRepo:
    """误报标记仓库"""

    def __init__(self, db: Database):
        self.db = db

    async def create(
        self,
        finding_id: str,
        reason: str,
        marked_by: str = "manual",
        scope: str = "instance",
        confidence: float = 1.0,
    ) -> FalsePositiveMark:
        """创建误报标记"""
        cursor = await self.db.conn.execute(
            """INSERT INTO false_positive_marks (finding_id, reason, marked_by, scope, confidence)
               VALUES (?, ?, ?, ?, ?)""",
            (finding_id, reason, marked_by, scope, confidence),
        )
        await self.db.conn.commit()
        mark_id = cursor.lastrowid
        return FalsePositiveMark(
            id=mark_id, finding_id=finding_id, reason=reason,
            marked_by=marked_by, scope=scope, confidence=confidence,
            created_at=datetime.utcnow(),
        )

    async def get_by_finding_id(self, finding_id: str) -> List[FalsePositiveMark]:
        """获取某 Finding 的所有误报标记"""
        cursor = await self.db.conn.execute(
            "SELECT * FROM false_positive_marks WHERE finding_id = ? ORDER BY created_at DESC",
            (finding_id,),
        )
        rows = await cursor.fetchall()
        return [self._row_to_mark(r) for r in rows]

    async def list_all(
        self, limit: int = 100, offset: int = 0
    ) -> List[FalsePositiveMark]:
        """列出所有误报标记"""
        cursor = await self.db.conn.execute(
            "SELECT * FROM false_positive_marks ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return [self._row_to_mark(r) for r in rows]

    async def delete(self, mark_id: int) -> bool:
        """删除误报标记"""
        cursor = await self.db.conn.execute(
            "DELETE FROM false_positive_marks WHERE id = ?", (mark_id,)
        )
        await self.db.conn.commit()
        return cursor.rowcount > 0

    async def is_marked_fp(self, finding_id: str) -> bool:
        """检查 Finding 是否已被标记为误报"""
        cursor = await self.db.conn.execute(
            "SELECT COUNT(*) FROM false_positive_marks WHERE finding_id = ?",
            (finding_id,),
        )
        row = await cursor.fetchone()
        return (row[0] if row else 0) > 0

    async def get_fingerprints(self, scope: str = "global") -> List[str]:
        """获取指定 scope 下已标记误报的 Finding 指纹"""
        cursor = await self.db.conn.execute(
            """SELECT DISTINCT f.fingerprint
               FROM false_positive_marks m
               JOIN findings f ON m.finding_id = f.id
               WHERE m.scope = ? AND f.fingerprint IS NOT NULL""",
            (scope,),
        )
        rows = await cursor.fetchall()
        return [row["fingerprint"] for row in rows]

    @staticmethod
    def _row_to_mark(row: aiosqlite.Row) -> FalsePositiveMark:
        d = _row_to_dict(row)
        if d.get("created_at") and isinstance(d["created_at"], str):
            try:
                d["created_at"] = datetime.fromisoformat(d["created_at"])
            except ValueError:
                d["created_at"] = None
        return FalsePositiveMark(**d)


# ─────────────────────── ScanHistoryRepo ───────────────────────

class ScanHistoryRepo:
    """扫描历史仓库"""

    def __init__(self, db: Database):
        self.db = db

    async def create(
        self,
        project_path: str,
        scanner: str,
        project_id: Optional[str] = None,
        language: Optional[str] = None,
        total_findings: int = 0,
        duration_seconds: float = 0.0,
        status: str = "completed",
        error_message: Optional[str] = None,
    ) -> ScanHistory:
        """记录一次扫描"""
        scan_id = _generate_id()
        now = datetime.utcnow().isoformat()
        await self.db.conn.execute(
            """INSERT INTO scan_history
               (scan_id, project_id, project_path, scanner, language,
                total_findings, duration_seconds, status, error_message, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, project_id, project_path, scanner, language,
             total_findings, duration_seconds, status, error_message, now),
        )
        await self.db.conn.commit()
        return ScanHistory(
            scan_id=scan_id, project_id=project_id,
            project_path=project_path, scanner=scanner,
            language=language, total_findings=total_findings,
            duration_seconds=duration_seconds, status=status,
            error_message=error_message, timestamp=datetime.fromisoformat(now),
        )

    async def get_by_scan_id(self, scan_id: str) -> Optional[ScanHistory]:
        """按 scan_id 获取"""
        cursor = await self.db.conn.execute(
            "SELECT * FROM scan_history WHERE scan_id = ?", (scan_id,)
        )
        row = await cursor.fetchone()
        return self._row_to_history(row) if row else None

    async def list_history(
        self,
        project_id: Optional[str] = None,
        scanner: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[ScanHistory]:
        """列出扫描历史"""
        clauses = []
        params: list = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        if scanner:
            clauses.append("scanner = ?")
            params.append(scanner)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        query = f"SELECT * FROM scan_history{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = await self.db.conn.execute(query, params)
        rows = await cursor.fetchall()
        return [self._row_to_history(r) for r in rows]

    async def delete(self, scan_id: str) -> bool:
        """删除扫描历史"""
        cursor = await self.db.conn.execute(
            "DELETE FROM scan_history WHERE scan_id = ?", (scan_id,)
        )
        await self.db.conn.commit()
        return cursor.rowcount > 0

    @staticmethod
    def _row_to_history(row: aiosqlite.Row) -> ScanHistory:
        d = _row_to_dict(row)
        if d.get("timestamp") and isinstance(d["timestamp"], str):
            try:
                d["timestamp"] = datetime.fromisoformat(d["timestamp"])
            except ValueError:
                d["timestamp"] = None
        return ScanHistory(**d)
