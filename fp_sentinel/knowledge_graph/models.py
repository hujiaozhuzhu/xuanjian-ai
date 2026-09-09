"""
知识图谱归档数据模型 (Pydantic v2)

- KnowledgeMatch  : 扫描时从历史档案中召回的「同类漏洞 / 修复建议 / CVE 案例」
- FixRecord       : 归档到知识图谱的单条 finding 记录（含其命中的 KnowledgeMatch 列表）
- FixSnapshot     : 一次完整扫描对应的归档快照（项目 / 版本 / 时间 关键索引）
- ArchiveQuery    : 归档检索条件 —— 支持按项目 / 版本 / 漏洞类型 / 时间范围快速检索
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class KnowledgeMatch(BaseModel):
    """知识图谱召回的「历史同类漏洞 / 修复建议 / CVE 案例」"""
    model_config = ConfigDict(extra="forbid")

    match_id: str = Field(..., description="归档记录 id")
    rule_id: str = Field(..., description="命中规则")
    category: Optional[str] = Field(None, description="漏洞分类键")
    cwe: Optional[str] = Field(None, description="CWE 编号")
    language: Optional[str] = Field(None, description="编程语言")
    severity: Optional[str] = Field(None, description="历史严重度")
    file_path: Optional[str] = Field(None, description="历史文件路径")
    line_start: Optional[int] = Field(None, description="历史行号")
    fix_title: str = Field("", description="修复建议标题")
    fix_diff: str = Field("", description="修复 diff 字符串（仅展示）")
    reference_cve: str = Field("", description="匹配 CVE")
    incident_note: str = Field("", description="匹配的事故说明")
    archived_at: str = Field("", description="归档时间 ISO8601")
    similarity: float = Field(0.0, ge=0.0, le=1.0, description="相似度评分 0-1")


class FixRecord(BaseModel):
    """归档到知识图谱的单条 finding 记录"""
    model_config = ConfigDict(extra="ignore")

    id: Optional[str] = None
    snapshot_id: str = ""  # 所属快照
    finding_id: Optional[str] = None
    project_name: str = ""
    project_path: str = ""
    rule_id: str = ""
    severity: str = ""
    file_path: str = ""
    line_start: int = 0
    line_end: Optional[int] = None
    code_snippet: str = ""
    message: str = ""
    category: Optional[str] = None
    language: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    scanner: str = ""
    confidence: float = 0.0
    fix_title: str = ""
    fix_diff: str = ""
    fix_effort_minutes: int = 0
    reference_cve: str = ""
    incident_note: str = ""
    matched_knowledge: List[KnowledgeMatch] = Field(default_factory=list)
    archived_at: str = Field(default_factory=_now)

    def to_row(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "snapshot_id": self.snapshot_id,
            "finding_id": self.finding_id,
            "project_name": self.project_name,
            "project_path": self.project_path,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet[:4000],
            "message": self.message[:2000],
            "category": self.category or "",
            "language": self.language or "",
            "cwe": self.cwe or "",
            "owasp": self.owasp or "",
            "scanner": self.scanner,
            "confidence": self.confidence,
            "fix_title": self.fix_title[:500],
            "fix_diff": self.fix_diff[:4000],
            "fix_effort_minutes": self.fix_effort_minutes,
            "reference_cve": self.reference_cve[:50],
            "incident_note": self.incident_note[:1000],
            "archived_at": self.archived_at,
        }


class FixSnapshot(BaseModel):
    """一次扫描对应的归档快照：按「项目 / 版本 / 漏洞类型 / 时间范围」检索的主入口"""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="快照唯一 id (uuid)")
    project_name: str = ""
    project_path: str = ""
    version: str = "unversioned"
    language: Optional[str] = None
    scanner: str = ""
    total_findings: int = 0
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_category: Dict[str, int] = Field(default_factory=dict)
    duration_seconds: float = 0.0
    report_kind: str = "compliance"
    report_text: str = ""
    fix_cve_hits: int = 0
    fix_knowledge_hits: int = 0
    archived_at: str = Field(default_factory=_now)

    def to_row(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "project_name": self.project_name,
            "project_path": self.project_path,
            "version": self.version,
            "language": self.language or "",
            "scanner": self.scanner,
            "total_findings": self.total_findings,
            "by_severity": self.by_severity,
            "by_category": self.by_category,
            "duration_seconds": self.duration_seconds,
            "report_kind": self.report_kind,
            "report_text": self.report_text,
            "fix_cve_hits": self.fix_cve_hits,
            "fix_knowledge_hits": self.fix_knowledge_hits,
            "archived_at": self.archived_at,
        }


class ArchiveQuery(BaseModel):
    """归档检索条件 —— 按项目 / 版本 / 漏洞类型 / 时间范围快速检索历史记录"""
    model_config = ConfigDict(extra="forbid")

    # 基础维度
    project_name: Optional[str] = None
    project_path: Optional[str] = None
    version: Optional[str] = None
    category: Optional[str] = None
    cwe: Optional[str] = None
    language: Optional[str] = None
    severity: Optional[str] = None
    rule_id: Optional[str] = None
    # 记录语义上的快照限定（仅 search_records/count_records 使用）
    snapshot_id: Optional[str] = None
    # 时间范围 (ISO8601)
    since: Optional[str] = None
    until: Optional[str] = None
    limit: int = Field(50, ge=1, le=1000)
    offset: int = Field(0, ge=0)
