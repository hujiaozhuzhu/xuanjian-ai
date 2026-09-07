"""
自动归档钩子 —— 每次扫描完成后由 scan 命令 / REST 扫描接口调用

负责：
1) 接管一次完整扫描的输出 (findings, report_md, snapshot 元数据)；
2) 每个 finding 通过 KnowledgeQueryPlugin 召回历史同类漏洞；
3) 将「快照 + 记录归档」写入知识图谱 SQLite；
4) 返回归档结果 (snapshot_id / cve_hits / knowledge_hits) 供：
   - CLI / REST 报告展示；
   - 后续按项目 / 版本 / 类型 / 时间范围检索。

安全约束：
- S2：不修改用户源文件；
- S7：归档写入仅到 ~/.xuanjian/kg_archive.db；
- 零网络（依赖 KnowledgeQueryPlugin 已传入 archive_fn，不额外外发）。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional

from ..models import ArchiveQuery, FixRecord, FixSnapshot, KnowledgeMatch
from ..store import KnowledgeStore, default_kg_db_path, open_store
from .query_plugin import KnowledgeQueryPlugin, _infer_category, _finding_rule_id


logger = logging.getLogger(__name__)

# archive_fn 回调：
# async (category, cwe, language, limit) -> List[dict]
ArchiveFn = Callable[..., Awaitable[List[Dict[str, Any]]]]


def _build_archive_fn(store: KnowledgeStore) -> ArchiveFn:
    """把 KnowledgeStore.search_records 转为 query_plugin 所需的回调"""

    async def _fn(
        *,
        category: Optional[str],
        cwe: Optional[str],
        language: Optional[str],
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        if store._conn is None:
            await store.connect()
            await store.initialize()
        q = ArchiveQuery(
            category=category,
            cwe=cwe,
            language=language,
            limit=max(10, min(limit, 500)),
            offset=0,
        )
        return [
            {
                "id": r.id,
                "rule_id": r.rule_id,
                "severity": r.severity,
                "file_path": r.file_path,
                "line_start": r.line_start,
                "fix_title": r.fix_title,
                "fix_diff": r.fix_diff,
                "reference_cve": r.reference_cve,
                "incident_note": r.incident_note,
                "archived_at": r.archived_at,
                "category": r.category,
                "language": r.language,
            }
            for r in await store.search_records(q)
        ]

    return _fn


async def _fix_result_for(finding: Any) -> Dict[str, Any]:
    """从 finding 抽取修复建议兜底信息（标题/diff/工时/CVE）。"""
    # 尽量复用 fp_sentinel.reporting.fix_advisor。不存在则返回占位。
    try:
        from fp_sentinel.reporting.fix_advisor import suggest_fix
        sug = suggest_fix(finding)
        return {
            "fix_title": sug.title,
            "fix_diff": sug.diff,
            "reference_cve": sug.reference_cve,
            "incident_note": sug.incident_note,
            "fix_effort_minutes": sug.effort_minutes,
        }
    except Exception:  # noqa: BLE001
        return {
            "fix_title": "",
            "fix_diff": "",
            "reference_cve": "",
            "incident_note": "",
            "fix_effort_minutes": 0,
        }


def _row_from_finding(
    finding: Any,
    snapshot_id: str,
    project_name: str,
    project_path: str,
    matches: List[KnowledgeMatch],
    fix: Dict[str, Any],
) -> FixRecord:
    def g(key: str, alias: Optional[List[str]] = None, default: Any = None):
        keys = [key] + (alias or [])
        for k in keys:
            if isinstance(finding, dict):
                if k in finding and finding[k] is not None:
                    return finding[k]
            else:
                v = getattr(finding, k, None)
                if v is not None:
                    return v
        return default

    # 优先把「最高相似度那一条」的参考信息合并到记录上
    top = matches[0] if matches else None
    severity = g("severity", default="MEDIUM")
    severity = getattr(severity, "value", str(severity))

    cwe = g("cwe") or (top.cwe if top else None)
    return FixRecord(
        id=g("id") or g("finding_id"),
        snapshot_id=snapshot_id,
        finding_id=g("id") or g("fingerprint"),
        project_name=project_name,
        project_path=project_path,
        rule_id=g("rule_id", default=""),
        severity=severity,
        file_path=g("file_path", alias=["file"], default=""),
        line_start=int(g("line_start", alias=["line"], default=0) or 0),
        line_end=g("line_end"),
        code_snippet=g("code_snippet", alias=["code"], default="") or "",
        message=g("message", default="") or "",
        category=g("category") or (_infer_category(g("rule_id", default="")) if g("rule_id") else None),
        language=g("language"),
        cwe=cwe,
        owasp=g("owasp"),
        scanner=g("scanner", default="") or "",
        confidence=float(g("confidence", default=0.0) or 0.0),
        fix_title=fix.get("fix_title") or (top.fix_title if top else "") or "",
        fix_diff=fix.get("fix_diff") or (top.fix_diff if top else "") or "",
        fix_effort_minutes=int(fix.get("fix_effort_minutes") or 0),
        reference_cve=fix.get("reference_cve") or (top.reference_cve if top else "") or "",
        incident_note=fix.get("incident_note") or (top.incident_note if top else "") or "",
        matched_knowledge=matches[:5],
    )


class AutoArchiver:
    """封装归档流程，典型使用方式::

        async with AutoArchiver() as archiver:
            result = await archiver.archive_scan(...)
    """

    def __init__(
        self,
        *,
        store: Optional[KnowledgeStore] = None,
        db_path: Optional[str] = None,
        top_k: int = 5,
        fallback_knowledge: bool = True,
        min_score: float = 0.05,
    ):
        self._external_store = store is not None
        self.store = store or open_store(db_path or default_kg_db_path())
        self.top_k = top_k
        self.fallback_knowledge = fallback_knowledge
        self.min_score = min_score

    async def __aenter__(self):
        if self.store._conn is None:
            await self.store.connect()
            await self.store.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if not self._external_store:
            await self.store.close()
        return False

    async def archive_scan(
        self,
        *,
        project_name: str,
        project_path: str,
        findings: List[Any],
        report_md: str = "",
        version: str = "unversioned",
        language: Optional[str] = None,
        scanner: str = "",
        report_kind: str = "compliance",
        duration_seconds: float = 0.0,
    ) -> Dict[str, Any]:
        """对一次完整扫描执行归档。返回归档结果。"""
        project_name = project_name or _basename(project_path) or "unknown"
        query_plugin = KnowledgeQueryPlugin(
            archive_fn=_build_archive_fn(self.store),
            top_k=self.top_k,
            fallback=self.fallback_knowledge,
            min_score=self.min_score,
        )
        # 查询匹配
        matches_by_finding = await query_plugin.batch_match(findings)

        # 生成 snapshot 统计
        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        records: List[FixRecord] = []
        knowledge_hits = 0
        cve_hits = 0

        seen_match_ids = set()
        for finding in findings:
            fid = _find_key(finding)
            matches = matches_by_finding.get(fid or "", [])
            fix = await _fix_result_for(finding)
            rec = _row_from_finding(
                finding,
                snapshot_id="",  # 临时，下面统一回填
                project_name=project_name,
                project_path=project_path,
                matches=matches,
                fix=fix,
            )
            sev = rec.severity
            by_severity[sev] = by_severity.get(sev, 0) + 1
            cat = (rec.category or "uncategorized").lower()
            by_category[cat] = by_category.get(cat, 0) + 1

            knowledge_hits += len(matches)
            for m in matches:
                if m.reference_cve and m.match_id not in seen_match_ids:
                    seen_match_ids.add(m.match_id)
                    cve_hits += 1
            records.append(rec)

        snapshot = FixSnapshot(
            id="",
            project_name=project_name,
            project_path=project_path,
            version=version,
            language=language,
            scanner=scanner,
            total_findings=len(findings),
            by_severity=by_severity,
            by_category=by_category,
            duration_seconds=float(duration_seconds),
            report_kind=report_kind,
            report_text=report_md[:200000],  # 限制存储量
            fix_cve_hits=cve_hits,
            fix_knowledge_hits=knowledge_hits,
        )
        snapshot = await self.store.archive_snapshot(snapshot)
        for rec in records:
            rec.snapshot_id = snapshot.id
        await self.store.archive_records(
            snapshot_id=snapshot.id, records=records
        )

        return {
            "snapshot_id": snapshot.id,
            "project_name": snapshot.project_name,
            "project_path": snapshot.project_path,
            "total_findings": snapshot.total_findings,
            "by_severity": snapshot.by_severity,
            "by_category": snapshot.by_category,
            "knowledge_hits": knowledge_hits,
            "cve_hits": cve_hits,
            "archived_at": snapshot.archived_at,
        }


def _find_key(finding: Any) -> Optional[str]:
    for k in ("id", "fingerprint", "finding_id"):
        v = None
        if isinstance(finding, dict):
            v = finding.get(k)
        else:
            v = getattr(finding, k, None)
        if v is not None and v != "":
            return str(v)
    return None


def _basename(path: str) -> str:
    from pathlib import PurePath
    return PurePath(path).name or path


# 便捷函数 —— scan 命令直接 await archive_scan(...)
async def archive_scan(
    *,
    project_name: str,
    project_path: str,
    findings: List[Any],
    report_md: str = "",
    version: str = "unversioned",
    language: Optional[str] = None,
    scanner: str = "",
    report_kind: str = "compliance",
    duration_seconds: float = 0.0,
    db_path: Optional[str] = None,
    top_k: int = 5,
) -> Dict[str, Any]:
    """便捷函数：一次性触发归档。

    在无法获得 AutoArchiver 上下文场景（如 FastAPI 请求）下可直接调用。
    """
    async with AutoArchiver(db_path=db_path, top_k=top_k) as archiver:
        return await archiver.archive_scan(
            project_name=project_name,
            project_path=project_path,
            findings=findings,
            report_md=report_md,
            version=version,
            language=language,
            scanner=scanner,
            report_kind=report_kind,
            duration_seconds=duration_seconds,
        )


def attach_kg_metadata(findings: List[Any], matches: Dict[str, List[KnowledgeMatch]]) -> None:
    """把每条的命中知识写入 finding.metadata（原地），方便 JSON/SARIF 透传。"""
    for finding in findings:
        fid = _find_key(finding)
        if not fid or fid not in matches:
            continue
        if isinstance(finding, dict):
            md = finding.get("metadata")
            if not isinstance(md, dict):
                md = {}
                finding["metadata"] = md
        else:
            md = getattr(finding, "metadata", None)
            if not isinstance(md, dict):
                md = {}
                try:
                    finding.metadata = md  # type: ignore[assignment]
                except Exception:  # noqa: BLE001
                    continue
        md["knowledge_graph"] = {
            "hits": len(matches[fid]),
            "matches": [m.model_dump() for m in matches[fid][:5]],
        }