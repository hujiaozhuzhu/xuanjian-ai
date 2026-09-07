"""
知识图谱 REST 路由 —— 接入 FastAPI app (fp_sentinel.server.create_app)

注册端点：
  POST /api/kg/match            —— 单条规则匹配
  POST /api/kg/archive           —— 触发归档
  GET  /api/kg/search            —— 按条件检索
  GET  /api/kg/stats             —— 统计
  DELETE /api/kg/purge           —— 清理 (S5 语义)

全部通过 typer/fastapi 标准形态返回 JSON；失败返回 {"error": "..."}。
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from .features.query_plugin import KnowledgeQueryPlugin
from .models import ArchiveQuery

logger = logging.getLogger(__name__)


router = APIRouter()

# 在 KNOWLEDGE / features 里 archive 叫 auto_archive.archive_scan
def _get_archive_scan():
    from .features.auto_archive import archive_scan as fn
    return fn


def _get_store_factory():
    from .store import open_store
    return open_store


def _get_default_db():
    from .store import default_kg_db_path
    return default_kg_db_path()


# ─────────────────────── /api/kg/match ───────────────────────


@router.post("/api/kg/match")
async def kg_match(payload: Dict[str, Any]):
    """单条规则匹配：查找历史同类漏洞/修复/CVE。"""
    try:
        rule_id = payload.get("rule_id") or ""
        category = payload.get("category")
        cwe = payload.get("cwe")
        severity = payload.get("severity")
        language = payload.get("language")
        top_k = int(payload.get("top_k", 5))
        db_path = payload.get("db_path") or _get_default_db()
        if not rule_id:
            raise HTTPException(status_code=422, detail="rule_id required")
        store_factory = _get_store_factory()
        store = store_factory(db_path)
        await store.connect()
        await store.initialize()
        try:
            plugin = KnowledgeQueryPlugin(
                archive_fn=_adapter(store),
            )
            plugin.top_k = top_k
            matches = await plugin.match(
                rule_id=rule_id, category=category, cwe=cwe,
                severity=severity, language=language,
            )
        finally:
            await store.close()
        return {"matches": [m.model_dump() for m in matches]}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("/api/kg/match failed")
        return {"error": str(e)}


def _adapter(store):
    async def _fn(category, cwe, language, limit):
        q = ArchiveQuery(
            category=category, cwe=cwe, language=language,
            limit=limit or 200, offset=0,
        )
        recs = await store.search_records(q)
        return [
            {
                "id": r.id, "rule_id": r.rule_id, "severity": r.severity,
                "fix_title": r.fix_title, "fix_diff": r.fix_diff,
                "reference_cve": r.reference_cve, "incident_note": r.incident_note,
                "archived_at": r.archived_at, "category": r.category,
                "language": r.language, "file_path": r.file_path,
                "line_start": r.line_start,
            }
            for r in recs
        ]
    return _fn


# ─────────────────────── /api/kg/archive ───────────────────────


@router.post("/api/kg/archive")
async def kg_archive(payload: Dict[str, Any]):
    """手动触发归档。"""
    try:
        project_name = payload.get("project_name") or ""
        project_path = payload.get("project_path") or ""
        findings = payload.get("findings") or []
        if not project_name or not project_path or not isinstance(findings, list):
            raise HTTPException(
                status_code=422,
                detail="project_name / project_path / findings (list) required",
            )
        result = await _get_archive_scan()(
            project_name=project_name,
            project_path=project_path,
            findings=findings,
            report_md=payload.get("report_md", ""),
            version=payload.get("version", "unversioned"),
            language=payload.get("language"),
            scanner=payload.get("scanner", ""),
            report_kind=payload.get("report_kind", "compliance"),
            duration_seconds=float(payload.get("duration_seconds", 0.0) or 0.0),
            db_path=payload.get("db_path"),
            top_k=int(payload.get("top_k", 5)),
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("/api/kg/archive failed")
        return {"error": str(e)}


# ─────────────────────── /api/kg/search ───────────────────────


@router.get("/api/kg/search")
async def kg_search(
    project_name: Optional[str] = None,
    project_path: Optional[str] = None,
    version: Optional[str] = None,
    category: Optional[str] = None,
    cwe: Optional[str] = None,
    language: Optional[str] = None,
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    scope: str = Query("snapshots", regex="^(snapshots|records)$"),
    db_path: Optional[str] = None,
):
    """按项目 / 版本 / 漏洞类型 / 时间范围检索历史记录。"""
    try:
        store_factory = _get_store_factory()
        store = store_factory(db_path or _get_default_db())
        await store.connect()
        await store.initialize()
        try:
            q = ArchiveQuery(
                project_name=project_name, project_path=project_path, version=version,
                category=category, cwe=cwe, language=language, severity=severity,
                rule_id=rule_id, since=since, until=until,
                limit=limit, offset=offset,
            )
            if scope == "records":
                items = await store.search_records(q)
                total = await store.count_records(q)
            else:
                items = await store.search_snapshots(q)
                total = await store.count_snapshots(q)
        finally:
            await store.close()
        return {
            "total": total,
            "limit": limit, "offset": offset, "scope": scope,
            "items": [item.to_row() for item in items],
        }
    except Exception as e:
        logger.exception("/api/kg/search failed")
        return {"error": str(e)}


# ─────────────────────── /api/kg/stats ───────────────────────


@router.get("/api/kg/stats")
async def kg_stats(db_path: Optional[str] = None):
    try:
        store_factory = _get_store_factory()
        store = store_factory(db_path or _get_default_db())
        await store.connect()
        await store.initialize()
        try:
            return await store.stats()
        finally:
            await store.close()
    except Exception as e:
        logger.exception("/api/kg/stats failed")
        return {"error": str(e)}


# ─────────────────────── /api/kg/purge ───────────────────────


@router.delete("/api/kg/purge")
async def kg_purge(days: int = Query(90, ge=1, le=3650), db_path: Optional[str] = None):
    try:
        store_factory = _get_store_factory()
        store = store_factory(db_path or _get_default_db())
        await store.connect()
        await store.initialize()
        try:
            removed = await store.purge(days=days)
        finally:
            await store.close()
        return {"removed_snapshots": removed, "days": days}
    except Exception as e:
        logger.exception("/api/kg/purge failed")
        return {"error": str(e)}
