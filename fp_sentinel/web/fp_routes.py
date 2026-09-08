"""
玄鉴 v3.0 — 自适应误报引擎 API 路由

提供 /api/v1/fp-optimize/* 前缀的 REST API，
覆盖用户反馈收集、自动规则优化、个性化模型、误报率统计四大功能。
版本: 3.0.0
"""

import logging
import os
import tempfile
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ─────────────────────── 请求/响应模型 ───────────────────────

class FeedbackSubmitRequest(BaseModel):
    """提交单条反馈请求"""
    finding_id: str = Field(..., description="关联的发现ID")
    project_id: Optional[str] = Field(None, description="项目ID")
    feedback_type: str = Field(..., description="反馈类型: false_positive/true_positive/unsure")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="反馈置信度")
    reason: Optional[str] = Field(None, description="反馈原因")
    marker: Optional[str] = Field(None, description="标记人")
    rule_id: Optional[str] = Field(None, description="规则ID")
    scanner: Optional[str] = Field(None, description="扫描工具")
    fingerprint: Optional[str] = Field(None, description="漏洞指纹")
    code_snippet: Optional[str] = Field(None, description="代码片段")
    file_path: Optional[str] = Field(None, description="文件路径")
    severity: Optional[str] = Field(None, description="严重程度")


class BatchFeedbackRequest(BaseModel):
    """批量提交反馈请求"""
    feedbacks: list = Field(..., description="反馈列表")


class OptimizeRequest(BaseModel):
    """触发优化请求"""
    dry_run: bool = Field(False, description="仅分析不应用")
    project_id: Optional[str] = Field(None, description="项目ID")


def create_fp_optimize_router(
    db_path: Optional[str] = None,
) -> APIRouter:
    """
    创建 FP Optimize API 路由器

    Args:
        db_path: SQLite 数据库路径 (None 使用默认路径)

    Returns:
        FastAPI APIRouter
    """
    if db_path is None:
        db_path = os.path.join(tempfile.gettempdir(), "xuanjian_fp_optimize.db")

    router = APIRouter(prefix="/api/v1/fp-optimize", tags=["fp-optimize"])

    # 延迟初始化 store 和 engines
    _store = None
    _feedback_engine = None
    _stats_engine = None
    _personalization_engine = None

    async def _get_store():
        nonlocal _store
        if _store is None:
            from ..fp_optimize.feedback_store import FeedbackStore

            # 使用环境变量或默认路径
            path = os.environ.get("XUANJIAN_FP_DB", db_path)
            _store = FeedbackStore(db_path=path)
            await _store.initialize()
        return _store

    async def _get_feedback_engine():
        nonlocal _feedback_engine
        if _feedback_engine is None:
            from ..fp_optimize.feedback_engine import FeedbackLearningEngine
            store = await _get_store()
            _feedback_engine = FeedbackLearningEngine(store)
        return _feedback_engine

    async def _get_stats_engine():
        nonlocal _stats_engine
        if _stats_engine is None:
            from ..fp_optimize.stats_engine import StatsEngine
            store = await _get_store()
            _stats_engine = StatsEngine(store)
        return _stats_engine

    async def _get_personalization_engine():
        nonlocal _personalization_engine
        if _personalization_engine is None:
            from ..fp_optimize.personalization import PersonalizationEngine
            store = await _get_store()
            _personalization_engine = PersonalizationEngine(store)
        return _personalization_engine

    # ═══════════════════ 反馈提交接口 ═══════════════════

    @router.post("/feedback")
    async def submit_feedback(req: FeedbackSubmitRequest):
        """提交单条用户反馈"""
        try:
            store = await _get_store()
            from ..fp_optimize.models import FeedbackType, FeedbackSource

            feedback = await store.add_feedback(
                finding_id=req.finding_id,
                feedback_type=FeedbackType(req.feedback_type),
                project_id=req.project_id,
                source=FeedbackSource.MANUAL,
                confidence=req.confidence,
                reason=req.reason,
                marker=req.marker,
                rule_id=req.rule_id,
                scanner=req.scanner,
                fingerprint=req.fingerprint,
                code_snippet=req.code_snippet,
                file_path=req.file_path,
                severity=req.severity,
            )
            return {
                "status": "ok",
                "feedback_id": feedback.id,
                "created_at": feedback.created_at.isoformat() if feedback.created_at else None,
            }
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"无效的反馈类型: {e}")
        except Exception as e:
            logger.exception("提交反馈失败")
            raise HTTPException(status_code=500, detail=str(e))

    @router.post("/feedback/batch")
    async def submit_batch_feedback(req: BatchFeedbackRequest):
        """批量提交用户反馈"""
        try:
            store = await _get_store()
            count = await store.batch_add_feedbacks(req.feedbacks)
            return {"status": "ok", "count": count}
        except Exception as e:
            logger.exception("批量提交反馈失败")
            raise HTTPException(status_code=500, detail=str(e))

    @router.get("/feedback")
    async def list_feedbacks(
        project_id: Optional[str] = None,
        feedback_type: Optional[str] = None,
        rule_id: Optional[str] = None,
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ):
        """查询反馈列表"""
        store = await _get_store()
        feedbacks = await store.list_feedbacks(
            project_id=project_id,
            feedback_type=feedback_type,
            rule_id=rule_id,
            limit=limit,
            offset=offset,
        )
        return {
            "status": "ok",
            "total": len(feedbacks),
            "feedbacks": [f.model_dump() for f in feedbacks],
        }

    @router.delete("/feedback/{feedback_id}")
    async def delete_feedback(feedback_id: str):
        """删除反馈记录"""
        store = await _get_store()
        ok = await store.delete_feedback(feedback_id)
        if not ok:
            raise HTTPException(status_code=404, detail="反馈不存在")
        return {"status": "ok"}

    # ═══════════════════ 统计分析接口 ═══════════════════

    @router.get("/stats")
    async def get_statistics(project_id: Optional[str] = None):
        """获取反馈统计数据"""
        engine = await _get_stats_engine()
        stats = await engine.feedback_engine.get_feedback_statistics(project_id)
        return {"status": "ok", "stats": stats.model_dump()}

    @router.get("/dashboard")
    async def get_dashboard(project_id: Optional[str] = None):
        """获取仪表板综合数据"""
        engine = await _get_stats_engine()
        dashboard = await engine.get_dashboard_data(project_id)
        return {"status": "ok", "dashboard": dashboard.model_dump()}

    @router.get("/trend")
    async def get_trend(
        project_id: Optional[str] = None,
        days: int = Query(30, ge=1, le=365),
    ):
        """获取误报率趋势报告"""
        engine = await _get_stats_engine()
        report = await engine.get_trend_report(project_id, days)
        return report

    @router.get("/optimization-report")
    async def get_optimization_report(project_id: Optional[str] = None):
        """获取优化效果报告"""
        engine = await _get_stats_engine()
        report = await engine.get_optimization_report(project_id)
        return report

    @router.get("/predictions")
    async def get_predictions(project_id: Optional[str] = None):
        """获取误报率预测"""
        engine = await _get_stats_engine()
        preds = await engine.get_predictions(project_id)
        return preds

    @router.get("/recommendations")
    async def get_recommendations(project_id: Optional[str] = None):
        """获取优化建议"""
        engine = await _get_stats_engine()
        recs = await engine.get_recommendations(project_id)
        return {"status": "ok", "recommendations": recs}

    # ═══════════════════ 优化接口 ═══════════════════

    @router.post("/optimize")
    async def trigger_optimization(req: OptimizeRequest):
        """触发自动优化"""
        from ..fp_optimize.models import OptimizationStatus

        engine = await _get_feedback_engine()
        result = await engine.analyze_and_optimize(
            project_id=req.project_id,
            dry_run=req.dry_run,
        )
        return result

    @router.get("/optimizations")
    async def list_optimizations(
        status_filter: Optional[str] = Query(None, alias="status"),
        limit: int = Query(50, ge=1, le=200),
    ):
        """列出优化记录"""
        store = await _get_store()
        records = await store.list_optimizations(
            status=status_filter,
            limit=limit,
        )
        return {"status": "ok", "optimizations": records}

    @router.get("/fp-patterns")
    async def get_fp_patterns(
        project_id: Optional[str] = None,
        min_confidence: float = Query(0.6, ge=0.0, le=1.0),
    ):
        """识别系统性误报模式"""
        engine = await _get_feedback_engine()
        patterns = await engine.identify_fp_patterns(project_id, min_confidence)
        return {"status": "ok", "patterns": patterns}

    # ═══════════════════ 个性化模型接口 ═══════════════════

    @router.get("/profile")
    async def get_profile(project_id: str = Query(..., description="项目ID")):
        """获取代码风格画像"""
        engine = await _get_personalization_engine()
        profile = await engine.get_profile(project_id)
        if profile is None:
            return {
                "status": "no_profile",
                "message": "尚未构建代码风格画像",
            }
        return {"status": "ok", "profile": profile.model_dump()}

    @router.post("/profile/build")
    async def build_profile(project_id: str = Query(..., description="项目ID")):
        """构建/重新构建代码风格画像"""
        engine = await _get_personalization_engine()
        profile = await engine.build_profile(project_id)
        return {"status": "ok", "profile": profile.model_dump()}

    @router.get("/profile/adjustments")
    async def get_adjustments(project_id: str = Query(..., description="项目ID")):
        """获取个性化调整策略"""
        engine = await _get_personalization_engine()
        summary = await engine.get_optimization_summary(project_id)
        return summary

    # ═══════════════════ 误报指纹接口 ═══════════════════

    @router.get("/fp-fingerprints")
    async def get_fp_fingerprints(project_id: Optional[str] = None):
        """获取已标记为误报的指纹列表"""
        store = await _get_store()
        fps = await store.get_fp_fingerprints(project_id)
        return {"status": "ok", "fp_fingerprints": fps, "count": len(fps)}

    return router
