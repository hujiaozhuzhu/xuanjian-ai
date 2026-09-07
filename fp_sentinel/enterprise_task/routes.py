"""
企业任务管理 - REST API 路由

提供 /api/tasks/* 端点，支持完整 CRUD 与状态流转

安全红线:
- S1: 零网络请求
- S2: 不修改源代码
- S7: 数据库路径固定于 ~/.xuanjian/
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from ..config import load_config, expand_db_path
from ..database import get_database
from .models import (
    BulkCreateRequest,
    TaskAssignmentRequest,
    TaskPriority,
    TaskQueryParams,
    TaskReviewRequest,
    TaskStatus,
    TaskStatusChangeRequest,
    TaskType,
)
from .repository import TaskCommentRepo, TaskRepo, TaskTransitionRepo
from .service import (
    InvalidTransitionError,
    PermissionDeniedError,
    TaskError,
    TaskNotFoundError,
    TaskService,
)

logger = logging.getLogger(__name__)

task_router = APIRouter(prefix="/api/tasks", tags=["enterprise-tasks"])


def _build_service(db) -> TaskService:
    """从数据库连接构建 TaskService"""
    task_repo = TaskRepo(db.conn)
    transition_repo = TaskTransitionRepo(db.conn)
    comment_repo = TaskCommentRepo(db.conn)
    return TaskService(task_repo, transition_repo, comment_repo)


# ─────────────────────── 创建 ───────────────────────

@task_router.post("/create")
async def create_task(request: dict):
    """创建任务"""
    config = load_config()
    db_path = expand_db_path(config.database.path)

    async with get_database(db_path) as db:
        service = _build_service(db)
        task = await service.create_task(
            project_id=request["project_id"],
            title=request["title"],
            task_type=TaskType(request.get("task_type", "scan")),
            description=request.get("description", ""),
            priority=TaskPriority(request.get("priority", "P2")),
            finding_id=request.get("finding_id"),
            finding_rule_id=request.get("finding_rule_id"),
            finding_severity=request.get("finding_severity"),
            finding_file_path=request.get("finding_file_path"),
            finding_line_start=request.get("finding_line_start"),
            assigned_to=request.get("assigned_to"),
            assigned_by=request.get("assigned_by"),
            due_date=request.get("due_date"),
            tags=request.get("tags", []),
            project_name=request.get("project_name", ""),
        )
        return {"status": "ok", "task": task.model_dump()}


@task_router.post("/bulk-create")
async def bulk_create(request: BulkCreateRequest):
    """从扫描发现批量创建修复任务"""
    config = load_config()
    db_path = expand_db_path(config.database.path)

    async with get_database(db_path) as db:
        service = _build_service(db)
        count, tasks = await service.bulk_create_from_findings(request)
        return {
            "status": "ok",
            "created": count,
            "tasks": [t.model_dump() for t in tasks],
        }


# ─────────────────────── 查询 ───────────────────────

@task_router.get("/list")
async def list_tasks(
    project_id: Optional[str] = None,
    status: Optional[str] = None,
    task_type: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """查询任务列表"""
    config = load_config()
    db_path = expand_db_path(config.database.path)

    async with get_database(db_path) as db:
        service = _build_service(db)
        params = TaskQueryParams(
            project_id=project_id,
            status=TaskStatus(status) if status else None,
            task_type=TaskType(task_type) if task_type else None,
            priority=TaskPriority(priority) if priority else None,
            assigned_to=assigned_to,
            finding_severity=severity,
            limit=limit,
            offset=offset,
        )
        tasks = await service.list_tasks(params)
        return {"status": "ok", "total": len(tasks), "tasks": [t.model_dump() for t in tasks]}


@task_router.get("/{task_id}")
async def get_task(task_id: str):
    """获取任务详情 + 时间线"""
    config = load_config()
    db_path = expand_db_path(config.database.path)

    async with get_database(db_path) as db:
        service = _build_service(db)
        try:
            timeline = await service.get_task_timeline(task_id)
            return {"status": "ok", **timeline}
        except TaskNotFoundError:
            raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")


@task_router.get("/{task_id}/transitions")
async def get_transitions(task_id: str):
    """获取任务状态流转记录"""
    config = load_config()
    db_path = expand_db_path(config.database.path)

    async with get_database(db_path) as db:
        service = _build_service(db)
        transitions = await service.get_task_transitions(task_id)
        return {"status": "ok", "transitions": [t.model_dump() for t in transitions]}


# ─────────────────────── 操作 ───────────────────────

@task_router.post("/assign")
async def assign_task(request: TaskAssignmentRequest):
    """分配任务"""
    config = load_config()
    db_path = expand_db_path(config.database.path)

    async with get_database(db_path) as db:
        service = _build_service(db)
        try:
            task = await service.assign_task(request)
            return {"status": "ok", "task": task.model_dump()}
        except (TaskNotFoundError, TaskError) as e:
            raise HTTPException(status_code=400, detail=str(e.message))


@task_router.post("/change-status")
async def change_status(request: dict):
    """变更任务状态"""
    config = load_config()
    db_path = expand_db_path(config.database.path)

    async with get_database(db_path) as db:
        service = _build_service(db)
        req = TaskStatusChangeRequest(**request)
        try:
            task = await service.change_status(req)
            return {"status": "ok", "task": task.model_dump()}
        except TaskNotFoundError:
            raise HTTPException(status_code=404, detail="任务不存在")
        except (InvalidTransitionError, PermissionDeniedError, TaskError) as e:
            raise HTTPException(status_code=400, detail=str(e.message))


@task_router.post("/review")
async def review_task(request: dict):
    """评审修复"""
    config = load_config()
    db_path = expand_db_path(config.database.path)

    async with get_database(db_path) as db:
        service = _build_service(db)
        req = TaskReviewRequest(**request)
        try:
            task = await service.review_task(req)
            return {"status": "ok", "task": task.model_dump()}
        except (TaskNotFoundError, TaskError) as e:
            raise HTTPException(status_code=400, detail=str(e.message))


@task_router.post("/{task_id}/comment")
async def add_comment(task_id: str, request: dict):
    """添加评论"""
    config = load_config()
    db_path = expand_db_path(config.database.path)

    async with get_database(db_path) as db:
        service = _build_service(db)
        try:
            cmt = await service.add_comment(
                task_id, request["content"], request.get("author")
            )
            return {"status": "ok", "comment": cmt.model_dump()}
        except TaskNotFoundError:
            raise HTTPException(status_code=404, detail="任务不存在")


# ─────────────────────── 统计 ───────────────────────

@task_router.get("/stats/summary")
async def get_stats(project_id: Optional[str] = None):
    """任务进度统计"""
    config = load_config()
    db_path = expand_db_path(config.database.path)

    async with get_database(db_path) as db:
        service = _build_service(db)
        stats = await service.get_stats(project_id)
        return {"status": "ok", "stats": stats.model_dump()}


@task_router.get("/transitions/valid")
async def valid_transitions():
    """返回所有合法状态流转"""
    config = load_config()
    db_path = expand_db_path(config.database.path)

    async with get_database(db_path) as db:
        service = _build_service(db)
        return {"status": "ok", "transitions": service.get_valid_transitions()}
