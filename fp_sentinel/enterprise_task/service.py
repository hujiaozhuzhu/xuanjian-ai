"""
企业任务管理 - 业务逻辑层

实现：扫描任务分配、漏洞修复跟踪、修复结果评审、任务进度统计
状态流转可追溯，多项目多用户支持
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .models import (
    BulkCreateRequest,
    ReviewVerdict,
    STATUS_ROLE_MAP,
    Task,
    TaskAssignmentRequest,
    TaskComment,
    TaskPriority,
    TaskQueryParams,
    TaskReviewRequest,
    TaskStats,
    TaskStatus,
    TaskStatusChangeRequest,
    TaskTransition,
    TaskType,
    VALID_TRANSITIONS,
)
from .repository import TaskCommentRepo, TaskRepo, TaskTransitionRepo

logger = logging.getLogger(__name__)


class TaskError(Exception):
    """任务操作异常基类"""
    def __init__(self, message: str, code: str = "TASK_ERROR"):
        self.message = message
        self.code = code
        super().__init__(message)


class InvalidTransitionError(TaskError):
    """不合法的状态流转"""
    def __init__(self, from_status: str, to_status: str):
        super().__init__(
            f"非法状态流转: {from_status} -> {to_status}",
            code="INVALID_TRANSITION",
        )


class PermissionDeniedError(TaskError):
    """角色权限不足"""
    def __init__(self, role: str, status: str):
        super().__init__(
            f"角色 '{role}' 无权操作状态 '{status}' 的任务",
            code="PERMISSION_DENIED",
        )


class TaskNotFoundError(TaskError):
    """任务不存在"""
    def __init__(self, task_id: str):
        super().__init__(f"任务不存在: {task_id}", code="TASK_NOT_FOUND")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(dt_str: str) -> Optional[datetime]:
    """解析 ISO8601 时间字符串"""
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str)
    except ValueError:
        return None


class TaskService:
    """任务管理服务"""

    def __init__(
        self,
        task_repo: TaskRepo,
        transition_repo: TaskTransitionRepo,
        comment_repo: TaskCommentRepo,
    ):
        self.tasks = task_repo
        self.transitions = transition_repo
        self.comments = comment_repo

    # ─────────────────────── 创建 ───────────────────────

    async def create_task(
        self,
        project_id: str,
        title: str,
        task_type: TaskType,
        description: str = "",
        priority: TaskPriority = TaskPriority.P2,
        finding_id: Optional[str] = None,
        finding_rule_id: Optional[str] = None,
        finding_severity: Optional[str] = None,
        finding_file_path: Optional[str] = None,
        finding_line_start: Optional[int] = None,
        assigned_to: Optional[str] = None,
        assigned_by: Optional[str] = None,
        due_date: Optional[str] = None,
        tags: Optional[List[str]] = None,
        project_name: str = "",
    ) -> Task:
        """创建单个任务"""
        now = _now_iso()
        initial_status = TaskStatus.ASSIGNED if assigned_to else TaskStatus.PENDING

        task = Task(
            id="",
            project_id=project_id,
            project_name=project_name,
            task_type=task_type,
            status=initial_status,
            priority=priority,
            assigned_to=assigned_to,
            assigned_by=assigned_by,
            finding_id=finding_id,
            finding_rule_id=finding_rule_id,
            finding_severity=finding_severity,
            finding_file_path=finding_file_path,
            finding_line_start=finding_line_start,
            title=title,
            description=description,
            due_date=due_date,
            tags=tags or [],
            created_at=now,
            updated_at=now,
        )

        saved = await self.tasks.create(task)

        # 记录初始状态流转
        await self.transitions.record(
            task_id=saved.id,
            to_status=initial_status.value,
            from_status=None,
            operator=assigned_by,
            operator_role="system",
            comment="创建任务",
        )

        return saved

    async def bulk_create_from_findings(
        self,
        request: BulkCreateRequest,
    ) -> Tuple[int, List[Task]]:
        """
        从扫描发现批量创建修复任务。
        跳过已有未完成任务的 finding_id（幂等）。
        返回: (实际创建数, 创建的任务列表)
        """
        created_tasks = []
        skipped = 0

        for fid in request.finding_ids:
            # 检查是否已存在未完成的任务
            existing = await self.tasks.find_by_finding_id(fid)
            if existing:
                skipped += 1
                continue

            task = Task(
                id="",
                project_id=request.project_id,
                task_type=TaskType.VULN_FIX,
                status=TaskStatus.PENDING,
                priority=request.priority,
                finding_id=fid,
                title=f"修复漏洞: {fid}",
                description=f"关联 Finding 自动生成的修复任务",
                assigned_to=request.assigned_to,
                assigned_by=request.assigned_by,
                due_date=request.due_date,
                tags=request.tags,
            )
            task.created_at = _now_iso()
            task.updated_at = _now_iso()
            saved = await self.tasks.create(task)
            created_tasks.append(saved)

            await self.transitions.record(
                task_id=saved.id,
                to_status=TaskStatus.PENDING.value,
                operator=request.assigned_by,
                operator_role="system",
                comment="从扫描发现自动创建",
            )

        return len(created_tasks), created_tasks

    # ─────────────────────── 分配 ───────────────────────

    async def assign_task(self, request: TaskAssignmentRequest) -> Task:
        """分配任务给指定用户"""
        task = await self.tasks.get_by_id(request.task_id)
        if not task:
            raise TaskNotFoundError(request.task_id)

        if task.status in (TaskStatus.DONE, TaskStatus.CANCELLED):
            raise TaskError(
                f"无法分配已{ '完成' if task.status == TaskStatus.DONE else '取消' }的任务",
                code="TASK_FINALIZED",
            )

        assigned_by = request.assigned_by or task.assigned_by or "system"

        await self.tasks.update(
            task.id,
            assigned_to=request.assigned_to,
            assigned_by=assigned_by,
        )

        new_status = TaskStatus.ASSIGNED if task.status == TaskStatus.PENDING else task.status
        if new_status != task.status:
            await self.tasks.update(task.id, status=new_status)
            await self.transitions.record(
                task_id=task.id,
                to_status=new_status.value,
                from_status=task.status.value,
                operator=assigned_by,
                operator_role="manager",
                comment=request.comment or f"分配给 {request.assigned_to}",
            )
        else:
            await self.transitions.record(
                task_id=task.id,
                to_status=task.status.value,
                from_status=task.status.value,
                operator=assigned_by,
                operator_role="manager",
                comment=request.comment or f"重新分配给 {request.assigned_to}",
            )

        return await self.tasks.get_by_id(request.task_id)

    # ─────────────────────── 状态流转 ───────────────────────

    async def change_status(self, request: TaskStatusChangeRequest) -> Task:
        """
        变更任务状态（驱动状态机）
        - 校验流转合法性
        - 校验角色权限
        - 自动处理修复提交、完成时间戳
        """
        task = await self.tasks.get_by_id(request.task_id)
        if not task:
            raise TaskNotFoundError(request.task_id)

        new_status = request.new_status
        old_status = task.status

        # 1. 校验流转合法性
        allowed = VALID_TRANSITIONS.get(old_status, [])
        if new_status not in allowed:
            raise InvalidTransitionError(old_status.value, new_status.value)

        # 2. 校验角色权限
        allowed_roles = STATUS_ROLE_MAP.get(old_status, [])
        if request.operator_role not in allowed_roles:
            raise PermissionDeniedError(request.operator_role, old_status.value)

        # 3. 准备更新字段
        update_fields: Dict = {"status": new_status}

        # 提交修复
        if new_status == TaskStatus.FIX_SUBMITTED:
            if request.fix_diff:
                update_fields["fix_diff"] = request.fix_diff
            if request.fix_commit_hash:
                update_fields["fix_commit_hash"] = request.fix_commit_hash
            if request.fix_notes:
                update_fields["fix_notes"] = request.fix_notes

        # 完成
        if new_status == TaskStatus.DONE:
            update_fields["completed_at"] = _now_iso()

        # 评审驳回 -> 回到进行中
        if new_status == TaskStatus.IN_PROGRESS and old_status == TaskStatus.UNDER_REVIEW:
            update_fields["review_verdict"] = None
            update_fields["review_comment"] = None
            update_fields["reviewed_by"] = None
            update_fields["reviewed_at"] = None

        # 4. 执行更新
        await self.tasks.update(task.id, **update_fields)

        # 5. 记录流转
        await self.transitions.record(
            task_id=task.id,
            to_status=new_status.value,
            from_status=old_status.value,
            operator=request.operator,
            operator_role=request.operator_role,
            comment=request.comment,
        )

        return await self.tasks.get_by_id(request.task_id)

    # ─────────────────────── 评审 ───────────────────────

    async def submit_fix(
        self,
        task_id: str,
        fix_diff: str,
        operator: str,
        fix_commit_hash: Optional[str] = None,
        fix_notes: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> Task:
        """提交修复"""
        request = TaskStatusChangeRequest(
            task_id=task_id,
            new_status=TaskStatus.FIX_SUBMITTED,
            operator=operator,
            operator_role="developer",
            comment=comment or "提交修复",
            fix_diff=fix_diff,
            fix_commit_hash=fix_commit_hash,
            fix_notes=fix_notes,
        )
        return await self.change_status(request)

    async def start_progress(self, task_id: str, operator: str, comment: Optional[str] = None) -> Task:
        """开始处理（从 assigned -> in_progress 或从 under_review -> in_progress）"""
        task = await self.tasks.get_by_id(task_id)
        if not task:
            raise TaskNotFoundError(task_id)

        request = TaskStatusChangeRequest(
            task_id=task_id,
            new_status=TaskStatus.IN_PROGRESS,
            operator=operator,
            operator_role="developer",
            comment=comment or "开始处理",
        )
        return await self.change_status(request)

    async def submit_for_review(
        self, task_id: str, operator: str, comment: Optional[str] = None
    ) -> Task:
        """提交评审（fix_submitted -> under_review）"""
        request = TaskStatusChangeRequest(
            task_id=task_id,
            new_status=TaskStatus.UNDER_REVIEW,
            operator=operator,
            operator_role="developer",
            comment=comment or "提交评审",
        )
        return await self.change_status(request)

    async def review_task(self, request: TaskReviewRequest) -> Task:
        """评审修复结果"""
        task = await self.tasks.get_by_id(request.task_id)
        if not task:
            raise TaskNotFoundError(request.task_id)

        if task.status != TaskStatus.UNDER_REVIEW:
            raise TaskError(
                f"任务当前状态为 '{task.status.value}'，只有 'under_review' 状态可评审",
                code="NOT_UNDER_REVIEW",
            )

        now = _now_iso()
        verdict = request.verdict

        # 通过则完成，需修改或驳回则回到进行中
        if verdict == ReviewVerdict.PASS:
            new_status = TaskStatus.DONE
            update_fields = {
                "status": new_status,
                "review_verdict": verdict,
                "review_comment": request.comment,
                "reviewed_by": request.reviewer,
                "reviewed_at": now,
                "completed_at": now,
            }
        else:
            new_status = TaskStatus.IN_PROGRESS
            update_fields = {
                "status": new_status,
                "review_verdict": verdict,
                "review_comment": request.comment,
                "reviewed_by": request.reviewer,
                "reviewed_at": now,
            }

        await self.tasks.update(task.id, **update_fields)

        await self.transitions.record(
            task_id=task.id,
            to_status=new_status.value,
            from_status=task.status.value,
            operator=request.reviewer,
            operator_role="reviewer",
            comment=request.comment or f"评审: {verdict.value}",
        )

        return await self.tasks.get_by_id(request.task_id)

    async def cancel_task(
        self, task_id: str, operator: str, operator_role: str, comment: Optional[str] = None
    ) -> Task:
        """取消任务"""
        task = await self.tasks.get_by_id(task_id)
        if not task:
            raise TaskNotFoundError(task_id)

        if task.status in (TaskStatus.DONE, TaskStatus.CANCELLED):
            raise TaskError(
                f"无法取消已{'完成' if task.status == TaskStatus.DONE else '取消'}的任务",
                code="TASK_FINALIZED",
            )

        request = TaskStatusChangeRequest(
            task_id=task_id,
            new_status=TaskStatus.CANCELLED,
            operator=operator,
            operator_role=operator_role,
            comment=comment or "取消任务",
        )
        return await self.change_status(request)

    # ─────────────────────── 查询 ───────────────────────

    async def get_task(self, task_id: str) -> Optional[Task]:
        """获取单个任务"""
        return await self.tasks.get_by_id(task_id)

    async def list_tasks(self, params: TaskQueryParams) -> List[Task]:
        """多维度查询任务列表"""
        return await self.tasks.list_tasks(params)

    async def get_task_transitions(self, task_id: str) -> List[TaskTransition]:
        """获取任务的完整状态流转历史"""
        return await self.transitions.list_by_task(task_id)

    async def get_task_timeline(self, task_id: str) -> Dict:
        """获取任务完整时间线（任务 + 流转记录 + 评论）"""
        task = await self.tasks.get_by_id(task_id)
        if not task:
            raise TaskNotFoundError(task_id)

        transitions = await self.transitions.list_by_task(task_id)
        comments = await self.comments.list_by_task(task_id)

        return {
            "task": task.model_dump(),
            "transitions": [t.model_dump() for t in transitions],
            "comments": [c.model_dump() for c in comments],
        }

    # ─────────────────────── 评论 ───────────────────────

    async def add_comment(
        self, task_id: str, content: str, author: Optional[str] = None
    ) -> TaskComment:
        """添加任务评论"""
        task = await self.tasks.get_by_id(task_id)
        if not task:
            raise TaskNotFoundError(task_id)
        return await self.comments.add(task_id=task_id, content=content, author=author)

    async def list_comments(self, task_id: str) -> List[TaskComment]:
        """列出任务评论"""
        return await self.comments.list_by_task(task_id)

    # ─────────────────────── 统计 ───────────────────────

    async def get_stats(self, project_id: Optional[str] = None) -> TaskStats:
        """获取任务进度统计"""
        return await self.tasks.get_stats(project_id)

    async def get_multi_project_stats(self, project_ids: List[str]) -> Dict[str, TaskStats]:
        """获取多项目任务统计"""
        result = {}
        for pid in project_ids:
            result[pid] = await self.tasks.get_stats(pid)
        return result

    # ─────────────────────── 工具方法 ───────────────────────

    def get_allowed_actions(self, task_status: TaskStatus) -> List[str]:
        """获取某状态下允许的操作列表"""
        allowed = VALID_TRANSITIONS.get(task_status, [])
        return [s.value for s in allowed]

    def can_transition(self, from_status: TaskStatus, to_status: TaskStatus) -> bool:
        """检查状态流转是否合法"""
        allowed = VALID_TRANSITIONS.get(from_status, [])
        return to_status in allowed

    @staticmethod
    def get_valid_transitions() -> Dict[str, List[str]]:
        """返回所有合法状态流转（供 API/CLI 展示）"""
        return {
            k.value: [s.value for s in v] for k, v in VALID_TRANSITIONS.items()
        }
