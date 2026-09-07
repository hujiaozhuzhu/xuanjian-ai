"""
玄鉴 v2.5.0 — 企业任务管理模块 (Enterprise Task Management)

数据模型定义：扫描任务分配、漏洞修复跟踪、修复结果评审、任务进度统计
支持多项目、多用户的任务管理，状态流转清晰可追溯。

安全红线：
- S1: 零网络请求，纯本地 SQLite
- S2: 不修改被扫描源代码
- S7: 数据库路径固定于 ~/.xuanjian/
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ─────────────────────────── 枚举 ───────────────────────────

class TaskType(str, Enum):
    """任务类型"""
    SCAN = "scan"                           # 扫描任务
    VULN_FIX = "vuln_fix"                   # 漏洞修复
    FIX_REVIEW = "fix_review"               # 修复评审
    RETEST = "retest"                       # 复测


class TaskStatus(str, Enum):
    """任务状态"""
    PENDING = "pending"                     # 待处理
    ASSIGNED = "assigned"                   # 已分配
    IN_PROGRESS = "in_progress"             # 进行中
    FIX_SUBMITTED = "fix_submitted"         # 修复已提交
    UNDER_REVIEW = "under_review"           # 评审中
    DONE = "done"                           # 已完成
    CANCELLED = "cancelled"                 # 已取消


class TaskPriority(str, Enum):
    """任务优先级"""
    P0 = "P0"   # 紧急
    P1 = "P1"   # 高
    P2 = "P2"   # 中
    P3 = "P3"   # 低


class ReviewVerdict(str, Enum):
    """评审结论"""
    PASS = "pass"               # 通过
    NEEDS_WORK = "needs_work"   # 需要修改
    REJECT = "reject"           # 驳回


# ─────────────────────────── 状态流转规则 ───────────────────────────

VALID_TRANSITIONS: Dict[TaskStatus, List[TaskStatus]] = {
    TaskStatus.PENDING:        [TaskStatus.ASSIGNED, TaskStatus.CANCELLED],
    TaskStatus.ASSIGNED:       [TaskStatus.IN_PROGRESS, TaskStatus.CANCELLED],
    TaskStatus.IN_PROGRESS:    [TaskStatus.FIX_SUBMITTED, TaskStatus.CANCELLED],
    TaskStatus.FIX_SUBMITTED:  [TaskStatus.UNDER_REVIEW, TaskStatus.CANCELLED],
    TaskStatus.UNDER_REVIEW:   [TaskStatus.DONE, TaskStatus.IN_PROGRESS, TaskStatus.CANCELLED],
    TaskStatus.DONE:           [],
    TaskStatus.CANCELLED:      [],
}

STATUS_ROLE_MAP: Dict[TaskStatus, List[str]] = {
    TaskStatus.PENDING:        ["admin", "manager"],
    TaskStatus.ASSIGNED:       ["admin", "manager", "developer"],
    TaskStatus.IN_PROGRESS:    ["admin", "manager", "developer"],
    TaskStatus.FIX_SUBMITTED:  ["admin", "manager", "developer"],
    TaskStatus.UNDER_REVIEW:   ["admin", "manager", "reviewer"],
    TaskStatus.DONE:           [],
    TaskStatus.CANCELLED:      [],
}


# ─────────────────────────── 核心模型 ───────────────────────────

def _now_iso() -> str:
    """获取当前 UTC ISO8601 时间戳"""
    return datetime.now(timezone.utc).isoformat()


class Task(BaseModel):
    """扫描/修复/评审任务"""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="任务唯一 ID (uuid)")
    project_id: str = Field(..., description="关联项目 ID")
    project_name: str = Field("", description="项目名称（冗余存储便于查询）")
    task_type: TaskType = Field(..., description="任务类型")
    status: TaskStatus = Field(default=TaskStatus.PENDING, description="当前状态")
    priority: TaskPriority = Field(default=TaskPriority.P2, description="优先级")

    # 分配
    assigned_to: Optional[str] = Field(None, description="被指派人用户 ID")
    assigned_by: Optional[str] = Field(None, description="分配人用户 ID")

    # 关联
    finding_id: Optional[str] = Field(None, description="关联 Finding ID")
    finding_rule_id: Optional[str] = Field(None, description="关联 Finding 规则 ID")
    finding_severity: Optional[str] = Field(None, description="关联 Finding 严重度")
    finding_file_path: Optional[str] = Field(None, description="关联 Finding 文件路径")
    finding_line_start: Optional[int] = Field(None, description="关联 Finding 起始行")

    # 内容
    title: str = Field(..., description="任务标题")
    description: str = Field("", description="任务详细描述")

    # 修复
    fix_diff: Optional[str] = Field(None, description="修复 diff 字符串（仅展示，不直接修改代码）")
    fix_commit_hash: Optional[str] = Field(None, description="修复提交 hash")
    fix_notes: Optional[str] = Field(None, description="修复备注")

    # 评审
    review_verdict: Optional[ReviewVerdict] = Field(None, description="评审结论")
    review_comment: Optional[str] = Field(None, description="评审意见")
    reviewed_by: Optional[str] = Field(None, description="评审人用户 ID")
    reviewed_at: Optional[str] = Field(None, description="评审时间 ISO8601")

    # 时间戳
    created_at: str = Field(default_factory=_now_iso, description="创建时间 ISO8601")
    updated_at: str = Field(default_factory=_now_iso, description="更新时间 ISO8601")
    due_date: Optional[str] = Field(None, description="截止日期 ISO8601")
    completed_at: Optional[str] = Field(None, description="完成时间 ISO8601")

    # 元数据
    tags: List[str] = Field(default_factory=list, description="标签")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="额外元数据")


class TaskTransition(BaseModel):
    """任务状态流转记录（审计追溯）"""
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = Field(None, description="记录 ID")
    task_id: str = Field(..., description="关联任务 ID")
    from_status: Optional[str] = Field(None, description="变更前状态")
    to_status: str = Field(..., description="变更后状态")
    operator: Optional[str] = Field(None, description="操作人用户 ID")
    operator_role: Optional[str] = Field(None, description="操作人角色")
    comment: Optional[str] = Field(None, description="变更备注")
    created_at: str = Field(default_factory=_now_iso, description="变更时间")


class TaskComment(BaseModel):
    """任务评论 / 协作记录"""
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = Field(None, description="评论 ID")
    task_id: str = Field(..., description="关联任务 ID")
    author: Optional[str] = Field(None, description="评论人用户 ID")
    content: str = Field(..., description="评论内容")
    created_at: str = Field(default_factory=_now_iso, description="评论时间")


class TaskStats(BaseModel):
    """任务进度统计"""
    model_config = ConfigDict(extra="ignore")

    project_id: Optional[str] = Field(None, description="项目 ID (None 表示全局)")
    project_name: str = Field("", description="项目名称")
    total_tasks: int = Field(0, description="总任务数")
    by_status: Dict[str, int] = Field(default_factory=dict, description="按状态分组计数")
    by_priority: Dict[str, int] = Field(default_factory=dict, description="按优先级分组计数")
    by_type: Dict[str, int] = Field(default_factory=dict, description="按类型分组计数")
    by_assignee: Dict[str, int] = Field(default_factory=dict, description="按指派人分组计数")
    by_severity: Dict[str, int] = Field(default_factory=dict, description="按严重度分组计数")
    done_count: int = Field(0, description="已完成数")
    cancelled_count: int = Field(0, description="已取消数")
    overdue_count: int = Field(0, description="逾期数")
    completion_rate: float = Field(0.0, description="完成率 0-1")
    avg_resolution_hours: float = Field(0.0, description="平均解决耗时（小时）")


class TaskAssignmentRequest(BaseModel):
    """任务分配请求"""
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., description="任务 ID")
    assigned_to: str = Field(..., description="被指派人")
    assigned_by: str = Field("", description="分配人")
    comment: Optional[str] = Field(None, description="分配备注")


class TaskStatusChangeRequest(BaseModel):
    """任务状态变更请求"""
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., description="任务 ID")
    new_status: TaskStatus = Field(..., description="目标状态")
    operator: str = Field("", description="操作人")
    operator_role: str = Field("developer", description="操作人角色")
    comment: Optional[str] = Field(None, description="变更备注")
    fix_diff: Optional[str] = Field(None, description="修复 diff（提交修复时）")
    fix_commit_hash: Optional[str] = Field(None, description="修复提交 hash")
    fix_notes: Optional[str] = Field(None, description="修复备注")


class TaskReviewRequest(BaseModel):
    """修复评审请求"""
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., description="任务 ID")
    verdict: ReviewVerdict = Field(..., description="评审结论")
    reviewer: str = Field("", description="评审人")
    comment: Optional[str] = Field(None, description="评审意见")


class TaskQueryParams(BaseModel):
    """任务查询参数"""
    model_config = ConfigDict(extra="forbid")

    project_id: Optional[str] = None
    status: Optional[TaskStatus] = None
    task_type: Optional[TaskType] = None
    priority: Optional[TaskPriority] = None
    assigned_to: Optional[str] = None
    finding_severity: Optional[str] = None
    tags: Optional[List[str]] = None
    since: Optional[str] = None
    until: Optional[str] = None
    limit: int = Field(50, ge=1, le=500)
    offset: int = Field(0, ge=0)


class BulkCreateRequest(BaseModel):
    """批量创建任务请求（从扫描发现自动创建修复任务）"""
    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(..., description="项目 ID")
    finding_ids: List[str] = Field(..., description="关联 Finding ID 列表")
    priority: TaskPriority = Field(default=TaskPriority.P2, description="优先级")
    assigned_to: Optional[str] = Field(None, description="初始指派人")
    assigned_by: Optional[str] = Field(None, description="分配人")
    due_date: Optional[str] = Field(None, description="截止日期")
    tags: List[str] = Field(default_factory=list, description="标签")
