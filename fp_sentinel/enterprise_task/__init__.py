"""
玄鉴 v2.5.0 — 企业任务管理模块 (Enterprise Task Management)

扫描任务分配、漏洞修复跟踪、修复结果评审、任务进度统计
支持多项目、多用户的任务管理，状态流转清晰可追溯

安全红线：
- S1: 零网络请求，纯本地 SQLite
- S2: 不修改被扫描源代码（fix_diff 仅做展示）
- S7: 数据库路径固定于 ~/.xuanjian/
"""

from .models import (
    ReviewVerdict,
    STATUS_ROLE_MAP,
    Task,
    TaskAssignmentRequest,
    TaskComment,
    TaskPriority,
    TaskQueryParams,
    TaskStats,
    TaskStatus,
    TaskTransition,
    TaskType,
    VALID_TRANSITIONS,
)
from .repository import TaskCommentRepo, TaskRepo, TaskTransitionRepo
from .service import (
    InvalidTransitionError,
    PermissionDeniedError,
    TaskError,
    TaskNotFoundError,
    TaskService,
)

__all__ = [
    "Task",
    "TaskTransition",
    "TaskComment",
    "TaskStats",
    "TaskType",
    "TaskStatus",
    "TaskPriority",
    "ReviewVerdict",
    "TaskQueryParams",
    "TaskAssignmentRequest",
    "TaskReviewRequest",
    "VALID_TRANSITIONS",
    "STATUS_ROLE_MAP",
    "TaskRepo",
    "TaskTransitionRepo",
    "TaskCommentRepo",
    "TaskService",
    "TaskError",
    "InvalidTransitionError",
    "PermissionDeniedError",
    "TaskNotFoundError",
]
