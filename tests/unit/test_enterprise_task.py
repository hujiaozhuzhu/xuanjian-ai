"""
test_enterprise_task — 企业任务管理模块全量单元测试

覆盖：models / repository / service / CLI
安全红线：S1 零网络, S2 不修改代码, S7 固定路径
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from fp_sentinel.enterprise_task.models import (
    VALID_TRANSITIONS,
    BulkCreateRequest,
    ReviewVerdict,
    STATUS_ROLE_MAP,
    Task,
    TaskAssignmentRequest,
    TaskComment,
    TaskPriority,
    TaskQueryParams,
    TaskReviewRequest,
    TaskStatus,
    TaskStats,
    TaskTransition,
    TaskType,
)
from fp_sentinel.enterprise_task.repository import (
    TaskCommentRepo,
    TaskRepo,
    TaskTransitionRepo,
)
from fp_sentinel.enterprise_task.service import (
    InvalidTransitionError,
    PermissionDeniedError,
    TaskError,
    TaskNotFoundError,
    TaskService,
)


# ─────────────────────── Fixtures ───────────────────────

@pytest.fixture
def tmp_db_path(tmp_path):
    """临时数据库路径"""
    return str(tmp_path / "test_et.db")


@pytest.fixture
def event_loop():
    """创建事件循环"""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def repo(tmp_db_path):
    """创建 TaskRepo（同步，手动管理连接）"""
    import sqlite3
    conn = sqlite3.connect(tmp_db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    r = TaskRepo.__new__(TaskRepo)
    # Use aiosqlite connection instead - we need to use the async version
    conn.close()
    return tmp_db_path


@pytest.fixture
async def async_repo(tmp_path):
    """异步 TaskRepo"""
    import aiosqlite
    db_path = str(tmp_path / "test_et.db")
    conn = await aiosqlite.connect(db_path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA foreign_keys=ON")
    repo = TaskRepo(conn)
    await repo.initialize_schema()
    yield repo
    await conn.close()


@pytest.fixture
async def async_transition_repo(async_repo):
    """共享同一个连接的 TransitionRepo"""
    return TaskTransitionRepo(async_repo.conn)


@pytest.fixture
async def async_comment_repo(async_repo):
    """共享同一个连接的 CommentRepo"""
    return TaskCommentRepo(async_repo.conn)


@pytest.fixture
async def service(async_repo, async_transition_repo, async_comment_repo):
    """创建 TaskService"""
    return TaskService(async_repo, async_transition_repo, async_comment_repo)


# ─────────────────────── Models Tests ───────────────────────

class TestTaskModels:
    """任务模型测试"""

    def test_task_type_enum(self):
        assert TaskType.SCAN.value == "scan"
        assert TaskType.VULN_FIX.value == "vuln_fix"
        assert TaskType.FIX_REVIEW.value == "fix_review"
        assert TaskType.RETEST.value == "retest"

    def test_task_status_enum(self):
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.DONE.value == "done"
        assert TaskStatus.CANCELLED.value == "cancelled"

    def test_task_priority_enum(self):
        assert TaskPriority.P0.value == "P0"
        assert TaskPriority.P3.value == "P3"

    def test_review_verdict_enum(self):
        assert ReviewVerdict.PASS.value == "pass"
        assert ReviewVerdict.NEEDS_WORK.value == "needs_work"
        assert ReviewVerdict.REJECT.value == "reject"

    def test_valid_transitions_exist(self):
        assert VALID_TRANSITIONS[TaskStatus.PENDING] == [TaskStatus.ASSIGNED, TaskStatus.CANCELLED]
        assert VALID_TRANSITIONS[TaskStatus.DONE] == []
        assert VALID_TRANSITIONS[TaskStatus.CANCELLED] == []

    def test_status_role_map(self):
        assert "admin" in STATUS_ROLE_MAP[TaskStatus.PENDING]
        assert "developer" in STATUS_ROLE_MAP[TaskStatus.IN_PROGRESS]
        assert "developer" in STATUS_ROLE_MAP[TaskStatus.ASSIGNED]
        assert "reviewer" in STATUS_ROLE_MAP[TaskStatus.UNDER_REVIEW]

    def test_task_assignment_request(self):
        req = TaskAssignmentRequest(task_id="t1", assigned_to="user1")
        assert req.task_id == "t1"
        assert req.assigned_to == "user1"
        assert req.assigned_by == ""

    def test_task_assignment_request_forbid_extra(self):
        with pytest.raises(Exception):  # pydantic ValidationError
            TaskAssignmentRequest(task_id="t1", assigned_to="user1", unknown_field="x")

    def test_bulk_create_request(self):
        req = BulkCreateRequest(
            project_id="p1",
            finding_ids=["f1", "f2"],
            priority=TaskPriority.P1,
        )
        assert len(req.finding_ids) == 2
        assert req.priority == TaskPriority.P1

    def test_task_review_request(self):
        req = TaskReviewRequest(
            task_id="t1",
            verdict=ReviewVerdict.PASS,
            reviewer="rev1",
        )
        assert req.verdict == ReviewVerdict.PASS

    def test_task_query_params_defaults(self):
        params = TaskQueryParams()
        assert params.limit == 50
        assert params.offset == 0

    def test_task_query_params_custom(self):
        params = TaskQueryParams(limit=100, offset=10, status=TaskStatus.DONE)
        assert params.limit == 100
        assert params.status == TaskStatus.DONE

    def test_task_query_params_limit_bounds(self):
        with pytest.raises(Exception):
            TaskQueryParams(limit=0)
        with pytest.raises(Exception):
            TaskQueryParams(limit=501)


# ─────────────────────── Task Construction Tests ───────────────────────

class TestTaskConstruction:
    """Task 模型构建测试"""

    def test_create_minimal_task(self):
        task = Task(id="tid-1", project_id="proj-1", title="测试扫描", task_type=TaskType.SCAN)
        assert task.id == "tid-1"
        assert task.status == TaskStatus.PENDING
        assert task.priority == TaskPriority.P2
        assert task.task_type == TaskType.SCAN

    def test_create_full_task(self):
        task = Task(
            id="tid-2",
            project_id="proj-2",
            project_name="测试项目",
            task_type=TaskType.VULN_FIX,
            status=TaskStatus.ASSIGNED,
            priority=TaskPriority.P0,
            assigned_to="dev1",
            assigned_by="admin1",
            finding_id="finds-001",
            finding_rule_id="py.injection.sql",
            finding_severity="CRITICAL",
            finding_file_path="app/db.py",
            finding_line_start=42,
            title="修复SQL注入",
            description="修复 db.py 中的 SQL 注入漏洞",
            tags=["security", "sqli"],
            metadata={"source": "auto"},
        )
        assert task.task_type == TaskType.VULN_FIX
        assert task.assigned_to == "dev1"
        assert task.tags == ["security", "sqli"]
        assert task.metadata == {"source": "auto"}

    def test_task_timestamps_auto(self):
        task = Task(id="t1", project_id="p1", title="T", task_type=TaskType.SCAN)
        assert task.created_at
        assert task.updated_at

    def test_task_default_tags(self):
        task = Task(id="t1", project_id="p1", title="T", task_type=TaskType.SCAN)
        assert task.tags == []

    def test_task_tags_assignment(self):
        task = Task(id="t1", project_id="p1", title="T", task_type=TaskType.SCAN, tags=["a", "b"])
        assert len(task.tags) == 2


# ─────────────────────── Repository Tests ───────────────────────

class TestTaskRepository:
    """任务仓库测试"""

    @pytest.mark.asyncio
    async def test_create_task(self, async_repo):
        task = Task(id="", project_id="p1", title="扫描任务", task_type=TaskType.SCAN)
        task.created_at = datetime.now(timezone.utc).isoformat()
        task.updated_at = task.created_at
        saved = await async_repo.create(task)
        assert saved.id  # UUID generated
        assert saved.status == TaskStatus.PENDING

    @pytest.mark.asyncio
    async def test_get_by_id(self, async_repo):
        task = Task(id="", project_id="p1", title="测试", task_type=TaskType.SCAN)
        task.created_at = datetime.now(timezone.utc).isoformat()
        task.updated_at = task.created_at
        saved = await async_repo.create(task)
        fetched = await async_repo.get_by_id(saved.id)
        assert fetched is not None
        assert fetched.id == saved.id
        assert fetched.title == "测试"

    @pytest.mark.asyncio
    async def test_get_by_id_missing(self, async_repo):
        result = await async_repo.get_by_id("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_update_task(self, async_repo):
        task = Task(id="", project_id="p1", title="原始", task_type=TaskType.SCAN)
        task.created_at = datetime.now(timezone.utc).isoformat()
        task.updated_at = task.created_at
        saved = await async_repo.create(task)
        updated = await async_repo.update(saved.id, title="已修改", priority=TaskPriority.P0)
        assert updated is True
        fetched = await async_repo.get_by_id(saved.id)
        assert fetched.title == "已修改"
        assert fetched.priority == TaskPriority.P0

    @pytest.mark.asyncio
    async def test_delete_task(self, async_repo):
        task = Task(id="", project_id="p1", title="待删除", task_type=TaskType.SCAN)
        task.created_at = datetime.now(timezone.utc).isoformat()
        task.updated_at = task.created_at
        saved = await async_repo.create(task)
        result = await async_repo.delete(saved.id)
        assert result is True
        assert await async_repo.get_by_id(saved.id) is None

    @pytest.mark.asyncio
    async def test_list_tasks(self, async_repo):
        for i in range(3):
            t = Task(id="", project_id="p1", title=f"任务{i}", task_type=TaskType.SCAN)
            t.created_at = datetime.now(timezone.utc).isoformat()
            t.updated_at = t.created_at
            await async_repo.create(t)
        tasks = await async_repo.list_tasks(TaskQueryParams(limit=10))
        assert len(tasks) == 3

    @pytest.mark.asyncio
    async def test_list_tasks_with_filter(self, async_repo):
        t1 = Task(id="", project_id="p1", title="A", task_type=TaskType.SCAN, status=TaskStatus.DONE)
        t1.created_at = datetime.now(timezone.utc).isoformat()
        t1.updated_at = t1.created_at
        await async_repo.create(t1)

        t2 = Task(id="", project_id="p1", title="B", task_type=TaskType.SCAN, status=TaskStatus.PENDING)
        t2.created_at = datetime.now(timezone.utc).isoformat()
        t2.updated_at = t2.created_at
        await async_repo.create(t2)

        params = TaskQueryParams(status=TaskStatus.DONE)
        tasks = await async_repo.list_tasks(params)
        assert len(tasks) == 1
        assert tasks[0].status == TaskStatus.DONE

    @pytest.mark.asyncio
    async def test_count_with_filter(self, async_repo):
        for i in range(5):
            t = Task(id="", project_id="p1", title=f"P0-{i}", task_type=TaskType.SCAN, priority=TaskPriority.P0)
            t.created_at = datetime.now(timezone.utc).isoformat()
            t.updated_at = t.created_at
            await async_repo.create(t)
        params = TaskQueryParams(priority=TaskPriority.P0)
        count = await async_repo.count(params)
        assert count == 5

    @pytest.mark.asyncio
    async def test_find_by_finding_id(self, async_repo):
        t = Task(id="", project_id="p1", title="修复", task_type=TaskType.VULN_FIX, finding_id="find-001")
        t.created_at = datetime.now(timezone.utc).isoformat()
        t.updated_at = t.created_at
        await async_repo.create(t)
        found = await async_repo.find_by_finding_id("find-001")
        assert found is not None
        assert found.finding_id == "find-001"

    @pytest.mark.asyncio
    async def test_find_by_finding_id_excludes_done(self, async_repo):
        t = Task(id="", project_id="p1", title="修复", task_type=TaskType.VULN_FIX,
                 finding_id="find-002", status=TaskStatus.DONE)
        t.created_at = datetime.now(timezone.utc).isoformat()
        t.updated_at = t.created_at
        await async_repo.create(t)
        found = await async_repo.find_by_finding_id("find-002")
        assert found is None  # done task should be excluded

    @pytest.mark.asyncio
    async def test_tags_serialization_round_trip(self, async_repo):
        tags = ["security", "sql-injection", "high-priority"]
        t = Task(id="", project_id="p1", title="T", task_type=TaskType.SCAN, tags=tags)
        t.created_at = datetime.now(timezone.utc).isoformat()
        t.updated_at = t.created_at
        saved = await async_repo.create(t)
        fetched = await async_repo.get_by_id(saved.id)
        assert fetched.tags == tags

    @pytest.mark.asyncio
    async def test_metadata_serialization_round_trip(self, async_repo):
        meta = {"scanner": "semgrep", "rule_count": 3}
        t = Task(id="", project_id="p1", title="T", task_type=TaskType.SCAN, metadata=meta)
        t.created_at = datetime.now(timezone.utc).isoformat()
        t.updated_at = t.created_at
        saved = await async_repo.create(t)
        fetched = await async_repo.get_by_id(saved.id)
        assert fetched.metadata["scanner"] == "semgrep"
        assert fetched.metadata["rule_count"] == 3


class TestTaskTransitionRepo:
    """任务流转记录仓库测试"""

    @pytest.mark.asyncio
    async def test_record_transition(self, async_transition_repo, async_repo):
        t = Task(id="", project_id="p1", title="T", task_type=TaskType.SCAN,
                 status=TaskStatus.ASSIGNED)
        t.created_at = datetime.now(timezone.utc).isoformat()
        t.updated_at = t.created_at
        task = await async_repo.create(t)
        
        tr = await async_transition_repo.record(
            task_id=task.id,
            to_status=TaskStatus.IN_PROGRESS.value,
            from_status=TaskStatus.ASSIGNED.value,
            operator="dev1",
            operator_role="developer",
        )
        assert tr.task_id == task.id
        assert tr.to_status == TaskStatus.IN_PROGRESS.value

    @pytest.mark.asyncio
    async def test_list_by_task(self, async_transition_repo, async_repo):
        t = Task(id="", project_id="p1", title="T", task_type=TaskType.SCAN)
        t.created_at = datetime.now(timezone.utc).isoformat()
        t.updated_at = t.created_at
        task = await async_repo.create(t)
        
        await async_transition_repo.record(task.id, TaskStatus.PENDING.value)
        await async_transition_repo.record(task.id, TaskStatus.ASSIGNED.value, from_status=TaskStatus.PENDING.value)
        
        transitions = await async_transition_repo.list_by_task(task.id)
        assert len(transitions) == 2


class TestTaskCommentRepo:
    """任务评论仓库测试"""

    @pytest.mark.asyncio
    async def test_add_comment(self, async_comment_repo, async_repo):
        t = Task(id="", project_id="p1", title="T", task_type=TaskType.SCAN)
        t.created_at = datetime.now(timezone.utc).isoformat()
        t.updated_at = t.created_at
        task = await async_repo.create(t)
        
        cmt = await async_comment_repo.add(task.id, "这个漏洞需要优先修复", author="admin1")
        assert cmt.content == "这个漏洞需要优先修复"
        assert cmt.author == "admin1"

    @pytest.mark.asyncio
    async def test_list_by_task(self, async_comment_repo, async_repo):
        t = Task(id="", project_id="p1", title="T", task_type=TaskType.SCAN)
        t.created_at = datetime.now(timezone.utc).isoformat()
        t.updated_at = t.created_at
        task = await async_repo.create(t)
        
        await async_comment_repo.add(task.id, "评论1")
        await async_comment_repo.add(task.id, "评论2")
        
        comments = await async_comment_repo.list_by_task(task.id)
        assert len(comments) == 2


# ─────────────────────── Service Tests ───────────────────────

class TestTaskService:
    """任务服务业务逻辑测试"""

    @pytest.mark.asyncio
    async def test_create_task(self, service):
        task = await service.create_task(
            project_id="p1", title="新扫描任务", task_type=TaskType.SCAN,
            description="测试描述"
        )
        assert task.id
        assert task.status == TaskStatus.PENDING  # no assignee
        assert task.title == "新扫描任务"

    @pytest.mark.asyncio
    async def test_create_task_with_assignee(self, service):
        task = await service.create_task(
            project_id="p1", title="紧急修复", task_type=TaskType.VULN_FIX,
            assigned_to="dev1", assigned_by="admin1"
        )
        assert task.status == TaskStatus.ASSIGNED
        assert task.assigned_to == "dev1"

    @pytest.mark.asyncio
    async def test_create_task_with_finding_info(self, service):
        task = await service.create_task(
            project_id="p1", title="修复SQL注入", task_type=TaskType.VULN_FIX,
            finding_id="f-001", finding_rule_id="py.injection.sql",
            finding_severity="CRITICAL", finding_file_path="app/db.py",
            finding_line_start=42,
        )
        assert task.finding_id == "f-001"
        assert task.finding_severity == "CRITICAL"
        assert task.finding_file_path == "app/db.py"

    @pytest.mark.asyncio
    async def test_bulk_create_from_findings(self, service):
        request = BulkCreateRequest(
            project_id="p1",
            finding_ids=["f-001", "f-002", "f-003"],
            priority=TaskPriority.P1,
            assigned_to="dev1",
            assigned_by="admin1",
        )
        count, tasks = await service.bulk_create_from_findings(request)
        assert count == 3
        assert len(tasks) == 3
        for t in tasks:
            assert t.task_type == TaskType.VULN_FIX

    @pytest.mark.asyncio
    async def test_bulk_create_skips_existing(self, service):
        """幂等性：已有未完成任务的 finding 跳过"""
        await service.create_task(
            project_id="p1", title="已存在", task_type=TaskType.VULN_FIX, finding_id="f-001"
        )
        request = BulkCreateRequest(
            project_id="p1",
            finding_ids=["f-001", "f-002"],
        )
        count, tasks = await service.bulk_create_from_findings(request)
        assert count == 1
        assert tasks[0].finding_id == "f-002"

    @pytest.mark.asyncio
    async def test_assign_task(self, service):
        task = await service.create_task(project_id="p1", title="T", task_type=TaskType.SCAN)
        from fp_sentinel.enterprise_task.models import TaskAssignmentRequest
        req = TaskAssignmentRequest(
            task_id=task.id, assigned_to="dev1", assigned_by="admin1"
        )
        updated = await service.assign_task(req)
        assert updated.assigned_to == "dev1"
        assert updated.status == TaskStatus.ASSIGNED

    @pytest.mark.asyncio
    async def test_assign_not_found_raises(self, service):
        from fp_sentinel.enterprise_task.models import TaskAssignmentRequest
        req = TaskAssignmentRequest(task_id="missing", assigned_to="dev1")
        with pytest.raises(TaskNotFoundError):
            await service.assign_task(req)

    @pytest.mark.asyncio
    async def test_assign_done_task_raises(self, service):
        task = await service.create_task(project_id="p1", title="T", task_type=TaskType.SCAN)
        # Force to done via direct repo update
        await service.tasks.update(task.id, status=TaskStatus.DONE, completed_at=datetime.now(timezone.utc).isoformat())
        from fp_sentinel.enterprise_task.models import TaskAssignmentRequest
        req = TaskAssignmentRequest(task_id=task.id, assigned_to="dev1")
        with pytest.raises(TaskError):
            await service.assign_task(req)

    @pytest.mark.asyncio
    async def test_invalid_transition_raises(self, service):
        task = await service.create_task(
            project_id="p1", title="T", task_type=TaskType.SCAN,
            assigned_to="dev1"
        )  # status = ASSIGNED
        from fp_sentinel.enterprise_task.models import TaskStatusChangeRequest
        req = TaskStatusChangeRequest(
            task_id=task.id,
            new_status=TaskStatus.DONE,  # ASSIGNED -> DONE is invalid
            operator="dev1",
            operator_role="developer",
        )
        with pytest.raises(InvalidTransitionError):
            await service.change_status(req)

    @pytest.mark.asyncio
    async def test_permission_denied_raises(self, service):
        # Create without assignee so status stays PENDING
        task = await service.create_task(
            project_id="p1", title="T", task_type=TaskType.SCAN
        )  # status = PENDING (no assignee)
        assert task.status == TaskStatus.PENDING
        from fp_sentinel.enterprise_task.models import TaskStatusChangeRequest
        # developer cannot change PENDING -> only admin/manager can
        req = TaskStatusChangeRequest(
            task_id=task.id,
            new_status=TaskStatus.ASSIGNED,
            operator="dev1",
            operator_role="developer",
        )
        with pytest.raises(PermissionDeniedError):
            await service.change_status(req)

    @pytest.mark.asyncio
    async def test_full_lifecycle_happy_path(self, service):
        """完整生命周期: pending -> assigned -> in_progress -> fix_submitted -> under_review -> done"""
        # 1. 创建任务
        task = await service.create_task(
            project_id="p1", title="修复XSS", task_type=TaskType.VULN_FIX,
            assigned_to="dev1"
        )
        assert task.status == TaskStatus.ASSIGNED

        # 2. 开始处理
        task = await service.start_progress(task.id, "dev1", "开始修复")
        assert task.status == TaskStatus.IN_PROGRESS

        # 3. 提交修复
        task = await service.submit_fix(
            task.id, "diff --git a/app.py b/app.py...", "dev1",
            fix_commit_hash="abc123", fix_notes="使用参数化查询修复"
        )
        assert task.status == TaskStatus.FIX_SUBMITTED
        assert task.fix_diff.startswith("diff")
        assert task.fix_commit_hash == "abc123"

        # 4. 提交评审
        task = await service.submit_for_review(task.id, "dev1")
        assert task.status == TaskStatus.UNDER_REVIEW

        # 5. 评审通过
        req = TaskReviewRequest(
            task_id=task.id, verdict=ReviewVerdict.PASS, reviewer="rev1", comment="LGTM"
        )
        task = await service.review_task(req)
        assert task.status == TaskStatus.DONE
        assert task.review_verdict == ReviewVerdict.PASS
        assert task.completed_at is not None

        # 6. 验证时间线
        timeline = await service.get_task_timeline(task.id)
        assert timeline["task"]["id"] == task.id
        assert len(timeline["transitions"]) >= 5

    @pytest.mark.asyncio
    async def test_review_needs_work_loops_back(self, service):
        """评审需要修改 -> 回到 in_progress"""
        task = await service.create_task(
            project_id="p1", title="修复", task_type=TaskType.VULN_FIX, assigned_to="dev1"
        )
        task = await service.start_progress(task.id, "dev1")
        task = await service.submit_fix(task.id, "fix diff", "dev1")
        task = await service.submit_for_review(task.id, "dev1")

        req = TaskReviewRequest(
            task_id=task.id, verdict=ReviewVerdict.NEEDS_WORK,
            reviewer="rev1", comment="需要增加输入验证"
        )
        task = await service.review_task(req)
        assert task.status == TaskStatus.IN_PROGRESS
        assert task.review_verdict == ReviewVerdict.NEEDS_WORK
        assert task.completed_at is None  # not done

    @pytest.mark.asyncio
    async def test_review_reject_loops_back(self, service):
        """评审驳回 -> 回到 in_progress"""
        task = await service.create_task(
            project_id="p1", title="修复", task_type=TaskType.VULN_FIX, assigned_to="dev1"
        )
        task = await service.start_progress(task.id, "dev1")
        task = await service.submit_fix(task.id, "fix diff", "dev1")
        task = await service.submit_for_review(task.id, "dev1")

        req = TaskReviewRequest(
            task_id=task.id, verdict=ReviewVerdict.REJECT, reviewer="rev1",
            comment="修复不完整"
        )
        task = await service.review_task(req)
        assert task.status == TaskStatus.IN_PROGRESS

    @pytest.mark.asyncio
    async def test_review_wrong_status_raises(self, service):
        """非 under_review 状态不能评审"""
        task = await service.create_task(
            project_id="p1", title="修复", task_type=TaskType.VULN_FIX, assigned_to="dev1"
        )
        req = TaskReviewRequest(
            task_id=task.id, verdict=ReviewVerdict.PASS, reviewer="rev1"
        )
        with pytest.raises(TaskError) as exc:
            await service.review_task(req)
        assert "NOT_UNDER_REVIEW" in str(exc.value.code)

    @pytest.mark.asyncio
    async def test_cancel_task(self, service):
        task = await service.create_task(
            project_id="p1", title="测试", task_type=TaskType.SCAN
        )
        cancelled = await service.cancel_task(task.id, "admin1", "manager", "项目变更")
        assert cancelled.status == TaskStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_done_task_raises(self, service):
        task = await service.create_task(
            project_id="p1", title="T", task_type=TaskType.SCAN
        )
        await service.tasks.update(task.id, status=TaskStatus.DONE, completed_at=datetime.now(timezone.utc).isoformat())
        with pytest.raises(TaskError):
            await service.cancel_task(task.id, "admin1", "manager")

    @pytest.mark.asyncio
    async def test_get_allowed_actions(self, service):
        actions = service.get_allowed_actions(TaskStatus.IN_PROGRESS)
        assert TaskStatus.FIX_SUBMITTED.value in actions
        assert TaskStatus.CANCELLED.value in actions

    @pytest.mark.asyncio
    async def test_get_allowed_actions_for_terminal(self, service):
        actions = service.get_allowed_actions(TaskStatus.DONE)
        assert actions == []

    @pytest.mark.asyncio
    async def test_can_transition(self, service):
        assert service.can_transition(TaskStatus.PENDING, TaskStatus.ASSIGNED) is True
        assert service.can_transition(TaskStatus.PENDING, TaskStatus.DONE) is False
        assert service.can_transition(TaskStatus.DONE, TaskStatus.PENDING) is False

    @pytest.mark.asyncio
    async def test_get_valid_transitions(self, service):
        transitions = service.get_valid_transitions()
        assert "pending" in transitions
        assert "assigned" in transitions["pending"]
        assert transitions["done"] == []


# ─────────────────────── Statistics Tests ───────────────────────

class TestTaskStats:
    """任务统计测试"""

    @pytest.mark.asyncio
    async def test_get_stats_empty(self, service):
        stats = await service.get_stats()
        assert stats.total_tasks == 0
        assert stats.completion_rate == 0.0

    @pytest.mark.asyncio
    async def test_get_stats_with_tasks(self, service):
        # Create tasks in different statuses
        for i in range(5):
            t = await service.create_task(
                project_id="p1", title=f"扫描{i}", task_type=TaskType.SCAN,
                assigned_to="dev1"
            )
        stats = await service.get_stats("p1")
        assert stats.total_tasks == 5
        assert stats.by_status.get("assigned", 0) == 5
        assert stats.done_count == 0

    @pytest.mark.asyncio
    async def test_get_stats_completion_rate(self, service):
        # Create 4 tasks: 3 done, 1 pending
        for i in range(3):
            t = await service.create_task(
                project_id="p1", title=f"修复{i}", task_type=TaskType.VULN_FIX,
                assigned_to="dev1"
            )
            await service.start_progress(t.id, "dev1")
            await service.submit_fix(t.id, f"diff-{i}", "dev1")
            await service.submit_for_review(t.id, "dev1")
            req = TaskReviewRequest(task_id=t.id, verdict=ReviewVerdict.PASS, reviewer="rev1")
            await service.review_task(req)

        # 1 pending
        await service.create_task(project_id="p1", title="待办", task_type=TaskType.SCAN)

        stats = await service.get_stats("p1")
        assert stats.total_tasks == 4
        assert stats.done_count == 3
        assert stats.completion_rate == 0.75

    @pytest.mark.asyncio
    async def test_get_stats_by_priority(self, service):
        await service.create_task(
            project_id="p1", title="P0", task_type=TaskType.SCAN,
            priority=TaskPriority.P0, assigned_to="dev1"
        )
        await service.create_task(
            project_id="p1", title="P2", task_type=TaskType.SCAN,
            priority=TaskPriority.P2, assigned_to="dev1"
        )
        stats = await service.get_stats("p1")
        assert stats.by_priority["P0"] == 1
        assert stats.by_priority["P2"] == 1

    @pytest.mark.asyncio
    async def test_get_stats_by_type(self, service):
        await service.create_task(
            project_id="p1", title="扫描", task_type=TaskType.SCAN, assigned_to="dev1"
        )
        await service.create_task(
            project_id="p1", title="修复", task_type=TaskType.VULN_FIX, assigned_to="dev1"
        )
        stats = await service.get_stats("p1")
        assert stats.by_type["scan"] == 1
        assert stats.by_type["vuln_fix"] == 1

    @pytest.mark.asyncio
    async def test_get_stats_by_assignee(self, service):
        await service.create_task(
            project_id="p1", title="T1", task_type=TaskType.SCAN, assigned_to="dev1"
        )
        await service.create_task(
            project_id="p1", title="T2", task_type=TaskType.SCAN, assigned_to="dev2"
        )
        stats = await service.get_stats("p1")
        assert stats.by_assignee["dev1"] == 1
        assert stats.by_assignee["dev2"] == 1

    @pytest.mark.asyncio
    async def test_get_stats_by_severity(self, service):
        await service.create_task(
            project_id="p1", title="Critical", task_type=TaskType.VULN_FIX,
            finding_severity="CRITICAL", assigned_to="dev1"
        )
        stats = await service.get_stats("p1")
        assert stats.by_severity.get("CRITICAL") == 1

    @pytest.mark.asyncio
    async def test_get_stats_overdue(self, service):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        t = await service.create_task(
            project_id="p1", title="逾期", task_type=TaskType.SCAN,
            assigned_to="dev1", due_date=past
        )
        stats = await service.get_stats("p1")
        assert stats.overdue_count == 1

    @pytest.mark.asyncio
    async def test_get_stats_project_filter(self, service):
        await service.create_task(
            project_id="p1", title="P1", task_type=TaskType.SCAN, assigned_to="dev1"
        )
        await service.create_task(
            project_id="p2", title="P2", task_type=TaskType.SCAN, assigned_to="dev1"
        )
        s1 = await service.get_stats("p1")
        s2 = await service.get_stats("p2")
        assert s1.total_tasks == 1
        assert s2.total_tasks == 1
        assert s1.total_tasks != s2.total_tasks or s1.project_id != s2.project_id

    @pytest.mark.asyncio
    async def test_multi_project_stats(self, service):
        await service.create_task(
            project_id="p1", title="T1", task_type=TaskType.SCAN, assigned_to="dev1"
        )
        await service.create_task(
            project_id="p2", title="T2", task_type=TaskType.SCAN, assigned_to="dev1"
        )
        result = await service.get_multi_project_stats(["p1", "p2"])
        assert "p1" in result
        assert "p2" in result
        assert result["p1"].total_tasks == 1
        assert result["p2"].total_tasks == 1

    @pytest.mark.asyncio
    async def test_project_name_in_stats(self, service):
        await service.create_task(
            project_id="p1", title="T", task_type=TaskType.SCAN,
            assigned_to="dev1", project_name="MyProject"
        )
        stats = await service.get_stats("p1")
        assert stats.project_name == "MyProject"


# ─────────────────────── TaskTimeline Tests ───────────────────────

class TestTaskTimeline:
    """任务时间线测试"""

    @pytest.mark.asyncio
    async def test_get_timeline_not_found(self, service):
        with pytest.raises(TaskNotFoundError):
            await service.get_task_timeline("nonexistent")

    @pytest.mark.asyncio
    async def test_get_timeline_with_transitions_and_comments(self, service):
        task = await service.create_task(
            project_id="p1", title="T", task_type=TaskType.SCAN, assigned_to="dev1"
        )
        await service.add_comment(task.id, "评论1", "user1")
        await service.add_comment(task.id, "评论2", "user2")

        timeline = await service.get_task_timeline(task.id)
        assert timeline["task"]["id"] == task.id
        assert len(timeline["transitions"]) >= 1  # initial creation
        assert len(timeline["comments"]) == 2


# ─────────────────────── Query Filter Tests ───────────────────────

class TestTaskQueryParams:
    """任务查询过滤参数测试"""

    @pytest.mark.asyncio
    async def test_list_by_project_id(self, service):
        await service.create_task(project_id="p1", title="T1", task_type=TaskType.SCAN)
        await service.create_task(project_id="p2", title="T2", task_type=TaskType.SCAN)
        params = TaskQueryParams(project_id="p1")
        tasks = await service.list_tasks(params)
        assert len(tasks) == 1
        assert tasks[0].project_id == "p1"

    @pytest.mark.asyncio
    async def test_list_by_status(self, service):
        t1 = await service.create_task(project_id="p1", title="T", task_type=TaskType.SCAN)
        t2 = await service.create_task(
            project_id="p1", title="T2", task_type=TaskType.SCAN, assigned_to="dev1"
        )
        params = TaskQueryParams(project_id="p1", status=TaskStatus.ASSIGNED)
        tasks = await service.list_tasks(params)
        assert len(tasks) == 1
        assert tasks[0].status == TaskStatus.ASSIGNED

    @pytest.mark.asyncio
    async def test_list_by_priority(self, service):
        await service.create_task(
            project_id="p1", title="T1", task_type=TaskType.SCAN, priority=TaskPriority.P0
        )
        await service.create_task(
            project_id="p1", title="T2", task_type=TaskType.SCAN, priority=TaskPriority.P3
        )
        params = TaskQueryParams(project_id="p1", priority=TaskPriority.P0)
        tasks = await service.list_tasks(params)
        assert len(tasks) == 1

    @pytest.mark.asyncio
    async def test_list_pagination(self, service):
        for i in range(5):
            await service.create_task(project_id="p1", title=f"T{i}", task_type=TaskType.SCAN)
        params = TaskQueryParams(project_id="p1", limit=2, offset=0)
        tasks = await service.list_tasks(params)
        assert len(tasks) == 2

        params2 = TaskQueryParams(project_id="p1", limit=2, offset=4)
        tasks2 = await service.list_tasks(params2)
        assert len(tasks2) == 1


# ─────────────────────── Comment Tests ───────────────────────

class TestComments:
    """评论功能测试"""

    @pytest.mark.asyncio
    async def test_add_comment_not_found(self, service):
        with pytest.raises(TaskNotFoundError):
            await service.add_comment("missing", "内容")

    @pytest.mark.asyncio
    async def test_list_comments(self, service):
        task = await service.create_task(project_id="p1", title="T", task_type=TaskType.SCAN)
        await service.add_comment(task.id, "第一评论", "user1")
        await service.add_comment(task.id, "第二评论", "user2")
        comments = await service.list_comments(task.id)
        assert len(comments) == 2
        assert comments[0].content == "第一评论"
        assert comments[1].content == "第二评论"


# ─────────────────────── Edge Cases Tests ───────────────────────

class TestEdgeCases:
    """边界条件测试"""

    @pytest.mark.asyncio
    async def test_create_task_with_due_date(self, service):
        due = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        task = await service.create_task(
            project_id="p1", title="T", task_type=TaskType.SCAN, due_date=due
        )
        assert task.due_date is not None

    @pytest.mark.asyncio
    async def test_create_task_with_tags(self, service):
        task = await service.create_task(
            project_id="p1", title="T", task_type=TaskType.SCAN,
            tags=["security", "sqli"]
        )
        assert "security" in task.tags

    @pytest.mark.asyncio
    async def test_submit_fix_without_diff(self, service):
        """提交修复时 diff 可以为空"""
        task = await service.create_task(
            project_id="p1", title="T", task_type=TaskType.VULN_FIX, assigned_to="dev1"
        )
        task = await service.start_progress(task.id, "dev1")
        task = await service.submit_fix(task.id, "", "dev1")
        assert task.status == TaskStatus.FIX_SUBMITTED

    @pytest.mark.asyncio
    async def test_review_without_comment(self, service):
        task = await service.create_task(
            project_id="p1", title="T", task_type=TaskType.VULN_FIX, assigned_to="dev1"
        )
        task = await service.start_progress(task.id, "dev1")
        task = await service.submit_fix(task.id, "diff", "dev1")
        task = await service.submit_for_review(task.id, "dev1")
        req = TaskReviewRequest(
            task_id=task.id, verdict=ReviewVerdict.PASS, reviewer="rev1"
        )
        task = await service.review_task(req)
        assert task.status == TaskStatus.DONE

    @pytest.mark.asyncio
    async def test_double_cancel_raises(self, service):
        task = await service.create_task(project_id="p1", title="T", task_type=TaskType.SCAN)
        await service.cancel_task(task.id, "admin1", "manager")
        with pytest.raises(TaskError):
            await service.cancel_task(task.id, "admin1", "manager")

    @pytest.mark.asyncio
    async def test_update_not_found(self, service):
        result = await service.tasks.update("nonexistent", title="X")
        assert result is False
