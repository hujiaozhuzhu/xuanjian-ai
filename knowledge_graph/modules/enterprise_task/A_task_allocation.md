# 子功能 A: 扫描任务分配

> 版本: v2.5.0 ｜ 所属模块: 企业任务管理

## 功能描述

支持安全扫描发现到修复任务的自动转化，实现单人分配与批量分配两种模式。

## 核心能力

### 1. 单人任务创建
```python
task = await service.create_task(
    project_id="proj-001",
    title="修复SQL注入",
    task_type=TaskType.VULN_FIX,
    finding_id="find-123",
    finding_severity="CRITICAL",
    assigned_to="dev-zhang",
    assigned_by="sec-admin",
    due_date="2026-09-15T00:00:00Z",
    tags=["sqli", "critical"],
)
```

### 2. 批量从 Finding 创建（幂等）
```python
request = BulkCreateRequest(
    project_id="proj-001",
    finding_ids=["f-001", "f-002", "f-003"],
    priority=TaskPriority.P0,
    assigned_to="dev-li",
)
count, tasks = await service.bulk_create_from_findings(request)
```

幂等性：已有未完成任务的 finding_id 自动跳过，避免重复创建。

### 3. 再分配
```python
req = TaskAssignmentRequest(
    task_id="task-001",
    assigned_to="dev-wang",
    assigned_by="manager-1",
    comment="工作调整，转交小王处理"
)
task = await service.assign_task(req)
```

## 自动分配规则

- 无 assignee 创建时：状态 = `pending`
- 有 assignee 创建时：状态 = `assigned`，并记录分配流转

## CLI 命令

```bash
fp-sentinel task create <project_id> <title> --type vuln_fix --assign-to dev1 --priority P0
fp-sentinel task bulk-create <project_id> <f1,f2,f3> --priority P1 --assign-to dev1
fp-sentinel task assign <task_id> <new_assignee>
```

## 测试覆盖

| 测试用例 | 说明 |
|---------|------|
| test_create_task | 创建无指派人 → pending |
| test_create_task_with_assignee | 创建有指派人 → assigned |
| test_create_task_with_finding_info | 完整 finding 信息关联 |
| test_bulk_create_from_findings | 批量创建 3 个 |
| test_bulk_create_skips_existing | 已有任务的 finding 跳过 |
| test_assign_task | 分配 + 状态流转 |
| test_assign_not_found_raises | 不存在的任务 |
| test_assign_done_task_raises | 已完成不可分配 |
