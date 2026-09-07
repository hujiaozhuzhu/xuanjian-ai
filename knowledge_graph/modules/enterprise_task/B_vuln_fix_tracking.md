# 子功能 B: 漏洞修复跟踪

> 版本: v2.5.0 ｜ 所属模块: 企业任务管理

## 功能描述

通过严格的状态机驱动漏洞修复全流程，每一步流转都记录操作人、时间、备注，确保可追溯。

## 状态流转

```
pending → assigned → in_progress → fix_submitted → under_review → done
                                                         ↑
                                                         └─ needs_work/reject → in_progress (迭代)
```

### 合法流转

| From | To | 操作 |
|------|-----|------|
| pending | assigned | 分配任务 |
| assigned | in_progress | 开始处理 |
| in_progress | fix_submitted | 提交修复 |
| fix_submitted | under_review | 提交评审 |
| under_review | done | 评审通过 |
| under_review | in_progress | 评审需修改/驳回 |

## 核心接口

### 开始处理
```python
task = await service.start_progress(task_id="t-001", operator="dev1", comment="开始分析")
# assigned → in_progress
```

### 提交修复
```python
task = await service.submit_fix(
    task_id="t-001",
    fix_diff="--- a/app.py\n+++ b/app.py\n@@ -42 +42 @@\n- cursor.execute(...)\n+ cursor.execute(..., params)",
    operator="dev1",
    fix_commit_hash="abc123",
    fix_notes="使用参数化查询修复 SQL 注入",
)
# in_progress → fix_submitted
```

### 提交评审
```python
task = await service.submit_for_review(task_id="t-001", operator="dev1")
# fix_submitted → under_review
```

### 取消
```python
task = await service.cancel_task(task_id="t-001", operator="admin1", operator_role="manager", comment="需求变更")
# → cancelled
```

## 状态校验机制

每次 `change_status` 调用执行三重校验：

1. **合法性校验**: 目标状态在 `VALID_TRANSITIONS[当前状态]` 内
2. **权限校验**: 操作人角色在 `STATUS_ROLE_MAP[当前状态]` 内
3. **数据完整性**: 提交修复需包含 fix_diff（可为空字符串），完成时自动写入 `completed_at`

## 查询时间线

```python
timeline = await service.get_task_timeline(task_id="t-001")
# 返回: {task, transitions: [...], comments: [...]}
```

## CLI 命令

```bash
fp-sentinel task start <task_id>
fp-sentinel task submit <task_id> --diff "fix diff" --commit abc123 --notes "说明"
fp-sentinel task show <task_id>           # 详情+时间线
fp-sentinel task transitions <task_id>    # 流转记录
fp-sentinel task cancel <task_id> --comment "原因"
```

## 测试覆盖

| 测试用例 | 说明 |
|---------|------|
| test_full_lifecycle_happy_path | 完整6步流转 + 时间线验证 |
| test_invalid_transition_raises | pending→done 非法 |
| test_permission_denied_raises | developer 操作 pending |
| test_start_progress | assigned→in_progress |
| test_submit_fix | in_progress→fix_submitted + diff 验证 |
| test_submit_for_review | fix_submitted→under_review |
| test_cancel_task | 取消 |
| test_cancel_done_task_raises | 终态不可取消 |
| test_double_cancel_raises | 重复取消 |
| test_review_wrong_status_raises | 非 under_review 不可评审 |
