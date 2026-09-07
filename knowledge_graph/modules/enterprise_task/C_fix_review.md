# 子功能 C: 修复结果评审

> 版本: v2.5.0 ｜ 所属模块: 企业任务管理

## 功能描述

对提交的修复结果进行评审，支持三种结论：通过、需修改、驳回。通过的修复自动完成，需修改/驳回则回到进行中状态迭代修复。

## 评审流程

```
reviewer 收到 under_review 任务
    │
    ├── PASS → done (completed_at 自动写入)
    │
    ├── NEEDS_WORK → in_progress (清除上次评审记录，开发者继续修复)
    │
    └── REJECT → in_progress (同上)
```

## 评审状态机

```
[UNDER_REVIEW]
    │
    ├── review_task(PASS) → [DONE]
    │     └── completed_at = now
    │     └── review_verdict = pass
    │
    ├── review_task(NEEDS_WORK) → [IN_PROGRESS]
    │     └── 清除 review_verdict/review_comment/reviewed_by/reviewed_at
    │
    └── review_task(REJECT) → [IN_PROGRESS]
          └── 清除评审记录
```

## 核心接口

```python
req = TaskReviewRequest(
    task_id="t-001",
    verdict=ReviewVerdict.PASS,  # pass / needs_work / reject
    reviewer="senior-dev-1",
    comment="修复完整，已添加输入验证和参数化查询"
)
task = await service.review_task(req)
```

## 数据模型

| 字段 | 类型 | 说明 |
|------|------|------|
| review_verdict | ReviewVerdict | pass / needs_work / reject |
| review_comment | str | 评审意见 |
| reviewed_by | str | 评审人 |
| reviewed_at | str (ISO8601) | 评审时间 |

## 迭代修复流程

```
开发者提交 → 评审人评审
                ├── 通过 → 完成
                └── 需修改 → 回到 in_progress → 开发者再次修复 → 再次提交 → 再次评审
```

每次评审驳回都会清除上次评审记录，确保 review_verdict 始终反映最新评审。

## CLI 命令

```bash
# 通过
fp-sentinel task review <task_id> pass --by reviewer1 --comment "LGTM"

# 需修改
fp-sentinel task review <task_id> needs_work --by reviewer1 --comment "缺少输入验证"

# 驳回
fp-sentinel task review <task_id> reject --by reviewer1 --comment "修复方案需调整"
```

## 安全合规

- **S2**: fix_diff 仅做展示，不直接修改源代码，由开发者自行应用修复
- **S1**: 纯本地操作，零网络请求

## 测试覆盖

| 测试用例 | 说明 |
|---------|------|
| test_full_lifecycle_happy_path | 评审通过 → done |
| test_review_needs_work_loops_back | 需修改 → in_progress |
| test_review_reject_loops_back | 驳回 → in_progress |
| test_review_wrong_status_raises | 非 under_review 状态拒绝评审 |
| test_review_without_comment | 无意见评审通过 |
