# 子功能 D: 任务进度统计

> 版本: v2.5.0 ｜ 所属模块: 企业任务管理

## 功能描述

提供多维度的任务进度统计，帮助管理层快速掌握项目安全修复态势：按状态/优先级/类型/指派人/严重度分组，以及完成率、逾期数、平均解决耗时等核心指标。

## 统计维度

| 维度 | 字段 | 说明 |
|------|------|------|
| 状态 | by_status | pending / assigned / in_progress / fix_submitted / under_review / done / cancelled |
| 优先级 | by_priority | P0 / P1 / P2 / P3 |
| 类型 | by_type | scan / vuln_fix / fix_review / retest |
| 指派人 | by_assignee | 按 assigned_to 分组 |
| 严重度 | by_severity | CRITICAL / HIGH / MEDIUM / LOW |

## 核心指标

| 指标 | 字段 | 计算方式 |
|------|------|---------|
| 总任务数 | total_tasks | COUNT(*) |
| 完成率 | completion_rate | done / (total - cancelled) |
| 逾期数 | overdue_count | due_date < now AND status NOT IN (done, cancelled) |
| 平均解决耗时 | avg_resolution_hours | AVG(completed_at - created_at) WHERE status=done |

## 核心接口

```python
# 全局统计
stats = await service.get_stats()

# 单项目统计
stats = await service.get_stats(project_id="proj-001")

# 多项目统计
result = await service.get_multi_project_stats(["proj-001", "proj-002"])
```

## 返回结构 (TaskStats)

```python
TaskStats(
    project_id="proj-001",
    project_name="核心服务",
    total_tasks=42,
    by_status={"assigned": 5, "in_progress": 12, "done": 20, "cancelled": 2},
    by_priority={"P0": 3, "P1": 15, "P2": 22, "P3": 2},
    by_type={"vuln_fix": 35, "scan": 5, "retest": 2},
    by_assignee={"dev-zhang": 10, "dev-li": 15, "dev-wang": 12},
    by_severity={"CRITICAL": 5, "HIGH": 20, "MEDIUM": 15, "LOW": 2},
    done_count=20,
    cancelled_count=2,
    overdue_count=3,
    completion_rate=0.4878,
    avg_resolution_hours=18.5,
)
```

## CLI 命令

```bash
# 全局统计
fp-sentinel task stats

# 单项目统计
fp-sentinel task stats --project <project_id>
```

## 输出示例

```
┌─────────────────────────────────────────────┐
│  📊 任务统计 (核心服务)                       │
├─────────────────────────────────────────────┤
│  总任务数     : 42                            │
│  已完成       : 20                            │
│  已取消       : 2                             │
│  逾期         : 3                             │
│  完成率       : 48.8%                         │
│  平均解决耗时 : 18.5h                         │
│                                             │
│  按状态:                                     │
│    in_progress   12                          │
│    done          20                          │
│    assigned      5                           │
│    ...                                       │
│                                             │
│  按指派人:                                    │
│    dev-li          15                        │
│    dev-wang        12                        │
│    dev-zhang       10                        │
└─────────────────────────────────────────────┘
```

## 实现说明

统计查询使用 SQLite 聚合函数直接计算，无需加载全量数据到内存：

```sql
-- 按状态分组
SELECT status, COUNT(*) as cnt FROM et_tasks WHERE project_id = ? GROUP BY status

-- 逾期数
SELECT COUNT(*) FROM et_tasks
WHERE project_id = ?
  AND due_date IS NOT NULL
  AND due_date < ?
  AND status NOT IN ('done', 'cancelled')

-- 平均解决耗时（Python 端计算时间差）
SELECT created_at, completed_at FROM et_tasks
WHERE project_id = ? AND completed_at IS NOT NULL AND status = 'done'
```

## 测试覆盖

| 测试用例 | 说明 |
|---------|------|
| test_get_stats_empty | 空库返回零值 |
| test_get_stats_with_tasks | 按状态分组正确 |
| test_get_stats_completion_rate | 完成率 = done/(total-cancelled) |
| test_get_stats_by_priority | P0/P2 分组计数 |
| test_get_stats_by_type | scan/vuln_fix 分组计数 |
| test_get_stats_by_assignee | 按人分组 |
| test_get_stats_by_severity | CRITICAL 分组 |
| test_get_stats_overdue | due_date < now |
| test_get_stats_project_filter | 项目隔离 |
| test_multi_project_stats | 多项目批量统计 |
| test_project_name_in_stats | 项目名称正确 |
