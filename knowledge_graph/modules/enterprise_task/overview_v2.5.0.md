# 玄鉴 v2.5.0 — 企业任务管理模块 (Enterprise Task Management)

> 版本: v2.5.0 ｜ 生成日期: 2026-09-08 ｜ 模块归属: 企业任务管理
> 模块路径: `fp_sentinel/enterprise_task/`

---

## 一、模块概述

企业任务管理模块 (Enterprise Task Management) 是玄鉴 v2.5.0 的核心子模块，
提供扫描任务分配、漏洞修复跟踪、修复结果评审、任务进度统计四项核心能力，
支持多项目、多用户的任务协同管理，状态流转清晰可追溯。

### 版本演进

| 版本 | 状态 | 主要变更 |
|------|------|---------|
| v2.2.0 | 已发布 | 攻防增强、开发者画像 |
| v2.3.0 | 已发布 | 规则自动调优、自定义规则加载、Java规则库优化 |
| v2.4.0 | 已发布 | 知识图谱查询、自动归档、可视化 |
| **v2.5.0** | **已完成** | **企业任务管理：扫描分配、修复跟踪、评审、统计** |

---

## 二、子功能清单

| 编号 | 子功能 | 说明 | 状态 |
|------|--------|------|------|
| A | 扫描任务分配 | 支持单人/批量分配，从扫描发现自动创建修复任务 | 已完成 |
| B | 漏洞修复跟踪 | 完整状态机驱动（pending→assigned→in_progress→fix_submitted→under_review→done） | 已完成 |
| C | 修复结果评审 | 通过/需修改/驳回三种结论，驳回自动回到进行中 | 已完成 |
| D | 任务进度统计 | 多维度统计（状态/优先级/类型/指派人/严重度）、完成率、逾期、平均解决耗时 | 已完成 |

---

## 三、文件结构

```
fp_sentinel/enterprise_task/
├── __init__.py                       # 模块入口、公共 API
├── models.py                         # Pydantic 数据模型、状态机定义
├── repository.py                     # SQLite (WAL) 数据存储层（Task/Transition/Comment）
├── service.py                        # 业务逻辑层（TaskService）
├── cli_commands.py                   # CLI 子命令组 (fp-sentinel task ...)
└── routes.py                         # REST API 路由 (/api/tasks/*)

tests/unit/
└── test_enterprise_task.py           # 79 用例

knowledge_graph/modules/enterprise_task/
├── overview_v2.5.0.md                # 本文件 - 模块总览
├── A_task_allocation.md              # 扫描任务分配子功能文档
├── B_vuln_fix_tracking.md            # 漏洞修复跟踪子功能文档
├── C_fix_review.md                   # 修复结果评审子功能文档
└── D_task_statistics.md              # 任务进度统计子功能文档
```

---

## 四、状态机设计

### 状态流转图

```
[PENDING] ──分配──→ [ASSIGNED] ──开始──→ [IN_PROGRESS] ──提交修复──→ [FIX_SUBMITTED]
     │                   │                    │                          │
     │                   │                    │                          │
     └──取消──→          └──取消──→           └──取消──→               └──提交评审──→
    [CANCELLED]          [CANCELLED]        [CANCELLED]              [UNDER_REVIEW]
                                                                         │     │
                                                                    通过 │     │ 需修改/驳回
                                                                         │     │
                                                                    [DONE]  └──→ [IN_PROGRESS] (循环)
```

### 状态流转规则

| 当前状态 | 允许流转 | 允许角色 |
|---------|---------|---------|
| pending | assigned, cancelled | admin, manager |
| assigned | in_progress, cancelled | admin, manager, developer |
| in_progress | fix_submitted, cancelled | admin, manager, developer |
| fix_submitted | under_review, cancelled | admin, manager, developer |
| under_review | done, in_progress, cancelled | admin, manager, reviewer |
| done | (终态) | - |
| cancelled | (终态) | - |

### 任务生命周期

```
创建任务 → 分配 → 开始处理 → 提交修复 → 提交评审 → 评审通过 → 完成
                                            ↓
                                      需修改/驳回 → 回到处理中（迭代修复）
```

---

## 五、测试汇总

| 测试文件 | 用例数 | 通过 | 覆盖率目标 |
|---------|-------|------|-----------|
| test_enterprise_task.py | 79 | 79 | >= 95% |

### 测试覆盖分类

| 测试类 | 用例数 | 覆盖内容 |
|--------|-------|---------|
| TestTaskModels | 12 | 枚举、请求对象、参数边界 |
| TestTaskConstruction | 5 | Task 模型构建、序列化 |
| TestTaskRepository | 11 | CRUD、过滤查询、标签/Metadata 序列化 |
| TestTaskTransitionRepo | 2 | 流转记录持久化 |
| TestTaskCommentRepo | 2 | 评论持久化 |
| TestTaskService | 16 | 全生命周期、状态流转、权限校验、异常分支 |
| TestTaskStats | 10 | 多维度统计、完成率、逾期、平均耗时 |
| TestTaskTimeline | 2 | 时间线（任务+流转+评论） |
| TestTaskQueryParams | 4 | 查询过滤、分页 |
| TestComments | 2 | 评论功能异常分支 |
| TestEdgeCases | 6 | 边界条件 |

---

## 六、安全合规

| 红线 | 实现方式 | 验证 |
|------|---------|------|
| S1 零网络 | 全部在内存 / SQLite 本地运行；无 HTTP/FTP/socket 调用 | 代码静态审查 |
| S2 不修改代码 | fix_diff 字段仅做展示用，不写入源文件 | 测试：submit_fix 不调用写文件 API |
| S3 不删除文件 | 仅写入新 DB 记录 | 操作审计 |
| S5 数据清理 | 通过 delete / cancel 管理数据生命周期 | test_delete_task |
| S7 路径白名单 | 依赖现有 Database 类路径管理 (~/.xuanjian/) | 复用 infrastructure |

---

## 七、CLI 使用

```bash
# 创建任务
fp-sentinel task create <project_id> <title> --type vuln_fix --priority P0 --assign-to dev1

# 批量从 finding 创建修复任务
fp-sentinel task bulk-create <project_id> <finding_id1,finding_id2,...> --priority P1

# 查询任务
fp-sentinel task list --project <project_id> --status assigned --limit 20

# 查看详情 + 时间线
fp-sentinel task show <task_id>

# 分配
fp-sentinel task assign <task_id> <assignee>

# 状态流转
fp-sentinel task start <task_id>
fp-sentinel task submit <task_id> --diff "fix diff content" --commit abc123
fp-sentinel task review <task_id> pass --by reviewer1 --comment "LGTM"
fp-sentinel task cancel <task_id> --comment "需求变更"

# 统计
fp-sentinel task stats --project <project_id>

# 状态流转图
fp-sentinel task flow
```

---

## 八、REST API

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/tasks/create | 创建任务 |
| POST | /api/tasks/bulk-create | 批量从 finding 创建 |
| GET | /api/tasks/list | 查询任务列表 |
| GET | /api/tasks/{id} | 获取任务详情+时间线 |
| GET | /api/tasks/{id}/transitions | 获取状态流转记录 |
| POST | /api/tasks/assign | 分配任务 |
| POST | /api/tasks/change-status | 变更状态 |
| POST | /api/tasks/review | 评审修复 |
| POST | /api/tasks/{id}/comment | 添加评论 |
| GET | /api/tasks/stats/summary | 进度统计 |
| GET | /api/tasks/transitions/valid | 合法状态流转 |

---

## 九、集成对接

### 9.1 CLI 注册
在 `fp_sentinel/cli/__init__.py` 中添加:
```python
try:
    from ..enterprise_task.cli_commands import task_app
    app.add_typer(task_app, name="task", help="企业任务管理")
except Exception:
    pass
```

### 9.2 REST 注册
在 `create_app` 中:
```python
from fp_sentinel.enterprise_task.routes import task_router
app.include_router(task_router)
```

### 9.3 内部复用
```python
from fp_sentinel.enterprise_task import TaskService, TaskRepo, TaskTransitionRepo, TaskCommentRepo

# 从 database 连接创建
service = TaskService(TaskRepo(db.conn), TaskTransitionRepo(db.conn), TaskCommentRepo(db.conn))
task = await service.create_task(project_id="p1", title="修复SQL注入", task_type=TaskType.VULN_FIX)
```

---

## 十、回滚策略

若 v2.5.0 任务管理模块引入问题：
1. 删除 `fp_sentinel/enterprise_task/` 目录
2. 删除 `tests/unit/test_enterprise_task.py`
3. 在 `cli/__init__.py` 中移除 task_app 注册
4. 在 Web app 中移除 task_router 注册

---

*文档由 CatPaw Agent 根据 v2.5.0 Enterprise Task Management Module 开发结果自动生成*
