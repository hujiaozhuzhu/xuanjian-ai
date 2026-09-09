# A4 — 协同任务管理 (Collaborative Task Management)

> 子功能编号：A4 | 模块路径：`fp_sentinel/privacy/collaborative_task.py`
> 状态：已完成 | 安全红线：S7/S9

## 功能目标

支持创建跨团队协同审计任务，分配不同范围的扫描权限，结果汇总时自动脱敏。

## 核心组件

### CollaborativeTaskManager
任务管理器 — 六态状态机驱动的完整生命周期：

```
[DRAFT] ──→ [PENDING] ──→ [SCANNING] ──→ [AGGREGATING] ──→ [REVIEWING] ──→ [COMPLETED]
   │             │              │               │                  │
   └─────────────┴──────────────┴───────────────┴──────────────────┴──→ [CANCELLED]
```

- `create_task()` → 创建草稿
- `assign_team_permission()` → 团队权限分配
- `start_task()` → 启动扫描
- `submit_team_results()` → 提交脱敏结果
- `aggregate_results()` → 按权限聚合
- `get_team_view()` → 团队隔离视角
- `finalize_task()` / `cancel_task()` → 完结/取消

### ResultDesensitizer
结果脱敏引擎：
- 文件路径 → SHA-256 哈希（不可逆）
- 行号 → 范围描述（L45-L50）
- 代码片段 → 完全移除
- 团队标识 → 哈希化
- `contains_plaintext_code()` 残留检测

### PermissionEngine
权限引擎 — 细粒度访问控制：
- 严重度分级访问（INFO → LOW → MEDIUM → HIGH → CRITICAL）
- 路径白名单/黑名单
- 代码查看权限开关
- 完整路径可见性控制
- 导出权限控制

## 权限矩阵

| 权限 | 默认值 | 说明 |
|------|--------|------|
| allowed_paths | [] | 允许扫描路径 |
| excluded_paths | [] | 排除路径 |
| max_severity_access | CRITICAL | 最高可见严重度 |
| can_view_code | False | 代码片段可见 |
| can_view_full_path | True | 路径可见（脱敏后） |
| can_export | True | 导出权限 |

## 数据流

```
创建任务 → 分配权限 → 启动扫描
    → 各团队扫描（本地数据不出域）
    → 结果脱敏（ResultDesensitizer）
    → 提交（submit_team_results，安全校验）
    → 聚合（aggregate_results，按权限过滤）
    → 团队视图（get_team_view，动态脱敏）
    → 完成任务
```

## 安全约束

- 提交时自动 `check_batch_safety()` 拦截明码
- 团队隔离：`get_team_view()` 仅返回该团队有权访问的数据
- 不合规提交直接 `ValueError` 拒绝入库
- 聚合结果哈希化，不含任何原始数据

## 测试覆盖

- `TestResultDesensitizer`：3 用例（脱敏/批量安全/代码检测）
- `TestPermissionEngine`：5 用例（严重度/过滤/路径/可见度）
- `TestCollaborativeTaskManager`：10 用例（创建/分配/提交/聚合/完成/取消/视图）
