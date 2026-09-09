# E3 权限检查引擎 — v2.5.0

> 子功能：角色-权限矩阵校验、项目级覆盖、审计联动
> 代码位置：`fp_sentinel/enterprise_perm/permissions.py`
> 测试文件：`tests/unit/test_enterprise_perm_permissions.py`

---

## 一、概述

权限检查引擎，是整个模块的核心校验层：
- 全局角色 → 权限矩阵 → 是否有权限
- 项目级角色覆盖 > 全局角色
- inactive 用户直接拒绝
- 所有 denied 操作强制记录审计日志

---

## 二、PermissionChecker 类

### 检查流程

```
check(user_id, permission, project_id?)
  ├── 查询用户是否存在 → 不存在则 denied
  ├── 用户是否 active → 非 active 则 denied
  ├── 确定生效角色
  │   ├── 有 project_id 且存在项目覆盖 → 使用项目角色 (source=project)
  │   └── 否则 → 使用全局角色 (source=global)
  ├── 查询 ROLE_PERMISSIONS[role] 是否包含 permission
  ├── allowed → 可选记录 perm.check (allowed)
  └── denied → 强制记录 perm.denied
```

### 方法

| 方法 | 说明 |
|------|------|
| check(user_id, permission, project_id?, log_allowed?) | 返回 PermissionCheckResult |
| require(user_id, permission, project_id?) | 无权限时抛出 PermissionDeniedError |
| check_batch(user_id, permissions) | 批量检查，返回 {permission: bool} |

---

## 三、PermissionDeniedError

自定义异常，由 `require()` 在无权限时抛出：
- 用户不存在
- 用户未激活
- 角色缺少权限

--- 

## 四、审计日志联动

| 场景 | 审计操作 | 结果 |
|------|---------|------|
| check 通过（log_allowed=True） | perm.check | allowed |
| check 拒绝 | perm.denied | denied |
| 用户不存在 | perm.denied | denied |
| 用户未激活 | perm.denied | denied |

审计日志写入失败不影响权限判定逻辑（使用 try/except 捕获，避免阻塞主流程）。