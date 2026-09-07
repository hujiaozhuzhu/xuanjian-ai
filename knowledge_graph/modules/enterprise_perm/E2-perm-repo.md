# E2 数据仓库层 — v2.5.0

> 子功能：UserRepo / ProjectRoleRepo / AuditRepo 的 CRUD 操作
> 代码位置：`fp_sentinel/enterprise_perm/repo.py`
> 测试文件：`tests/unit/test_enterprise_perm_repo.py`

---

## 一、概述

数据仓库层，提供三个核心仓库的 CRUD 操作：
- UserRepo：用户管理（创建、角色变更、激活/停用、查询）
- ProjectRoleRepo：项目级角色覆盖（授权、撤销、查询）
- AuditRepo：审计日志（记录、查询、统计）

所有操作遵循既定模式：构造函数接收 Database 实例，使用参数化 SQL 防止注入。

---

## 二、UserRepo

| 方法 | 说明 |
|------|------|
| create(username, role, display_name) | 创建用户（自动规范化用户名） |
| get_by_id(user_id) | 按 ID 查询 |
| get_by_username(username) | 按用户名查询（大小写不敏感） |
| list_all(active_only=True) | 列出用户 |
| list_by_role(role) | 按角色筛选 |
| update_role(user_id, new_role) | 更新全局角色 |
| deactivate(user_id) | 停用 |
| activate(user_id) | 激活 |
| delete(user_id) | 删除（级联删除项目角色） |
| count_by_role() | 按角色统计用户数 |

---

## 三、ProjectRoleRepo

| 方法 | 说明 |
|------|------|
| grant(user_id, project_id, role, granted_by) | 授予项目角色（UPSERT） |
| revoke(user_id, project_id) | 撤销项目角色 |
| get_project_role(user_id, project_id) | 获取某用户在某项目的角色 |
| get_user_projects(user_id) | 获取用户的所有项目角色 |
| get_project_users(project_id) | 获取某项目的所有用户角色 |

---

## 四、AuditRepo

| 方法 | 说明 |
|------|------|
| log(action, result, ...) | 记录审计日志 |
| list_entries(user_id, action, result_filter, limit, offset) | 查询审计日志 |
| count(user_id, action, result_filter) | 统计记录数 |
| get_action_stats() | 按操作类型统计 |

---

## 五、SQL 注入防护

- 所有查询使用 `?` 参数占位符
- LIKE 查询（如 repo.py 的 FindingRepo 模式）转义 `%`、`_`
- 审计 details 字段使用 `json.dumps` 序列化，不拼接 SQL