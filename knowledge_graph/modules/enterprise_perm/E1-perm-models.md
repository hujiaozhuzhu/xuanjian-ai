# E1 数据模型与枚举 — v2.5.0

> 子功能：数据模型与 SQLite 表定义
> 代码位置：`fp_sentinel/enterprise_perm/models.py`
> 测试文件：`tests/unit/test_enterprise_perm_models.py`

---

## 一、概述

企业权限管理的模型层，定义：
- 三级角色枚举（Role）：admin / security_engineer / developer
- 权限枚举（Permission）：13 种细粒度权限
- 审计操作枚举（AuditAction）和结果枚举（AuditResult）
- 权限矩阵（ROLE_PERMISSIONS）：角色到权限集合的映射
- Pydantic 数据模型：User / ProjectRole / AuditEntry / PermissionCheckResult / RoleInfo
- SQLite 表定义（只增不改）

安全红线声明：
- 权限数据仅存储于本地 SQLite，禁止任何网络上传
- 本模块只增不改既有表结构

---

## 二、枚举定义

### Role（三级角色）
| 值 | 描述 |
|---|------|
| admin | 管理员，拥有全部权限 |
| security_engineer | 安全工程师，可管理扫描/报告/知识图谱 |
| developer | 普通开发者，仅有基本操作权限 |

### Permission（13 种权限）
| 权限 | 类别 | 描述 |
|------|------|------|
| scan:run | 扫描 | 运行扫描 |
| scan:view_all | 扫描 | 查看所有扫描结果 |
| scan:delete | 扫描 | 删除扫描记录 |
| report:generate | 报告 | 生成报告 |
| report:view_all | 报告 | 查看所有报告 |
| report:delete | 报告 | 删除报告 |
| kg:query | 知识图谱 | 查询知识图谱 |
| kg:manage | 知识图谱 | 管理知识图谱 |
| fp:mark | 误报 | 标记误报 |
| fp:manage | 误报 | 管理误报规则 |
| perm:manage | 权限 | 管理用户权限 |
| audit:view | 审计 | 查看审计日志 |
| project:manage | 项目 | 管理项目 |

---

## 三、数据模型

### User
| 字段 | 类型 | 说明 |
|------|------|------|
| id | str | UUID 主键 |
| username | str | 唯一用户名（规范化：小写+去空白） |
| display_name | Optional[str] | 显示名 |
| role | Role | 全局角色 |
| is_active | bool | 是否激活 |
| created_at | Optional[datetime] | 创建时间 |
| updated_at | Optional[datetime] | 更新时间 |

### ProjectRole（项目级覆盖）
| 字段 | 类型 | 说明 |
|------|------|------|
| id | str | UUID 主键 |
| user_id | str | 用户ID（FK -> users.id） |
| project_id | str | 项目ID（FK -> projects.id） |
| role | Role | 项目角色 |
| granted_by | Optional[str] | 授权人 |
| created_at | Optional[datetime] | 创建时间 |

### AuditEntry（审计日志）
| 字段 | 类型 | 说明 |
|------|------|------|
| id | Optional[int] | 自增主键 |
| user_id | Optional[str] | 操作用户ID |
| username | Optional[str] | 操作用户名 |
| action | str | 操作类型 |
| resource_type | Optional[str] | 资源类型 |
| resource_id | Optional[str] | 资源ID |
| result | str | 结果(allowed/denied/success/failure) |
| details | Optional[str] | JSON 详情 |
| ip_address | str | IP地址（默认 127.0.0.1） |
| timestamp | Optional[datetime] | 操作时间 |

### PermissionCheckResult
| 字段 | 类型 | 说明 |
|------|------|------|
| allowed | bool | 是否允许 |
| user_id | str | 用户ID |
| permission | Permission | 请求的权限 |
| role | Optional[Role] | 判定所用的角色 |
| source | str | 角色来源：global/project |

---

## 四、权限矩阵

```
ROLE_PERMISSIONS = {
    Role.ADMIN: 全部13种权限,
    Role.SECURITY_ENGINEER: 扫描类(2) + 报告类(2) + 知识图谱(2) + 误报(2) + 审计(1),
    Role.DEVELOPER: 扫描运行 + 报告生成 + 知识图谱查询 + 误报标记,
}
```

---

## 五、新增 SQLite 表（只增不改）

```sql
CREATE TABLE IF NOT EXISTS users (...);
CREATE TABLE IF NOT EXISTS user_project_roles (...);
CREATE TABLE IF NOT EXISTS audit_log (...);
CREATE TABLE IF NOT EXISTS permission_definitions (...);
```

- 所有表使用 `CREATE TABLE IF NOT EXISTS`（幂等）
- 所有索引使用 `CREATE INDEX IF NOT EXISTS`（幂等）
- 外键：user_project_roles 引用 users.id 和 projects.id（级联删除）