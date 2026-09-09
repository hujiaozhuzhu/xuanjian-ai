# 企业权限管理（Enterprise Permission Management）知识库索引

> 版本：v2.5.0 | 模块标识：enterprise_perm | 代码位置：`fp_sentinel/enterprise_perm/`
> 生成时间：2026-09-07 | Agent：权限管理开发工程师

## 子功能清单

| 子功能 | 归档文档 | 代码位置 | 状态 |
|--------|---------|---------|------|
| E1 数据模型与枚举 | [E1-perm-models.md](./E1-perm-models.md) | `fp_sentinel/enterprise_perm/models.py` | 完成 |
| E2 数据仓库层 | [E2-perm-repo.md](./E2-perm-repo.md) | `fp_sentinel/enterprise_perm/repo.py` | 完成 |
| E3 权限检查引擎 | [E3-perm-permissions.md](./E3-perm-permissions.md) | `fp_sentinel/enterprise_perm/permissions.py` | 完成 |
| E4 CLI 命令集成 | [E4-perm-cli.md](./E4-perm-cli.md) | `fp_sentinel/cli/perm_commands.py` | 完成 |
| E5 安全红线落地 | [E5-perm-security.md](./E5-perm-security.md) | 融入上述模块 | 完成 |

## 权限矩阵

| 权限 | 管理员 | 安全工程师 | 普通开发者 |
|------|--------|-----------|-----------|
| scan:run | ✅ | ✅ | ✅ |
| scan:view_all | ✅ | ✅ | ❌ |
| scan:delete | ✅ | ❌ | ❌ |
| report:generate | ✅ | ✅ | ✅ |
| report:view_all | ✅ | ✅ | ❌ |
| report:delete | ✅ | ❌ | ❌ |
| kg:query | ✅ | ✅ | ✅ |
| kg:manage | ✅ | ✅ | ❌ |
| fp:mark | ✅ | ✅ | ✅ |
| fp:manage | ✅ | ✅ | ❌ |
| perm:manage | ✅ | ❌ | ❌ |
| audit:view | ✅ | ✅ | ❌ |
| project:manage | ✅ | ❌ | ❌ |

## 测试覆盖

- 单测文件：
  - `tests/unit/test_enterprise_perm_models.py` — 34 用例（枚举/模型/权限矩阵）
  - `tests/unit/test_enterprise_perm_repo.py` — 32 用例（User/ProjectRole/Audit CRUD）
  - `tests/unit/test_enterprise_perm_permissions.py` — 27 用例（权限检查引擎）
  - `tests/unit/test_enterprise_perm_cli.py` — 10 用例（CLI集成/安全红线）
- 总用例数：103
- 模块覆盖率：enterprise_perm 核心模块 96%（超过 95% 目标）
- 结果：全部通过（2026-09-07）
- 关联失败：0（全量测试有7个预存在于无关模块的旧失败，非本模块引入）

## 安全红线落地

- S1 (禁止外网)：代码中零网络调用，权限校验纯本地
- S2 (禁止修改代码)：本模块仅操作 permissions/audit 相关表
- S3 (禁止删除文件)：forget 仅删权限数据，不动源文件
- S6 (隐私)：用户名规范化存储，userid 为 UUID 不暴露真实身份
- S7 (输出白名单)：审计日志本地 SQLite，不外发

## 审计日志审计的操作类型

| 操作类型 | 描述 | 审计条件 |
|---------|------|---------|
| user.create | 创建用户 | 总是 |
| user.delete | 停用用户 | 总是 |
| user.role_change | 角色变更 | 总是 |
| project.grant | 项目授权 | 总是 |
| project.revoke | 项目撤销 | 总是 |
| perm.check | 权限检查 | log_allowed=True |
| perm.denied | 权限拒绝 | 总是（强制） |
| perm.grant | 权限授予 | 总是 |