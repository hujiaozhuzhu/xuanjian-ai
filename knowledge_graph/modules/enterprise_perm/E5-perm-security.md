# E5 安全红线落地 — v2.5.0

> 安全红线验证与审计
> 覆盖模块：全部 enterprise_perm 模块
> 测试文件：`tests/unit/test_enterprise_perm_cli.py`（TestSecurityRedLines 类）

---

## 一、S1（禁止外网）

- 权限校验纯本地 SQLite 查询
- 代码中零网络调用
- 审计日志 ip_address 字段默认 127.0.0.1

测试：`test_audit_log_no_network_safety`

---

## 二、S2（禁止修改代码）

- 本模块仅操作以下表：users / user_project_roles / audit_log / permission_definitions
- 不修改 findings / scan_history / projects 表结构

---

## 三、S3（禁止删除文件）

- 本模块不执行任何文件系统操作
- 用户"删除"仅删除数据库中权限数据

---

## 四、S6（隐私）

- 用户名规范化（小写+去空白）后存储
- 用户 ID 为 UUID，不暴露真实身份
- 用户名唯一约束防止身份重复注册
- 审计日志详情为 JSON 序列化，不含密码等敏感信息

测试：`test_no_plaintext_in_audit_details`, `test_username_normalization_in_db`

---

## 五、S7（输出白名单）

- 审计日志仅写入本地 SQLite
- CLI 输出为终端表格/文本，不生成文件
- 不发起到外部系统的连接

---

## 六、级联一致性

- 删除用户 → 其项目角色覆盖自动级联删除（FK ON DELETE CASCADE）
- 停用用户 → 即使有项目角色覆盖也不可绕过

测试：`test_project_role_cascade_on_user_delete`, `test_inactive_user_cannot_bypass_with_project_role`