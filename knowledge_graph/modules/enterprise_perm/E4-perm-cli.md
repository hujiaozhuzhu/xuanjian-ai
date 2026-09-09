# E4 CLI 命令集成 — v2.5.0

> 子功能：xuanjian perm 子命令组
> 代码位置：`fp_sentinel/cli/perm_commands.py`
> 测试文件：`tests/unit/test_enterprise_perm_cli.py`

---

## 一、概述

通过 `xuanjian perm` 子命令组暴露企业权限管理功能：
- 遵循与 profile/attack 子命令相同的注册模式
- 独立模块，在主 CLI 中通过 try/except 静默降级注册
- 所有命令使用 Rich Table 输出

---

## 二、命令列表

| 命令 | 说明 | 所需权限 |
|------|------|---------|
| perm user-add <username> --role <role> | 创建用户 | perm:manage |
| perm user-list [--all] | 列出用户 | perm:manage |
| perm user-role <username> <new_role> | 修改角色 | perm:manage |
| perm user-deactivate <username> | 停用用户 | perm:manage |
| perm project-grant <user> <project_id> --role <role> | 项目授权 | perm:manage |
| perm project-revoke <user> <project_id> | 项目撤销 | perm:manage |
| perm check <username> --perm <perm> [--project <id>] | 检查权限 | 任何人 |
| perm audit [--user] [--action] [--denied] [--limit] | 查看审计 | audit:view |
| perm roles | 查看权限矩阵 | 任何人 |

---

## 三、注册方式

在 `fp_sentinel/cli/__init__.py` 中：
```python
try:
    from .perm_commands import perm_app
    app.add_typer(perm_app, name="perm", help="企业权限管理")
except ImportError:
    pass
```

模块不可用时静默降级，不影响其他命令。

---

## 四、屏幕输出

- 表格使用 Rich `Table` 库
- 角色使用 style 标注：admin(magenta) / security_engineer(cyan) / developer(green)
- 激活状态使用颜色：激活(green) / 停用(red)
- 审计结果使用颜色：allowed(green) / denied(red)