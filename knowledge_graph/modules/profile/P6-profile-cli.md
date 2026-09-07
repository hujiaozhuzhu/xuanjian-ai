# P6 CLI 集成 — v2.2.0

> 版本：v2.2.0 | 子功能：CLI profile 命令组
> 代码位置：`fp_sentinel/cli/profile_commands.py`
> 测试文件：`tests/unit/test_profile_cli.py`

---

## 一、概述

profile 子命令组，通过 `profile_app = typer.Typer()` 暴露，由 Agent-Attack
在 `fp_sentinel/cli/__init__.py` 中 `app.add_typer(profile_app, name="profile")` 注册。
**本模块不修改 cli/__init__.py**（领地约定）。

---

## 二、命令清单

| 命令 | 用途 | 关键参数 |
|------|------|---------|
| `profile team` | 生成团队画像报告 Markdown | --month --kloc --output --reveal --top |
| `profile me` | 查看本人画像（个人视角） | --alias --output --reveal |
| `profile forget <alias>` | 删除画像库别名数据 | --yes |
| `profile scan <path>` | 扫描项目 + 只读 git 归因入库 | --lang --max-records |
| `profile build` | 对已有 findings 补做归因入库 | --max-records |
| `profile mark-fixed <finding_id>` | 标记 finding 为已修复（修复速度维度） | — |

---

## 三、命令实现要点

### `profile team`
- 加载 findings + attributions + fixes
- 构建 TeamProfile
- 生成 Markdown 报告
- reveal 解密姓名仅当三联通过
- 写入 --output 白名单目录

### `profile me`
- 未指定别名：列出匿名别名列表 + 发现数摘要
- 指定别名：过滤自己 findings -> analyze_developer -> 生成个人报告
- 别名支持 16 位 hash 或原始 email（自动转换）

### `profile forget`
- 支持 alias hash 或 email 输入
- 默认需交互确认（`typer.confirm`），`--yes` 跳过
- 调用 ProfileRepo.forget_alias 三元组删除
- 反馈每表删除行数

### `profile scan`
- 复用 ScannerManager + ResultNormalizer 执行扫描
- 扫描完成后 attribute_and_store 入库
- 归因覆盖率实时输出
- 非 git 目录优雅降级提示

### `profile build`
- 从数据库找出未归因的 findings
- 取最近一条扫描历史做项目根目录
- 调用 attribute_and_store 补做归因

### `profile mark-fixed`
- 验证 finding 存在且含 fingerprint
- 调用 ProfileRepo.record_fix 写入 finding_status

---

## 四、reveal 第三方校验链路

```
用户输入 --reveal
  -> _resolve_reveal(reveal=True, i_am_security_officer=True)
    -> check_reveal_allowed(reveal=True)
      -> FP_SENTINEL_REVEAL == "1" 环境变量
```

任一步失败则仅显示 alias 别名。

---

## 五、注册方式

```python
# fp_sentinel/cli/__init__.py 中由 Agent-Attack 收尾注册
try:
    from .profile_commands import profile_app
    app.add_typer(profile_app, name="profile", help="开发者画像")
except ImportError:
    pass
```

try-import 优雅降级：profile_commands 不存在时主 CLI 仍可用。

---

## 六、依赖关系

```
profile_commands.py
  -> config.expand_db_path / load_config
  -> database (FindingRepo / ScanHistoryRepo / ProjectRepo / get_database)
  -> models.ScanTool
  -> profile.attribution.attribute_and_store
  -> profile.analyzer.build_team_profile / analyze_developer / compute_team_health
  -> profile.models (ProfileRepo / alias_hash / ensure_profile_tables / get_profile_key / decrypt_name)
  -> reporting.profile_report (save_report / generate_team_report / generate_personal_report / check_reveal_allowed)
  -> scanners.ScannerManager / ResultNormalizer
  -> cli.terminal.create_console
```

---

## 七、测试结果

```
test_profile_app_exists_and_has_commands PASSED
test_profile_me_empty_db PASSED
test_profile_forget_removes_alias PASSED
test_profile_forget_declines_without_confirm PASSED
test_profile_team_generates_report PASSED
test_profile_mark_fixed PASSED
```

6/6 通过 (2026-09-07)

---

## 八、领地约定遵守

- [x] 未修改 `fp_sentinel/cli/__init__.py`
- [x] 未修改 `fp_sentinel/models.py`
- [x] 未修改 `fp_sentinel/database/*`
- [x] 未修改任何 Agent-Attack 领地模块
- [x] 测试文件名使用 `test_profile_` 前缀，互不覆盖
- [x] 画像库只新增表，不改动既有 findings/projects 等表
