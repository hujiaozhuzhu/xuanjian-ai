# A7. CLI 集成

> 版本：v2.2.0 | 文件：`fp_sentinel/cli/__init__.py` + `fp_sentinel/cli/attack_commands.py`
> 框架：typer

## 设计要点

### 命令一览

| 命令 | 功能 | 参数 |
|------|------|------|
| `fp-sentinel scan --report compliance` | 合规报告（默认） | project_path, --lang, --scanner, ... |
| `fp-sentinel scan --report attack` | 攻防报告 | 同上 |
| `fp-sentinel scan --report all` | 双报告 | 同上 |
| `fp-sentinel scan --report none` | 仅扫描 | 同上 |
| `fp-sentinel attack purge` | 清理 >30 天攻防数据 | --days |
| `fp-sentinel attack-purge` | 顶层别名（同 attack purge） | --days |
| `fp-sentinel version` | 显示版本 v2.2.0 | -- |

### scan 命令扩展

新增 `--report [compliance|attack|all|none]`（默认 compliance，向后兼容）与 `--output ./reports/`（S7 白名单目录）。

**报告生成流水线**（`_generate_reports()`）：
1. compliance：`compute_trend(...)` → `generate_compliance_report(...)`
2. attack：`build_attack_data(...)` → `generate_attack_report(...)` → `save_attack_records(...)`（S5 落库）

### 攻防数据落库（S5）

`attack_poc_records` 表（SQLite，攻击数据独立于 findings 表）：
- 字段：project_path, rule_id, file_path, line_start, vuln_type, poc_text, verify_status, probability, created_at
- 索引：created_at（供 purge 按时间清理）
- 保留策略：默认 30 天，可通过 `--days` 调整

### purge 实现

```python
async def purge_attack_records(db, days=30) -> int:
    cutoff = (now - timedelta(days=days)).isoformat()
    DELETE FROM attack_poc_records WHERE created_at < cutoff
    return deleted_count
```

### 子命令注册（cli/__init__.py）

```python
# 攻防子命令
try:
    from .attack_commands import attack_app, attack_purge_entry
    app.add_typer(attack_app, name="attack")
    app.command("attack-purge")(attack_purge_entry)
except ImportError:
    pass

# profile 子命令（Agent-Profile 领地，由 Agent-Attack 统一注册）
try:
    from .profile_commands import profile_app
    app.add_typer(profile_app, name="profile")
except ImportError:
    pass  # 模块未就绪时优雅降级
```

### 安全红线
- **S1**：PoC 生成经 `_assert_local`，目标默认 127.0.0.1
- **S2**：仅生成报告/diff 字符串，不修改源文件
- **S5**：攻防数据 created_at 落库 + attack-purge 清理
- **S7**：报告写入走 `resolve_output_path` 白名单

## 测试结果

```
tests/unit/test_attack_cli.py — 用例 10
- TestScanReportOption（4）: --report 帮助、非法类型拒绝、none 不生成、attack 生成 md
- TestAttackPurge（4）: purge 命令注册、attack 子命令注册、purge 运行、profile 优雅降级
- TestVersion（2）: __version__ == "2.2.0"、version 命令输出含 "2.2.0"
结果：10 PASSED
```

## 变更说明

| 文件 | 变更 |
|------|------|
| `fp_sentinel/cli/__init__.py` | 扩展 scan --report/--output 参数；注册 attack/attack-purge/profile 子命令 |
| `fp_sentinel/cli/attack_commands.py` | 新建，232 行，build_attack_data + save/purge + CLI 命令定义 |
