# P5 隐私控制 — v2.2.0

> 版本：v2.2.0 | 子功能：隐私控制全套（融入各模块）
> 代码位置：`fp_sentinel/profile/models.py` + `fp_sentinel/reporting/profile_report.py` + `fp_sentinel/cli/profile_commands.py`
> 测试文件：`tests/unit/test_profile_privacy.py`

---

## 一、概述

隐私保护贯穿画像模块始终。对照迭代计划 S6 安全红线全部技术落实。

---

## 二、安全红线对照表

| 红线 | 技术落实 | 验证位置 |
|------|---------|---------|
| S6.1 开发者身份默认匿名化（SHA256 别名） | `alias_hash()` 确定性 SHA256 前 16 位 | test_alias_hash_deterministic_and_anonymized |
| S6.2 本人可查（profile me） | `profile me --alias` 列出个人数据 | test_profile_me_empty_db |
| S6.3 提供 `profile forget <alias>` | `ProfileRepo.forget_alias()` 三元组删除 | test_forget_alias_keeps_findings_untouched |
| S6.4 报告固定声明"不用于绩效考核" | PRIVACY_BANNER 头部 + REPORT_FOOTER 脚注 | test_team_report_contains_privacy_banner_and_footer |
| S6.5 不提供画像评分导出为绩效格式的接口 | 代码中无 export_performance/performance_export/export_score/hr_report/kpi/performance_review | test_no_performance_export_interface |
| S6.6 email 明文不落盘 | 归因流程 alias_hash 即时转换，落盘只有 hashes | test_attribute_findings_on_real_repo_no_plaintext |
| S6.7 display_name 可选存（本地加密） | encrypt_name/decrypt_name SHA256 流加密 | test_name_encryption_roundtrip_and_no_plaintext |

---

## 三、forget 命令实现

### 入口
`profile forget <alias> [--yes]`

### 删除范围（仅画像库三元组）
```python
async def forget_alias(self, alias_hash_: str) -> Dict[str, int]:
    for table, col in (
        ("profile_snapshot", "alias_hash"),
        ("scan_attribution", "alias_hash"),
        ("developer_alias", "alias_hash"),
    ):
        DELETE FROM {table} WHERE {col} = ?
```

### 不动内容
- findings 表（扫描结果）
- projects 表（项目）
- false_positive_marks（误报标记）
- 用户代码文件（**零文件操作**）

---

## 四、reveal 三重门控

```
--reveal (CLI 参数)
  AND --i-am-security-officer (CLI 参数，hidden=True)
  AND FP_SENTINEL_REVEAL=1 (环境变量)
```

任何一项不满足则保持匿名别名展示。

实现链：
1. `profile_commands._resolve_reveal()`: 检查 CLI 双参数
2. `profile_report.check_reveal_allowed()`: 检查环境变量

---

## 五、本地弱加密设计

### 密钥管理
- 文件路径：`{db_dir}/profile.key`（与 SQLite 数据库同目录）
- 生成方式：首次使用 os.urandom(32)，hex 编码存文件
- 生命周期：与数据库共存

### 加密算法
- SHA256 计数器模式 keystream + XOR
- 非对称加密强度不足，明确声明"本地保护非强加密"
- 密钥不在代码/数据库中硬编码

### 密文特征
- Base64 编码
- 不含明文片段
- 密钥错误返回 None（不抛异常给日志）

---

## 六、无绩效导出接口验证

代码审计确认 `profile_commands / analyzer / models / report` 四个模块中不存在：
- export_performance
- performance_export
- export_score
- hr_report
- kpi
- performance_review

任何意象形制化为 KPI/评级的接口均不存在。

---

## 七、测试结果

```
test_forget_alias_and_query_empty PASSED
test_db_stores_no_plaintext_email_or_name PASSED
test_no_performance_export_interface PASSED
test_reveal_helper_is_gated PASSED
```

4/4 通过 (2026-09-07)
