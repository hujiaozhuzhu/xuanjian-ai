# P1 画像数据模型 — v2.2.0

> 版本：v2.2.0 | 子功能：画像数据模型 + SQLite 表
> 代码位置：`fp_sentinel/profile/models.py`
> 测试文件：`tests/unit/test_profile_models.py`

---

## 一、概述

画像模块的模型层，定义 pydantic 数据类与 SQLite 画像库表（只增不改既有表），
并提供 ProfileRepo 仓库操作类。

安全红线声明：
- 画像数据仅存储于本地 SQLite，禁止网络上传
- 开发者身份默认 SHA256 别名化，不存明文 email
- display_name 为可选本地弱加密存储（**本地保护非强加密**）
- 本模块不提供"评分导出为绩效格式"的任何接口

---

## 二、pydantic 模型

### AttributionRecord
单条归因记录（fingerprint -> 别名）。落盘结构不含任何 email/姓名明文。

| 字段 | 类型 | 说明 |
|------|------|------|
| finding_fingerprint | str | Finding 指纹 |
| alias_hash | str | SHA256 别名（前 16 位） |
| file | Optional[str] | 相对路径 |
| line | Optional[int] | 归因命中行号 |
| committed_at | Optional[str] | 提交时间 ISO |
| created_at | Optional[str] | 入库时间 ISO |

### DeveloperProfile
开发者画像（六维度）。

| 字段 | 类型 | 说明 |
|------|------|------|
| alias | str | SHA256 别名或 unknown |
| display_name | Optional[str] | reveal 模式解密展示 |
| period | Optional[str] | 统计周期（如 2026-08） |
| total_findings | int | 周期内发现总数 |
| scans_contributed | int | 贡献过的扫描日期数 |
| vuln_counts_by_cwe | Dict[str,int] | CWE 分布 |
| cwe_top3 | List[str] | CWE 偏好 top3 |
| avg_fix_hours | Optional[float] | 平均修复时长，无数据置空 |
| fix_pass_rate | Optional[float] | 修复质量 30 天未复发率 |
| repeat_rate | float | 复犯率 |
| knowledge_gaps | List[str] | 占比>50% 的 CWE（盲区） |
| trend | float | 月度发现数线性斜率 |

### TeamProfile
团队画像。

| 字段 | 类型 | 说明 |
|------|------|------|
| period | str | 统计周期 |
| members | List[DeveloperProfile] | 成员画像（匿名） |
| health_score | float | 0-100 健康度 |
| metrics | Dict | 团队四指标与分项得分 |
| findings | int | 周期内发现总数 |
| coverage | float | 归因覆盖率 0-1 |
| kloc | Optional[float] | 千行代码数 |

### FindingStatus
修复状态记录（仅 fixed 一种状态）。

---

## 三、SQLite 表（只增不改）

```sql
developer_alias(id, alias_hash UNIQUE, display_name_encrypted, created_at)
profile_snapshot(id, alias_hash, period, metrics_json, created_at)
scan_attribution(id, finding_fingerprint, alias_hash, file, committed_at, created_at)
finding_status(id, fingerprint UNIQUE, status, marked_at, created_at)
```

索引：
- idx_scan_attribution_fp (finding_fingerprint)
- idx_scan_attribution_alias (alias_hash)
- idx_profile_snapshot_alias (alias_hash, period)
- idx_finding_status_fp (fingerprint)

通过 `ensure_profile_tables(db)` 幂等创建。

---

## 四、别名化算法

```python
_ALIAS_SALT = "fp-sentinel:alias:v1"

def alias_hash(identifier: str) -> str:
    normalized = (identifier or "").strip().lower()
    return hashlib.sha256((_ALIAS_SALT + normalized).encode("utf-8")).hexdigest()[:16]
```

- 确定性：同一 email 始终得到同一别名
- 不可逆：SHA256 单向，前缀加盐
- 定长 16 位十六进制

---

## 五、display_name 本地弱加密

- 密钥存于数据库同目录 `profile.key`（32 字节随机，hex 编码）
- 算法：SHA256 计数器模式流加密 + XOR
- 解密仅当 reveal 双条件通过时使用
- **明确声明：本地保护非强加密**

---

## 六、ProfileRepo 仓库方法

| 方法 | 说明 |
|------|------|
| upsert_alias | 插入/更新别名 |
| get_alias | 按别名查询 |
| list_alias_hashes | 列出所有别名 |
| save_attribution / save_attributions | 保存归因记录 |
| list_attribution | 查询归因记录 |
| save_snapshot / list_snapshots | 画像快照存取 |
| record_fix / list_fixes | 修复状态记录 |
| forget_alias | **仅删画像库三元组数据**（profile_snapshot / scan_attribution / developer_alias），不动 findings |

---

## 七、测试结果

```
test_ensure_profile_tables_creates_new_tables_only PASSED
test_alias_hash_deterministic_and_anonymized PASSED
test_name_encryption_roundtrip_and_no_plaintext PASSED
test_profile_repo_attribution_roundtrip PASSED
test_record_fix_and_list PASSED
test_forget_alias_keeps_findings_untouched PASSED
```

6/6 通过 (2026-09-07)
