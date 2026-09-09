# P4 报告生成 — v2.2.0

> 版本：v2.2.0 | 子功能：团队/个人画像报告生成
> 代码位置：`fp_sentinel/reporting/profile_report.py`
> 测试文件：`tests/unit/test_profile_report.py`

---

## 一、概述

开发者画像 Markdown 报告生成器，输出团队报告（健康度 + 四指标 + 关键发现 + Top N 个人表 + 下月目标）
和个人报告（六维度 + 团队平均对比 + 建议）。

---

## 二、隐私声明常量

### PRIVACY_BANNER（报告头部固定）
```
画像数据仅用于培训与能力提升，不用于绩效考核、评级或任何人事决策。
数据仅存储于本地 SQLite，不上传网络。
```

### REPORT_FOOTER（报告脚注）
```
别名化与本地加密仅为本地保护措施，本地保护非强加密；
如需移除个人数据，请使用 profile forget <alias>。
```

---

## 三、核心函数签名

```python
def check_reveal_allowed(reveal_flag: bool, env_value=None) -> bool
    """reveal 双条件校验：reveal_flag=True + FP_SENTINEL_REVEAL=1"""

def validate_output_path(path: str, base_dir=None) -> Path
    """S7 白名单校验：resolve 后必须在 base_dir 内"""

def save_report(markdown, filename, base_dir=None) -> Path
    """写入白名单输出目录"""

def generate_team_report(team: TeamProfile, reveal=False, top_n=5) -> str
    """生成团队报告 Markdown"""

def generate_personal_report(profile: DeveloperProfile, team_metrics=None, reveal=False) -> str
    """生成个人报告 Markdown"""
```

---

## 四、团队报告章节结构

1. **团队健康度** (health_score/100, findings 总数, 归因覆盖率)
2. **四指标 vs 行业基准** (密度/修复速度/复犯率/高危占比 + 分项得分)
3. **关键发现** (超基准项自动提取 + 覆盖率不足警示)
4. **Top N 个人画像** (除非 reveal 否则仅显示别名)
5. **下月目标** (算法自动生成建议值)

---

## 五、个人报告章节结构

1. **六维度画像** (偏好/修复速度/修复质量/复犯率/盲区/趋势)
2. **与团队匿名平均对比** (修复时长 + 复犯率 + 高危占比)
3. **建议** (针对知识盲区、修复慢、复发给出提示)

---

## 六、reveal 三重门控

```python
# CLI 层（profile_commands.py）
def _resolve_reveal(reveal: bool, i_am_security_officer: bool) -> bool:
    if not check_reveal_allowed(reveal): return False
    if not i_am_security_officer: return False
    return True
```

CLI 参数层：`--reveal` + `--i-am-security-officer` + `FP_SENTINEL_REVEAL=1` 缺一不可。

---

## 七、S7 输出白名单实现

```python
def validate_output_path(path, base_dir=None):
    base = Path(base_dir or "reports").resolve()
    target = Path(path).resolve()
    if base != target and base not in target.parents:
        raise ValueError("路径穿越被拒绝（S7 白名单）")
    return target
```

目标路径 resolve 后必须是 base 本身或 base 的子路径。

---

## 八、测试结果

```
test_team_report_contains_privacy_banner_and_footer PASSED
test_team_report_default_anonymous PASSED
test_team_report_reveal_shows_display_name PASSED
test_reveal_gate_requires_env_and_flag PASSED
test_personal_report_includes_team_average PASSED
test_validate_output_path_rejects_traversal PASSED
test_save_report_writes_into_whitelist_dir PASSED
```

7/7 通过 (2026-09-07)
