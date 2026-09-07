# P3 画像算法 — v2.2.0

> 版本：v2.2.0 | 子功能：画像算法（六维度 + 团队健康度）
> 代码位置：`fp_sentinel/profile/analyzer.py`
> 测试文件：`tests/unit/test_profile_analyzer.py`

---

## 一、概述

画像算法子系统，实现开发者六维度画像与团队健康度评分。
对齐迭代计划框架 5.2 + P3 验收标准。

---

## 二、六维度画像

### 维度 1：漏洞模式偏好
- 实现：`cwe_counts` 按 CWE 计数，取 top3
- 代码路径：`_cwe_counts` + `DeveloperProfile.cwe_top3`

### 维度 2：修复速度
- 实现：finding 首次发现 -> mark fixed 的时间差（FindingStatus 表）
- 无数据置空（None），不猜测
- 代码路径：`compute_avg_fix_hours`

### 维度 3：修复质量
- 实现：修复后 30 天内同文件同 CWE 未复发比例
- 复发判定：fix_at < g.created_at && (g.created_at - fix_at).days <= 30 && 同文件同 CWE
- 代码路径：`compute_fix_pass_rate`

### 维度 4：复犯率
- 实现：同 fingerprint 在更早时间已出现过的 finding 占比
- 按时间排序，set 追踪已见 fingerprint
- 代码路径：`compute_repeat_rate`

### 维度 5：知识盲区
- 实现：占比 > 50%（非 30% 因为框架 5.2 要求更严格）的 CWE 类型
- 条件：cnt >= 2 && cnt/total > 0.50
- 代码路径：`analyze_developer -> knowledge_gaps`

### 维度 6：成长趋势
- 实现：按月 finding 数线性斜率（最小二乘法）
- 负值 = 改善，正值 = 恶化，不足 2 个月数据 = 0.0
- 代码路径：`_trend_slope`

---

## 三、团队健康度（0-100）

### 加权公式
```
健康度 = 密度分(30) + 修复速度分(30) + 复犯率分(25) + 高危占比分(15)
```

| 分项 | 权重 | 基准 | 计分逻辑 |
|------|------|------|---------|
| 漏洞密度 | 30 | 1.2/千行 | density <= 基准 满分；无 kloc 数据记中性 15 分 |
| 修复速度 | 30 | 72h | avg_fix <= 基准 满分；无数据记中性 15 分 |
| 复犯率 | 25 | 20% | repeat <= 基准 满分 |
| 高危占比 | 15 | 10% | high_ratio <= 基准 满分 |

单项线性递减 clamp 到 [0, 满分]。

### 常量
```python
DENSITY_BASELINE = 1.2          # 漏洞数 / 千行
FIX_SPEED_BASELINE_H = 72.0     # 平均修复时长（小时）
REPEAT_BASELINE = 0.20          # 复犯率
HIGH_RISK_BASELINE = 0.10       # 高危占比
RECURRENCE_WINDOW_DAYS = 30     # 修复质量复发窗口
```

---

## 四、核心函数签名

```python
def filter_by_period(findings, period) -> List[Finding]
def _trend_slope(findings) -> float
def _cwe_counts(findings) -> Dict[str, int]
def compute_repeat_rate(findings) -> float
def compute_avg_fix_hours(findings, fix_events) -> Optional[float]
def compute_fix_pass_rate(findings, fix_events) -> Optional[float]
def analyze_developer(alias, findings, fix_events=None, period=None, display_name=None) -> DeveloperProfile
def compute_team_health(findings, kloc=None, fix_events=None) -> Tuple[float, Dict]
def build_team_profile(findings, attributions, period=None, fix_events=None, kloc=None, display_names=None) -> TeamProfile
```

---

## 五、团队画像组装流程

1. 按 period 过滤 findings
2. fingerprint -> alias_hash 映射（来自 attributions）
3. 按 alias 分组计算各成员画像（未归因 -> unknown）
4. 全体 findings 计算团队健康度
5. 统计归因覆盖率
6. members 按发现数降序排列

---

## 六、金标准测试数据集

构造 3 虚拟作者、跨 2 个月（2026-07 ~ 2026-08）的合成 findings：
- alice: 6 条（CWE-89 x4、CWE-79 x2），复犯 1 次，修复 +24h 后复发
- bob: 2 条（CWE-79、CWE-798），均 +24h 修复，无复发
- carol: 3 条（CWE-89 x2、CWE-22 x1），1 条 +240h 修复

手工推算期望值，验证六维度 + 团队健康度。

---

## 七、测试结果

```
test_alice_cwe_preference_and_gaps PASSED
test_alice_repeat_rate PASSED
test_alice_fix_speed PASSED
test_alice_fix_quality_recurrence_detected PASSED
test_bob_clean_fix_quality PASSED
test_carol_trend_single_month_and_fix_speed PASSED
test_alice_trend_negative_is_improving PASSED
test_no_fix_data_leaves_empty_not_guessed PASSED
test_period_filter PASSED
test_team_health_gold_standard PASSED
test_team_health_neutral_when_no_fix_data PASSED
test_team_health_neutral_density_without_kloc PASSED
test_team_health_perfect_inputs PASSED
test_build_team_profile_members_and_coverage PASSED
test_build_team_profile_unattributed_goes_unknown PASSED
```

15/15 通过 (2026-09-07)
