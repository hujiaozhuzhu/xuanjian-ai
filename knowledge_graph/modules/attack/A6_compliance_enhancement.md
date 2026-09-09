# A6. 合规增强

> 版本：v2.2.0 | 文件：`fp_sentinel/reporting/fix_advisor.py` + `compliance_report.py`
> 数据源：`database/repositories.FindingRepo` + `ScanHistoryRepo`

## A6-1. Diff 修复建议生成器

### 覆盖范围

高频 15 类规则（按规则 ID 子串匹配，顺序优先级：os.system > ecb > sql > xss > cmd > path > secret > jwt > yaml > pickle > eval > ssrf > md5 > debug > redirect）：

| # | 规则键 | 标题 | 工时 |
|---|--------|------|------|
| 1 | sqli | SQL 注入 | 45min |
| 2 | xss | XSS | 30min |
| 3 | cmd | 命令注入 | 60min |
| 4 | path | 路径遍历 | 45min |
| 5 | secret | 硬编码密钥 | 30min |
| 6 | jwt | JWT 弱密钥/算法 | 30min |
| 7 | yaml | YAML 不安全加载 | 15min |
| 8 | pickle | Pickle 反序列化 | 60min |
| 9 | eval | eval 代码注入 | 45min |
| 10 | os.system | os.system 命令执行 | 45min |
| 11 | ssrf | SSRF | 60min |
| 12 | md5 | 弱哈希 MD5/SHA1 | 30min |
| 13 | ecb | ECB 模式加密 | 60min |
| 14 | debug | 调试模式暴露 | 15min |
| 15 | redirect | 开放重定向 | 30min |

### Diff 生成流程（S2 红线：仅字符串不落盘）

1. `_match_key(rule_id)` → 优先级匹配（os.system 优先）
2. `_extract_bad_lines(code_snippet, bad_patterns)` → 只读提取命中行
3. `_build_diff(filename, bad_lines, good_example)` → unified-diff 样式字符串

```python
@dataclass
class FixSuggestion:
    rule_id: str
    title: str
    diff: str                    # 纯展示 diff 字符串
    effort_minutes: int
    reference_cve: str
    incident_note: str           # 事故背景说明
    generic: bool                # 是否回退通用建议
```

### 安全红线
- **S2**：所有建议仅为 diff 字符串，不修改任何源文件
- **零网络**：纯正则匹配，无 I/O

### 测试结果

```
tests/unit/test_fix_advisor.py — 用例 16
- TestRuleCoverage（8）: ≥15 类别覆盖 + 8 个特定规则建议验证
- TestDiffFormat（8）: diff 结构、字符串非文件、incident_note 存在、xss/ssrf/debug/redirect 建议
结果：16 PASSED
```

## A6-2. 合规报告增强

### 报告章节

```
① 趋势对比      本次/上次/变化指纹对比表（无历史 → "首期基线"）
② 需关注        ROI 排序：严重度权重 ↑ 工时 ↓（先修低工时高危）
③ Diff 修复建议  复用 fix_advisor 生成的 diff 块
④ 声明           "修复建议仅为 diff 字符串，工具不修改源文件"
```

### 趋势对比算法

`compute_trend(finding_repo, history_repo, project_path, ...)`：
1. 本次 findings：优先使用调用方显式传入（避免未持久化误报为"全部已修复"）
2. 上次扫描：按 project_path 过滤历史，按 timestamp 倒序取相邻扫描
3. fingerprint 对比：新增 / 已修复 / 遗留三集划分
4. 无历史数据 → `is_baseline=True`，显示"首期基线"不崩溃

### ROI 排序

```python
_SEVERITY_WEIGHT = {"CRITICAL": 100, "HIGH": 60, "MEDIUM": 30, "LOW": 10, "INFO": 1}

def _roi_sort_key(pair):
    finding, sug = pair
    return (-_SEVERITY_WEIGHT[sev], sug.effort_minutes)
```

### 安全红线
- **S2**：Diff 建议仅以字符串展示，不修改源文件
- **S7**：报告写入走 attack_report 白名单校验

### 测试结果

```
tests/unit/test_compliance_report.py — 用例 9
- TestTrend（4）: 首期基线、新增/修复/遗留、项目历史边界、未持久化 findings 兜底
- TestReportContent（5）: 基线报告、趋势表计数、diff 块存在、ROI 排序、零文件修改
结果：9 PASSED
```

## 变更说明

| 文件 | 变更 |
|------|------|
| `fp_sentinel/reporting/fix_advisor.py` | 新建，314 行，15 类规则映射 + diff 生成 |
| `fp_sentinel/reporting/compliance_report.py` | 新建，246 行，趋势计算 + ROI 排序 |
