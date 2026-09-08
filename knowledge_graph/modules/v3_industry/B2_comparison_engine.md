# B2 - 跨行业对比分析功能设计

> **对应文件**: `fp_sentinel/industry_benchmark/comparison.py`, `engine.py`
> **版本**: v3.0.0
> **核心类**: `CrossIndustryAnalyzer`, `BenchmarkEngine`

---

## 1. 差距分析引擎 (BenchmarkEngine)

### 1.1 设计目标

将企业安全指标与行业基准进行对比，生成差距分析报告，量化企业在行业中的安全水位。

### 1.2 四维差距分析模型

```
┌────────────────────────────────────────────┐
│         BenchmarkEngine.analyze()          │
├────────────────────────────────────────────┤
│                                            │
│  维度1: 漏洞密度 (vuln_density)            │
│    ┌──────────────────────────┐            │
│    │ enterprise_density vs    │            │
│    │ industry_avg             │            │
│    └──────────────────────────┘            │
│                                            │
│  维度2: 修复速度 (repair_speed)            │
│    ┌──────────────────────────┐            │
│    │ enterprise_avg_days vs   │            │
│    │ industry_avg_days        │            │
│    └──────────────────────────┘            │
│                                            │
│  维度3: 合规评分 (compliance)              │
│    ┌──────────────────────────┐            │
│    │ enterprise_score vs      │            │
│    │ industry_target (80%)    │            │
│    └──────────────────────────┘            │
│                                            │
│  维度4: 覆盖范围 (coverage)                │
│    ┌──────────────────────────┐            │
│    │ category_coverage vs     │            │
│    │ 80% target               │            │
│    └──────────────────────────┘            │
│                                            │
│  ──→ GapAnalysisReport                     │
└────────────────────────────────────────────┘
```

### 1.3 差距分类算法

```python
def _classify_gap(gap_ratio: float, lower_is_better: bool = True) -> GapSeverity:
    # gap_ratio = (enterprise_value - industry_avg) / industry_avg
    # lower_is_better=True: 正差距 = 更差（修复天数、漏洞密度等）
    # lower_is_better=False: 负差距 = 更差（合规评分等）
```

**差距比率与严重度映射 (lower_is_better=True)**:

| gap_ratio | 严重度 | 含义 |
|-----------|--------|------|
| >= 0.50 | CRITICAL | 企业比行业差 50% 以上 |
| >= 0.25 | HIGH | 企业比行业差 25%-50% |
| >= 0.10 | MEDIUM | 企业比行业差 10%-25% |
| >= -0.05 | ON_PAR | 企业与行业持平 |
| < -0.05 | AHEAD | 企业优于行业 |

**差距比率与严重度映射 (lower_is_better=False，合规评分)**:

| gap_ratio | 严重度 | 含义 |
|-----------|--------|------|
| <= -0.30 | CRITICAL | 企业比行业目标低 30% 以上 |
| <= -0.15 | HIGH | 企业比行业目标低 15%-30% |
| <= -0.05 | MEDIUM | 企业比行业目标低 5%-15% |
| <= 0.05 | ON_PAR | 企业与行业目标持平 |
| > 0.05 | AHEAD | 企业优于行业目标 |

### 1.4 严重度到分数转换

```python
SEVERITY_SCORES = {
    GapSeverity.CRITICAL: 20.0,
    GapSeverity.HIGH: 40.0,
    GapSeverity.MEDIUM: 60.0,
    GapSeverity.ON_PAR: 75.0,
    GapSeverity.LOW: 85.0,
    GapSeverity.AHEAD: 95.0,
}
```

整体分数 = 各维度分数均值，最终严重度取各维度中最差者。

### 1.5 改进路线图生成

**优先级排序逻辑**:
1. CRITICAL 维度优先
2. HIGH 维度次之
3. MEDIUM 维度随后
4. ON_PAR 和 AHEAD 不生成建议

**路由建议格式**:
```
[P1] vulnerability_density: Prioritize critical and high vulnerability remediation | Implement automated regression testing | ...
[P1] compliance: Immediate remediation needed. Key gaps: GB/T 22239-2019 三级-8.1.3, 个人信息保护法-第51条, ...
[P2] repair_speed: Establish SLA-based repair timelines, automate patch management
```

### 1.6 关键发现 (Highlights) 生成

自动汇总以下关键发现：
- 所有 CRITICAL/HIGH 维度的差距描述
- 行业 TOP 3 威胁需关注的提示
- 修复速度与企业行业均值的对比结果

### 1.7 边界处理

- `sample_size=0` → 返回 ON_PAR，提示数据不足
- `scan_count=0` → 密度按 0 处理
- `industry_avg_repair_days=0` → 差距比率为 0
- `industry_cats=空` → 覆盖率为 0

### 1.8 BenchmarkEngine 类 API

```python
class BenchmarkEngine:
    def __init__(benchmark: Optional[BenchmarkDataset] = None)
    def set_benchmark(benchmark: BenchmarkDataset) -> None
    def get_benchmark() -> Optional[BenchmarkDataset]
    def analyze(enterprise: EnterpriseMetrics, benchmark: Optional[BenchmarkDataset] = None) -> GapAnalysisReport
```

便捷函数:
```python
def compare_enterprise_to_industry(enterprise, benchmark=None) -> GapAnalysisReport
```

---

## 2. 跨行业对比分析器 (CrossIndustryAnalyzer)

### 2.1 设计目标

从宏观视角对比 11 个行业在 6 个维度上的安全能力差异，识别各行业的安全水位。

### 2.2 六个对比维度

| # | 维度键 | 中文说明 | 计算方式 | 最优方向 |
|---|--------|---------|---------|---------|
| 1 | `avg_repair_days` | 平均修复周期 | `repair_cycle.overall_avg_days` | 越低越好 |
| 2 | `vuln_density` | 漏洞密度 | `sum(count for vuln_distribution)` | 越低越好 |
| 3 | `critical_ratio` | 严重漏洞占比 | `count(CRITICAL) / total * 100` | 越低越好 |
| 4 | `top_category_pct` | 主导类别集中度 | `max(percentage for vuln_distribution)` | 越低越好 |
| 5 | `compliance_count` | 合规要求数量 | `len(compliance_requirements)` | 越高越好 |
| 6 | `scenario_count` | 行业场景数量 | `len(industry_scenarios)` | 越高越好 |

### 2.3 对比分析流程

```
CrossIndustryAnalyzer
       │
       ├── compare_dimension(dimension)
       │      └─ 计算所有行业在该维度上的值
       │      └─ 排序确定 best/worst
       │      └─ 生成分析文本 (行业间差异 spread)
       │
       ├── compare_all_dimensions()
       │      └─ 对 6 个维度循环调用 compare_dimension
       │
       └── generate_report(industries?)
              └─ 执行 compare_all_dimensions
              └─ 构建行业排名 (industry_rankings)
              └─ 生成摘要文本
              └─ 返回 CrossIndustryReport
```

### 2.4 CrossIndustryReport 结构

```python
class CrossIndustryReport(BaseModel):
    report_id: str                    # 报告ID (格式: cross-{uuid12})
    comparisons: List[CrossIndustryComparison]  # 各维度对比
    summary: str                      # 摘要文本
    industry_rankings: Dict[str, List[Industry]]  # 各维度行业排名
```

### 2.5 排名逻辑说明

**越低越优维度** (`avg_repair_days`, `vuln_density`, `critical_ratio`, `top_category_pct`):
- 升序排列 → 第一个 = 最佳，最后 = 最差

**越高越优维度** (`compliance_count`, `scenario_count`):
- 降序排列 → 第一个 = 最佳，最后 = 最差

### 2.6 CrossIndustryAnalyzer 类 API

```python
class CrossIndustryAnalyzer:
    def __init__(benchmarks: Optional[Dict[Industry, BenchmarkDataset]] = None)
    def set_benchmarks(benchmarks: Dict[Industry, BenchmarkDataset]) -> None
    def compare_dimension(dimension: str) -> CrossIndustryComparison
    def compare_all_dimensions() -> List[CrossIndustryComparison]
    def generate_report(industries: Optional[List[Industry]] = None) -> CrossIndustryReport
    def get_industry_ranking(dimension: str) -> List[Industry]
```

便捷函数:
```python
def generate_cross_industry_report(industries=None) -> CrossIndustryReport
```

### 2.7 维度对比结果结构

```python
class CrossIndustryComparison(BaseModel):
    industries: List[Industry]     # 参与对比的行业列表
    dimension: str                  # 对比维度
    values: Dict[str, float]        # 行业标识 -> 指标值
    best_industry: Optional[Industry]   # 最佳行业
    worst_industry: Optional[Industry]  # 最差行业
    analysis: str                   # 自动分析结论
```

---

## 3. 分析报告输出示例

### 3.1 差距分析报告 (GapAnalysisReport)

```
报告ID: gap-a3f7b2c91e4d
行业: internet (互联网)
企业名称: TestCo
整体得分: 68.5 / 100
整体严重度: MEDIUM

维度差距:
  ├─ vulnerability_density: HIGH (企业 66.7/扫描 vs 行业 24.15/扫描, +176%)
  ├─ repair_speed: ON_PAR (企业 10.0天 vs 行业 15.8天, -37%)
  ├─ compliance: MEDIUM (企业 75.0% vs 行业目标 80.0%, -6%)
  └─ coverage: ON_PAR (覆盖 50% 类别, 缺失 5 个)

关键发现:
  ⚠ vuln_density: 企业漏洞密度远超行业均值 +176%
  ℹ 需关注的行业TOP威胁: 水平越权, SQL注入, 垂直越权
  ℹ 修复速度(10.0天)优于行业均值(15.8天)

改进路线:
  [P1] vulnerability_density: 优先修复严重/高危漏洞, 实施自动化回归测试
  [P1] compliance: 按 GB/T 22239-2019 补齐差距
```

### 3.2 跨行业报告 (CrossIndustryReport)

```
报告ID: cross-b8e2d4f6a1c3
行业数量: 11

修复周期排名 (从快到慢):
  1. securities (9.8天) ← 最佳
  2. finance (11.5天)
  3. insurance (15.2天)
  ...
  11. industrial_ctrl (35.0天) ← 最差

平均修复周期: 最佳=securities(9.8天), 最差=industrial_ctrl(35.0天), 行业差异=257%
安全成熟度(场景数): 最佳=internet/finance/healthcare(2个), 行业差异=0%
```

---

## 4. 核心算法速查

| 函数 | 文件 | 说明 |
|------|------|------|
| `_classify_gap` | engine.py | 差距比率 -> 严重度分级 |
| `_compute_vuln_density_gap` | engine.py | 漏洞密度维度计算 |
| `_compute_repair_speed_gap` | engine.py | 修复速度维度计算 |
| `_compute_compliance_gap` | engine.py | 合规评分维度计算 |
| `_compute_coverage_gap` | engine.py | 覆盖范围维度计算 |
| `_severity_to_score` | engine.py | 严重度 -> 评分转换 |
| `_overall_severity_from_categories` | engine.py | 综合严重度取最差 |
| `_generate_highlights` | engine.py | 关键发现自动提取 |
| `_generate_roadmap` | engine.py | 改进路线按优先级排序 |
| `compare_dimension` | comparison.py | 单维度跨行业对比 |
| `generate_report` | comparison.py | 全维度报告生成 |
