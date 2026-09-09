# A1 - 行业基准数据结构、数据来源与更新机制

> **对应文件**: `fp_sentinel/industry_benchmark/models.py`, `builtin_data.py`, `store.py`, `updater.py`
> **版本**: v3.0.0

---

## 1. 核心数据模型

### 1.1 Industry 枚举 (11 个行业)

```python
class Industry(str, Enum):
    INTERNET = "internet"
    FINANCE = "finance"
    GOVERNMENT = "government"
    INDUSTRIAL_CTRL = "industrial_ctrl"
    HEALTHCARE = "healthcare"
    EDUCATION = "education"
    TELECOM = "telecom"
    ENERGY = "energy"
    TRANSPORTATION = "transportation"
    INSURANCE = "insurance"
    SECURITIES = "securities"
```

### 1.2 基准数据集模型 (BenchmarkDataset)

```python
class BenchmarkDataset(BaseModel):
    industry: Industry                    # 行业标识
    version: str = "3.0.0"                # 数据集版本
    sample_size: int = 0                  # 样本规模
    vuln_distribution: List[VulnTypeStats]  # 漏洞类型分布
    repair_cycle: RepairCycle              # 修复周期统计
    top_vulnerabilities: List[TopVulnerability]  # TOP 10 漏洞
    compliance_requirements: List[ComplianceRequirement]  # 合规要求
    industry_scenarios: List[IndustryScenario]  # 行业特色场景
    metadata: BenchmarkMetadata            # 元数据
```

### 1.3 漏洞类型分布 (VulnTypeStats)

| 字段 | 类型 | 说明 |
|------|------|------|
| `category` | str | 漏洞类别键名（如 "INJECTION"） |
| `cwe` | Optional[str] | CWE 标识符（如 "CWE-89"） |
| `display_name` | str | 中文展示名 |
| `count` | int | 样本计数 |
| `percentage` | float | 占比 (0.0-100.0) |
| `avg_severity` | str | 平均严重度 |
| `trend` | str | 趋势：`rising` / `falling` / `stable` |

### 1.4 修复周期 (RepairCycle)

```python
class RepairCycle(BaseModel):
    critical_days: float    # 严重漏洞平均修复天数
    high_days: float        # 高危平均修复天数
    medium_days: float      # 中危平均修复天数
    low_days: float         # 低危平均修复天数
    overall_avg_days: float # 整体平均修复天数
```

### 1.5 TOP 10 常见漏洞 (TopVulnerability)

```python
class TopVulnerability(BaseModel):
    rank: int               # 排名 (1-100)
    rule_id: str            # 检测规则ID
    category: str           # 漏洞类别
    cwe: Optional[str]      # CWE 标识
    display_name: str       # 展示名称
    occurrence_rate: float  # 检出率 %
    severity: str           # 严重度
    description: str        # 详细描述
    compliance_refs: List[str]  # 合规引用
```

### 1.6 合规要求 (ComplianceRequirement)

```python
class ComplianceRequirement(BaseModel):
    ref_id: str             # 引用编号
    standard: str           # 标准名称
    section: str            # 条款
    description: str        # 要求描述
    related_cwes: List[str] # 关联 CWE 列表
    mandatory: bool         # 是否强制
```

### 1.7 行业特色场景 (IndustryScenario)

```python
class IndustryScenario(BaseModel):
    scenario_id: str            # 场景唯一ID
    title: str                  # 场景标题
    description: str            # 场景描述
    related_categories: List[str]  # 关联漏洞类别
    risk_level: str             # 风险级别
    mitigations: List[str]      # 缓解措施
```

### 1.8 差距分析模型

```python
class GapSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    ON_PAR = "on_par"
    AHEAD = "ahead"

class GapItem(BaseModel):
    category: str           # 差距维度
    industry_avg: float     # 行业均值
    enterprise_value: float # 企业值
    gap_ratio: float        # 差距比率
    severity: GapSeverity   # 差距严重度
    description: str        # 差距描述
    recommendation: str     # 改进建议

class CategoryGap(BaseModel):
    category_name: str          # 类别名
    items: List[GapItem]        # 差距项列表
    overall_severity: GapSeverity
    score: float                # 类别得分 (0-100)

class GapAnalysisReport(BaseModel):
    report_id: str              # 报告ID (格式: gap-{uuid12})
    enterprise_name: str        # 企业名称
    industry: Industry          # 行业
    overall_score: float        # 整体安全得分
    overall_severity: GapSeverity
    category_gaps: List[CategoryGap]
    highlights: List[str]       # 关键发现
    improvement_roadmap: List[str]  # 改进路线图
```

### 1.9 企业安全指标 (EnterpriseMetrics)

```python
class EnterpriseMetrics(BaseModel):
    project_name: str           # 项目名称
    industry: Industry          # 所属行业
    total_findings: int         # 总发现数量
    by_severity: Dict[str, int] # 按严重度分布
    by_category: Dict[str, int] # 按类别分布
    avg_repair_days: float      # 平均修复天数
    scan_count: int             # 扫描次数
    compliance_score: float     # 合规得分 (0-100)
    tech_stacks: List[str]      # 技术栈列表
```

### 1.10 模型设计特点

- **全量 Pydantic 验证**: 所有模型均使用 `ConfigDict(extra="forbid")` 或 `ConfigDict(extra="ignore")`
- **边界校验**: percentage (0-100)、rank (1-100)、compliance_score (0-100)、days (>=0)
- **序列化友好**: `Industry` 继承 `str, Enum` 支持 JSON 序列化

---

## 2. 数据来源

### 2.1 内置基准数据集 (Built-in Data)

文件: `builtin_data.py`

| 数据内容 | 说明 |
|---------|------|
| `INDUSTRY_METADATA` | 11 个行业的元数据（技术栈、风险画像） |
| `_DISTRIBUTION_DATA` | 11 行业的漏洞类型分布样本 (500 样本/行业) |
| `_REPAIR_CYCLES` | 11 行业的修复周期统计数据 |
| `_TOP_VULNS` | 11 行业各自的 TOP 10 漏洞 |
| `_COMPLIANCE_DATA` | 11 行业的合规要求 |
| `_SCENARIO_DATA` | 11 行业的特色漏洞攻击场景 |

### 2.2 数据来源声明

- **样本来源**: 基于公开安全报告（CNVD、CNNVD、NVD）与行业实践构建
- **样本周期**: 2025-Q1 ~ 2026-Q2
- **样本规模**: 每个行业 500 样本
- **置信度**: 0.95
- **安全红线**: S5（静态样本不连外网）、S6（权威来源引用）、S7（数据质量标注）

### 2.3 CNVD/CNNVD/NVD 引用（展示用）

模块声明了三个权威漏洞数据库作为数据来源引用（实际数据为内置静态样本，外部源默认禁用）：

| 源 | URL | 用途 |
|----|-----|------|
| CNVD | https://www.cnvd.org.cn | 中国国家漏洞库 |
| CNNVD | https://www.cnnvd.org.cn | 中国信息安全漏洞库 |
| NVD | https://nvd.nist.gov | 美国 NVD (CVE 来源) |

---

## 3. 更新机制

### 3.1 BenchmarkUpdater 类设计

文件: `updater.py`

```
┌─────────────────────────────────────────┐
│           BenchmarkUpdater              │
├─────────────────────────────────────────┤
│ - _policy: UpdatePolicy                 │
│ - _store: Optional[BenchmarkStore]      │
├─────────────────────────────────────────┤
│ + import_builtin_data(industry)         │
│ + import_all_builtin()                  │
│ + refresh_industry(industry)            │
│ + cleanup_old_records()                 │
│ + get_update_history()                  │
└─────────────────────────────────────────┘
```

### 3.2 更新策略 (UpdatePolicy)

```python
class UpdatePolicy(BaseModel):
    auto_update: bool = False       # 是否自动更新 (默认关闭)
    interval_days: int = 30         # 更新间隔 (天)
    retention_days: int = 180       # 历史保留天数 (S5)
    sources: List[UpdateSource]     # 数据源列表
```

### 3.3 两种策略模式

| 策略 | 函数 | auto_update | interval | retention | sources |
|------|------|:---:|:---:|:---:|:---:|
| 默认安全 | `create_default_policy()` | False | 30 天 | 180 天 | 全部禁用 |
| 激进更新 | `create_aggressive_policy()` | True | 7 天 | 90 天 | 全部启用 |

### 3.4 更新流程

```
refresh_industry(industry)
       │
       ├─ auto_update=True 且源启用 → _attempt_external_update()
       │                                   └─ 返回失败 (S1 红线，外部未实现)
       │
       └─ 否则 → import_builtin_data(industry)
                    └─ build_benchmark_dataset()
                    └─ store.save_benchmark() (可选)
                    └─ store.log_update() (可选)
                    └─ 返回 UpdateRecord
```

### 3.5 保留策略 (S5)

- `cleanup_old_records(retention_days)` 自动清理 update_log 中过期记录
- 默认保留 180 天
- 使用 `cutoff = now - timedelta(days=retention_days)` 计算删除阈值

### 3.6 更新记录 (UpdateRecord)

```python
class UpdateRecord(BaseModel):
    record_id: str          # 记录ID (格式: upd-{uuid12})
    source_id: str          # 数据源标识
    industry: Industry      # 行业
    updated_at: str         # ISO8601 时间戳
    changes_summary: str    # 变更摘要
    success: bool           # 是否成功
```

---

## 4. 持久化存储

### 4.1 SQLite 数据库结构

文件: `store.py`

**固定路径**: `~/.xuanjian/benchmark.db` (S7 红线)

```sql
-- 基准数据集
CREATE TABLE benchmarks (
    industry TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    data_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 差距分析报告
CREATE TABLE gap_reports (
    report_id TEXT PRIMARY KEY,
    industry TEXT NOT NULL,
    enterprise_name TEXT DEFAULT '',
    data_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- 跨行业对比报告
CREATE TABLE cross_reports (
    report_id TEXT PRIMARY KEY,
    data_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- 更新日志
CREATE TABLE update_log (
    record_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    industry TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 1,
    changes_summary TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
```

### 4.2 BenchmarkStore API

| 方法 | 说明 |
|------|------|
| `save_benchmark(dataset)` | 保存/更新行业基准数据 |
| `load_benchmark(industry)` | 按行业加载基准数据 |
| `load_all_benchmarks()` | 加载全部基准数据 |
| `list_stored_industries()` | 列出已存储的行业 |
| `save_gap_report(report)` | 保存差距分析报告 |
| `load_gap_report(report_id)` | 按ID加载差距分析报告 |
| `list_gap_reports(industry?)` | 列出差距分析报告ID |
| `save_cross_report(report)` | 保存跨行业报告 |
| `load_cross_report(report_id)` | 按ID加载跨行业报告 |
| `log_update(...)` | 记录更新操作 |
| `cleanup_old_records(retention_days)` | 清理过期记录 |

### 4.3 特性

- **WAL 模式**: `PRAGMA journal_mode=WAL` 提升并发性能
- **上下文管理器**: 支持 `with BenchmarkStore(...) as store:` 语法
- **工厂函数**: `open_benchmark_store()` 便捷入口
- **数据持久化**: Pydantic 模型通过 `model_dump_json()` / `model_validate_json()` 实现序列化

---

## 5. 各维度修复周期基准值

| 行业 | Critical (天) | High (天) | Medium (天) | Low (天) | 整体平均 |
|------|:---:|:---:|:---:|:---:|:---:|
| internet | 3.5 | 7.2 | 18.5 | 45.0 | 15.8 |
| finance | 2.0 | 5.0 | 14.0 | 30.0 | 11.5 |
| government | 5.0 | 12.0 | 30.0 | 60.0 | 22.5 |
| industrial_ctrl | 7.0 | 18.0 | 45.0 | 90.0 | 35.0 |
| healthcare | 4.5 | 10.0 | 25.0 | 55.0 | 19.2 |
| education | 6.0 | 15.0 | 35.0 | 70.0 | 26.8 |
| telecom | 3.0 | 8.0 | 20.0 | 45.0 | 16.5 |
| energy | 6.5 | 16.0 | 40.0 | 80.0 | 30.2 |
| transportation | 5.0 | 12.0 | 30.0 | 60.0 | 23.5 |
| insurance | 3.0 | 7.5 | 18.0 | 40.0 | 15.2 |
| securities | 1.5 | 4.0 | 10.0 | 25.0 | 9.8 |

---

## 6. 跨行业对比维度

文件: `comparison.py`

| 维度键 | 说明 | 越低越好 |
|--------|------|:---:|
| `avg_repair_days` | 整体平均修复周期(天) | 是 |
| `vuln_density` | 总漏洞密度(计数) | 是 |
| `critical_ratio` | 严重漏洞占比(%) | 是 |
| `top_category_pct` | 主导类别集中度(%) | 是 |
| `compliance_count` | 合规要求数量 | 否 |
| `scenario_count` | 行业场景数量 | 否 |
