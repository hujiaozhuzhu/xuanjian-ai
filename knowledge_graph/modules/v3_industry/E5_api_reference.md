# E5 - CLI 命令和 REST API 接口文档

> **对应文件**: `fp_sentinel/industry_benchmark/__init__.py` (统一导出接口)
> **版本**: v3.0.0
> **总导出符号**: 32 个

---

## 1. 模块导入接口

### 1.1 从 `__init__.py` 导出的全部符号

```python
from fp_sentinel.industry_benchmark import (
    # === Models (20 个) ===
    Industry,
    VulnTypeStats,
    ComplianceRequirement,
    BenchmarkDataset,
    BenchmarkMetadata,
    IndustryMeta,
    IndustryScenario,
    TopVulnerability,
    RepairCycle,
    GapSeverity,
    GapItem,
    CategoryGap,
    GapAnalysisReport,
    EnterpriseMetrics,
    RepairSuggestion,
    CrossIndustryComparison,
    CrossIndustryReport,
    UpdateSource,
    UpdateRecord,
    UpdatePolicy,
    IndustryRule,
    IndustryRuleSet,

    # === Data (4 个) ===
    build_benchmark_dataset,
    build_all_benchmarks,
    get_industry_meta,
    INDUSTRY_METADATA,

    # === Store (2 个) ===
    BenchmarkStore,
    open_benchmark_store,

    # === Engine (2 个) ===
    BenchmarkEngine,
    compare_enterprise_to_industry,

    # === Repair (2 个) ===
    RepairAdvisor,
    suggest_repairs_for_findings,

    # === Rules (3 个) ===
    IndustryRuleEngine,
    get_industry_rule_set,
    list_industry_rules,

    # === Comparison (2 个) ===
    CrossIndustryAnalyzer,
    generate_cross_industry_report,

    # === Updater (2 个) ===
    BenchmarkUpdater,
    create_default_policy,
)
```

### 1.2 模块元信息

| 属性 | 值 |
|------|-----|
| `__version__` | `"3.0.0"` |
| `__red_lines__` | `["S1", "S2", "S3", "S5", "S6", "S7"]` |

---

## 2. 数据查询 API

### 2.1 构建行业基准数据集

```python
from fp_sentinel.industry_benchmark import build_benchmark_dataset
from fp_sentinel.industry_benchmark.models import Industry

# 构建单个行业数据集
dataset = build_benchmark_dataset(Industry.FINANCE)
# 返回: BenchmarkDataset

# 构建全部 11 个行业数据集
all_datasets = build_all_benchmarks()
# 返回: Dict[Industry, BenchmarkDataset]
```

### 2.2 获取行业元数据

```python
from fp_sentinel.industry_benchmark import get_industry_meta, INDUSTRY_METADATA
from fp_sentinel.industry_benchmark.models import Industry

meta = get_industry_meta(Industry.HEALTHCARE)
# 返回: IndustryMeta (display_name="医疗", key_tech_stacks=[...], risk_profile="...")

# 或直接访问字典
all_meta = INDUSTRY_METADATA  # Dict[Industry, IndustryMeta]
```

### 2.3 全部公开常量

| 常量名 | 类型 | 说明 |
|--------|------|------|
| `INDUSTRY_METADATA` | `Dict[Industry, IndustryMeta]` | 11 个行业的元数据字典 |

---

## 3. 差距分析 API

### 3.1 BenchmarkEngine (类)

```python
from fp_sentinel.industry_benchmark import BenchmarkEngine
from fp_sentinel.industry_benchmark.models import EnterpriseMetrics, Industry

engine = BenchmarkEngine()
# 或带预设基准数据: engine = BenchmarkEngine(benchmark=my_dataset)

# 设置基准
engine.set_benchmark(dataset)

# 获取当前基准
benchmark = engine.get_benchmark()

# 执行差距分析
enterprise = EnterpriseMetrics(
    project_name="MyProject",
    industry=Industry.INTERNET,
    total_findings=200,
    by_severity={"CRITICAL": 5, "HIGH": 20, "MEDIUM": 60, "LOW": 115},
    by_category={"INJECTION": 30, "XSS": 40},
    avg_repair_days=10.0,
    scan_count=3,
    compliance_score=75.0,
)
report = engine.analyze(enterprise)
# 返回: GapAnalysisReport

# 可传入自定义基准覆盖
report = engine.analyze(enterprise, benchmark=custom_dataset)
```

### 3.2 便捷函数 (Functional API)

```python
from fp_sentinel.industry_benchmark import compare_enterprise_to_industry
from fp_sentinel.industry_benchmark.models import EnterpriseMetrics, Industry

report = compare_enterprise_to_industry(enterprise)
# 等价于 BenchmarkEngine().analyze(enterprise)
```

### 3.3 GapAnalysisReport 返回结构

```
GapAnalysisReport:
  ├── report_id: str          (如 "gap-a3f7b2c91e4d")
  ├── enterprise_name: str
  ├── industry: Industry
  ├── overall_score: float    (0-100)
  ├── overall_severity: GapSeverity
  ├── category_gaps: List[CategoryGap]  (4 个维度)
  │     └── CategoryGap:
  │           ├── category_name: str    ("vulnerability_density"/"repair_speed"/"compliance"/"coverage")
  │           ├── items: List[GapItem]
  │           │     └── GapItem:
  │           │           ├── category: str
  │           │           ├── industry_avg: float
  │           │           ├── enterprise_value: float
  │           │           ├── gap_ratio: float
  │           │           ├── severity: GapSeverity
  │           │           ├── description: str
  │           │           └── recommendation: str
  │           ├── overall_severity: GapSeverity
  │           └── score: float          (维度得分)
  ├── highlights: List[str]   (关键发现文本)
  └── improvement_roadmap: List[str]  (改进路线)
```

**快捷属性**:
```python
report.critical_gaps  # 过滤 severity in (CRITICAL, HIGH) 的差距项
```

---

## 4. 修复建议 API

### 4.1 RepairAdvisor (类)

```python
from fp_sentinel.industry_benchmark import RepairAdvisor
from fp_sentinel.industry_benchmark.models import Industry

advisor = RepairAdvisor()
# 或带基准上下文: advisor = RepairAdvisor(benchmark=finance_dataset)

# 设置/更新基准
advisor.set_benchmark(dataset)

# 单发现建议
suggestions = advisor.suggest_for_finding(
    category="INJECTION",
    severity="CRITICAL",
    cwe="CWE-89",
    industry=Industry.INTERNET
)
# 返回: List[RepairSuggestion] (按 priority 排序)

# 行业级别建议 (基于 TOP5 漏洞 + 场景匹配)
suggestions = advisor.suggest_for_industry(Industry.SECURITIES)

# 场景级建议映射
scenario_suggestions = advisor.suggest_for_scenarios(Industry.ENERGY)
# 返回: Dict[scenario_id, List[RepairSuggestion]]
```

### 4.2 便捷函数

```python
from fp_sentinel.industry_benchmark import suggest_repairs_for_findings
from fp_sentinel.industry_benchmark.models import Industry

findings = [
    ("INJECTION", "CRITICAL", "CWE-89"),
    ("XSS", "HIGH", "CWE-79"),
]
suggestions = suggest_repairs_for_findings(findings, Industry.INTERNET)
# 返回: 去重后按 priority 排序的 List[RepairSuggestion]
```

---

## 5. 行业规则 API

### 5.1 IndustryRuleEngine (类)

```python
from fp_sentinel.industry_benchmark import IndustryRuleEngine
from fp_sentinel.industry_benchmark.models import Industry, IndustryRule

engine = IndustryRuleEngine()

# 获取行业规则集
rs = engine.get_rule_set(Industry.INTERNET)
# 返回: IndustryRuleSet

# 添加自定义规则
engine.add_rule(Industry.INTERNET, custom_rule)

# 按技术栈过滤
rules = engine.get_rules_for_tech(Industry.FINANCE, "Java")
# 匹配 tech_targets 包含 "Java" 或 "*" 的规则

# 启用/禁用规则
success = engine.enable_rule(Industry.INTERNET, "INET-API-AUTH-001", enabled=False)
# 返回: bool (是否找到并操作)

# 获取有规则的全部行业
industries = engine.get_all_industries_with_rules()
# 返回: 11 个行业

# 统计
total = engine.count_rules()                    # 全部
finance = engine.count_rules(Industry.FINANCE)  # 金融
```

### 5.2 便捷函数

```python
from fp_sentinel.industry_benchmark import get_industry_rule_set, list_industry_rules

# 获取规则集
rs = get_industry_rule_set(Industry.TELECOM)

# 列出规则
rules = list_industry_rules(Industry.ENERGY, enabled_only=True)
rules = list_industry_rules(Industry.ENERGY, enabled_only=False)  # 含禁用
```

### 5.3 IndustryRuleSet 结构

```
IndustryRuleSet:
  ├── industry: Industry
  ├── rules: List[IndustryRule]
  ├── version: str = "3.0.0"
  └── enabled_rules: List[IndustryRule]  (仅 enabled=True)
```

### 5.4 IndustryRule 结构

```
IndustryRule:
  ├── rule_id: str              (如 "FIN-LOGIC-001")
  ├── industry: Industry
  ├── name: str
  ├── category: str
  ├── cwe: Optional[str]
  ├── severity: str
  ├── pattern: str
  ├── description: str
  ├── tech_targets: List[str]   (如 ["Java", "Spring"] 或 ["*"])
  ├── enabled: bool = True
  └── compliance_refs: List[str]
```

---

## 6. 跨行业对比 API

### 6.1 CrossIndustryAnalyzer (类)

```python
from fp_sentinel.industry_benchmark import CrossIndustryAnalyzer
from fp_sentinel.industry_benchmark.models import Industry

analyzer = CrossIndustryAnalyzer()
# 或带自定义基准: analyzer = CrossIndustryAnalyzer(benchmarks=my_dict)

# 设置基准
analyzer.set_benchmarks({Industry.INTERNET: dataset, ...})

# 单维度对比
comp = analyzer.compare_dimension("avg_repair_days")
# 返回: CrossIndustryComparison

comp = analyzer.compare_dimension("critical_ratio")
comp = analyzer.compare_dimension("scenario_count")

# 全维度对比
comps = analyzer.compare_all_dimensions()
# 返回: 6 个维度的 List[CrossIndustryComparison]

# 生成完整报告
report = analyzer.generate_report()          # 全部 11 行业
report = analyzer.generate_report(industries=[Industry.INTERNET, Industry.FINANCE])  # 子集
# 返回: CrossIndustryReport

# 按维度获取排名
ranking = analyzer.get_industry_ranking("avg_repair_days")
# 返回: List[Industry] (从最佳到最差排序)
```

### 6.2 便捷函数

```python
from fp_sentinel.industry_benchmark import generate_cross_industry_report

report = generate_cross_industry_report()
# 等价于 CrossIndustryAnalyzer().generate_report()
```

### 6.3 CrossIndustryReport 返回结构

```
CrossIndustryReport:
  ├── report_id: str        (如 "cross-b8e2d4f6a1c3")
  ├── comparisons: List[CrossIndustryComparison]
  │     └── CrossIndustryComparison:
  │           ├── industries: List[Industry]
  │           ├── dimension: str
  │           ├── values: Dict[str, float]  (industry.value -> 值)
  │           ├── best_industry: Optional[Industry]
  │           ├── worst_industry: Optional[Industry]
  │           └── analysis: str (分析文本)
  ├── summary: str          (摘要)
  └── industry_rankings: Dict[str, List[Industry]]  (维度 -> 排名)
```

---

## 7. 持久化存储 API

### 7.1 BenchmarkStore (类)

```python
from fp_sentinel.industry_benchmark import BenchmarkStore, open_benchmark_store

# 方式1: 直接构造
store = BenchmarkStore()                    # 使用默认路径 ~/.xuanjian/benchmark.db
store = BenchmarkStore(db_path=custom_path) # 测试时使用自定义路径

# 方式2: 工厂函数
store = open_benchmark_store()
store = open_benchmark_store(db_path=custom_path)

# 方式3: 上下文管理器 (自动关闭)
with BenchmarkStore() as store:
    store.save_benchmark(dataset)

# === 基准数据 CRUD ===
store.save_benchmark(dataset)                        # 保存/更新
dataset = store.load_benchmark(Industry.INTERNET)     # 加载
all_ds = store.load_all_benchmarks()                 # 加载全部
industries = store.list_stored_industries()          # 列出行业

# === 差距报告 CRUD ===
store.save_gap_report(gap_report)
report = store.load_gap_report("gap-xxx")
ids = store.list_gap_reports()                       # 全部
ids = store.list_gap_reports(industry=Industry.FINANCE)  # 按行业过滤

# === 跨行业报告 CRUD ===
store.save_cross_report(cross_report)
report = store.load_cross_report("cross-xxx")

# === 更新日志 ===
store.log_update("upd-xxx", "builtin", Industry.INTERNET, True, "summary")
deleted = store.cleanup_old_records(retention_days=180)

# === 关闭 ===
store.close()
```

---

## 8. 数据更新 API

### 8.1 BenchmarkUpdater (类)

```python
from fp_sentinel.industry_benchmark import BenchmarkUpdater, create_default_policy
from fp_sentinel.industry_benchmark.store import BenchmarkStore

# 默认安全策略
updater = BenchmarkUpdater()  # auto_update=False, retention_days=180

# 自定义策略
policy = create_default_policy()
store = BenchmarkStore()
updater = BenchmarkUpdater(policy=policy, store=store)

# 修改策略
new_policy = create_aggressive_policy(interval_days=7)
updater.policy = new_policy  # 通过 setter 更新

# 导入内置数据
record = updater.import_builtin_data(Industry.INTERNET)
# 返回: UpdateRecord (record_id="upd-xxx", success=True)

records = updater.import_all_builtin()
# 返回: Dict[Industry, UpdateRecord] (11 条)

# 刷新行业数据
record = updater.refresh_industry(Industry.GOVERNMENT)
# 无外部源时: 等价于 import_builtin_data
# 有外部源时: 返回失败 (S1 红线，外部未实现)

# 清理旧记录
deleted = updater.cleanup_old_records()  # 使用策略中 retention_days
deleted = updater.cleanup_old_records(retention_days=0)  # 清理全部

# 获取历史
history = updater.get_update_history()
history = updater.get_update_history(industry=Industry.INTERNET)
```

### 8.2 策略构建函数

```python
from fp_sentinel.industry_benchmark import create_default_policy, create_aggressive_policy

# 默认安全策略 (推荐)
policy = create_default_policy()
# auto_update=False, interval_days=30, retention_days=180, sources 全部禁用

# 激进策略 (需谨慎)
policy = create_aggressive_policy(interval_days=7, retention_days=90)
# auto_update=True, interval_days=7, retention_days=90, sources 全部启用

# 自定义策略
from fp_sentinel.industry_benchmark.models import UpdatePolicy, UpdateSource
custom = UpdatePolicy(
    auto_update=False,
    interval_days=14,
    retention_days=365,
    sources=[UpdateSource(source_id="cnvd", name="CNVD", enabled=False)]
)
```

---

## 9. CLI 命令 (间接调用路径)

行业基准模块通过玄鉴 CLI 的 `benchmark` 子命令被间接调用。参考 `fp_sentinel/cli/` 下的命令文件。

**注意**: 模块本身不直接定义 CLI 命令，而是通过公开 API 供 CLI 层调用。典型调用路径:

```
CLI Command → fp_sentinel.industry_benchmark 公开 API
```

---

## 10. REST API 接口 (间接)

行业基准模块通过 Flask 路由被间接暴露为 HTTP API。

**注意**: 模块不直接定义 REST 路由，而是通过 `__init__.py` 导出供 web 层调用。典型路由:

```
/api/v1/benchmark/<industry>           → build_benchmark_dataset
/api/v1/benchmark/gap-analysis         → compare_enterprise_to_industry
/api/v1/benchmark/cross-industry       → generate_cross_industry_report
/api/v1/benchmark/repair-suggestions   → suggest_repairs_for_findings
/api/v1/benchmark/industry-rules       → list_industry_rules
/api/v1/benchmark/health               → store.list_stored_industries
```

---

## 11. 使用示例：完整端到端工作流

```python
from fp_sentinel.industry_benchmark import (
    BenchmarkEngine, RepairAdvisor, CrossIndustryAnalyzer,
    IndustryRuleEngine, suggest_repairs_for_findings,
    BenchmarkStore, BenchmarkUpdater,
    compare_enterprise_to_industry, generate_cross_industry_report,
)
from fp_sentinel.industry_benchmark.models import EnterpriseMetrics, Industry

# 1. 初始化存储
with BenchmarkStore() as store:
    # 2. 导入内置数据
    updater = BenchmarkUpdater(store=store)
    updater.import_all_builtin()
    
    # 3. 准备企业指标
    enterprise = EnterpriseMetrics(
        project_name="Acme Corp",
        industry=Industry.FINANCE,
        total_findings=150,
        by_severity={"CRITICAL": 3, "HIGH": 15, "MEDIUM": 50, "LOW": 82},
        by_category={"BUSINESS_LOGIC": 40, "BROKEN_ACCESS_CONTROL": 30},
        avg_repair_days=8.0,
        scan_count=5,
        compliance_score=85.0,
    )
    
    # 4. 执行差距分析
    report = compare_enterprise_to_industry(enterprise)
    print(f"安全评分: {report.overall_score}/100, 严重度: {report.overall_severity.value}")
    
    # 5. 保存报告
    store.save_gap_report(report)
    
    # 6. 生成修复建议
    advisor = RepairAdvisor()
    findings = [("BUSINESS_LOGIC", "CRITICAL", "CWE-840"),
                ("BROKEN_ACCESS_CONTROL", "HIGH", "CWE-284")]
    suggestions = suggest_repairs_for_findings(findings, Industry.FINANCE)
    for s in suggestions:
        print(f"[P{s.priority}] {s.title}")
    
    # 7. 查看行业规则
    rules = IndustryRuleEngine().get_rules_for_tech(Industry.FINANCE, "Java")
    print(f"适用于 Java 的金融规则: {len(rules)} 条")
    
    # 8. 跨行业对比
    cross_report = generate_cross_industry_report()
    for comp in cross_report.comparisons:
        print(f"{comp.dimension}: 最佳={comp.best_industry.value if comp.best_industry else 'N/A'}")
```

---

## 12. 错误处理规范

| 异常场景 | 处理方式 |
|---------|---------|
| 无效行业值 | `Industry("xxx")` 抛出 `ValueError` |
| 无效百分比 (>100) | Pydantic `ValidationError` |
| 无效排名 (=0) | Pydantic `ValidationError` |
| 数据库不存在 | 自动创建目录和表 |
| 数据行损坏 | `load_all_benchmarks` 跳过该行 |
| 重复主键写入 | `INSERT OR REPLACE` 自动覆盖 |
| 外部更新未实现 | 返回 `UpdateRecord(success=False)` |
| 非预期字段传入 | `extra="forbid"` 抛出 `ValidationError` |
