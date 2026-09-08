# 行业基准模块 v3.0 - 知识图谱归档总览

> **版本**: v3.0.0 | **更新日期**: 2026
> **模块路径**: `fp_sentinel/industry_benchmark/`
> **知识图谱位置**: `knowledge_graph/modules/v3_industry/`
> **模块文件数**: 9 个 Python 文件 + 1 个 `__init__.py`
> **总代码行数**: 约 1200 逻辑行
> **整体测试覆盖率**: 95.28% (163 tests, all green)

---

## 1. 模块架构

### 1.1 目录结构

```
industry_benchmark/
├── __init__.py              # 统一导出 + 安全声明 (S1-S7)
├── models.py                # 20 个 Pydantic 数据模型 (~330 行)
├── builtin_data.py          # 11 个行业内置基准数据 (~585 行)
├── store.py                 # SQLite 持久化存储 (~276 行)
├── engine.py                # 基准引擎 + 差距分析 (~457 行)
├── repair_advisor.py        # 行业修复建议生成器 (~351 行)
├── industry_rules.py        # 行业专属规则引擎 (~502 行)
├── comparison.py            # 跨行业对比分析 (~202 行)
└── updater.py               # 数据更新 + 保留策略 (~208 行)
```

### 1.2 架构分层

```
┌─────────────────────────────────────────────────────┐
│                   接口层 (Interface)                  │
│  CLI Commands / REST API / __init__.py 公开导出       │
├─────────────────────────────────────────────────────┤
│                  业务逻辑层 (Business)                 │
│  BenchmarkEngine │ CrossIndustryAnalyzer             │
│  RepairAdvisor   │ IndustryRuleEngine                │
│  BenchmarkUpdater                                     │
├─────────────────────────────────────────────────────┤
│                  数据层 (Data)                        │
│  builtin_data (内置)  │  BenchmarkStore (SQLite)     │
├─────────────────────────────────────────────────────┤
│                  模型层 (Models)                      │
│  20 个 Pydantic 模型 │ Industry 枚举                 │
└─────────────────────────────────────────────────────┘
```

### 1.3 核心文件职责

| 文件 | 职责 | 关键类/函数 | 安全红线 |
|------|------|------------|---------|
| `__init__.py` | 模块统一接口导出 | `__all__` 公开列表 | S1-S7 |
| `models.py` | 数据模型定义 | 20 个 Pydantic 模型 | S6 (无客户代码泄露) |
| `builtin_data.py` | 内置基准数据集 | `build_benchmark_dataset`, `build_all_benchmarks` | S5, S6, S7 |
| `store.py` | 持久化存储 | `BenchmarkStore`, `open_benchmark_store` | S7 (固定路径) |
| `engine.py` | 差距分析引擎 | `BenchmarkEngine`, `compare_enterprise_to_industry` | S2 (只读) |
| `repair_advisor.py` | 修复建议生成 | `RepairAdvisor`, `suggest_repairs_for_findings` | S2 (只读) |
| `industry_rules.py` | 行业规则引擎 | `IndustryRuleEngine`, `list_industry_rules` | - |
| `comparison.py` | 跨行业对比 | `CrossIndustryAnalyzer`, `generate_cross_industry_report` | S2 (只读) |
| `updater.py` | 数据更新管理 | `BenchmarkUpdater`, `create_default_policy` | S1, S5, S7 |

---

## 2. 11 个行业基准介绍

| # | 行业标识 | 中文名称 | 核心关注 | 平均修复周期(天) |
|---|----------|---------|---------|:---:|
| 1 | `internet` | 互联网 | 越权访问、注入、SSRF | 15.8 |
| 2 | `finance` | 银行 | 业务逻辑漏洞、加密强度 | 11.5 |
| 3 | `government` | 政务 | 公民信息泄露、供应链安全 | 22.5 |
| 4 | `industrial_ctrl` | 工业控制 | 协议脆弱性、固件漏洞 | 35.0 |
| 5 | `healthcare` | 医疗 | 患者隐私 (PHI)、系统可用性 | 19.2 |
| 6 | `education` | 教育 | 学生信息泄露、成绩篡改 | 26.8 |
| 7 | `telecom` | 运营商 | 通信协议安全、计费欺诈 | 16.5 |
| 8 | `energy` | 能源 | SCADA 入侵、工控协议 | 30.2 |
| 9 | `transportation` | 交通 | 信号系统、GPS 欺骗 | 23.5 |
| 10 | `insurance` | 保险 | 理赔欺诈、精算篡改 | 15.2 |
| 11 | `securities` | 证券 | 延迟操纵、行情操纵 | 9.8 |

---

## 3. 核心功能说明

### 3.1 行业基准数据 (Benchmark Data)

功能入口：`builtin_data.py`

- 静态样本不连外网（S5 红线）
- 每个行业的数据集包含：漏洞类型分布、修复周期、TOP10 常见漏洞、合规要求、行业场景
- 数据来源：基于公开安全报告（CNVD/NVD/CNNVD）与行业实践构建
- 数据质量标注：置信度 0.95，样本周期 2025-Q1~2026-Q2

### 3.2 企业对标差距分析 (Benchmark Engine)

功能入口：`BenchmarkEngine.analyze()`, `compare_enterprise_to_industry()`

- 四维差距分析：漏洞密度、修复速度、合规评分、覆盖范围
- 差距严重度分级：`CRITICAL` > `HIGH` > `MEDIUM` > `ON_PAR` > `AHEAD`
- 自动改进路线图生成 (P1 优先)
- 关键发现 (highlights) 自动汇总

### 3.3 修复建议生成 (Repair Advisor)

功能入口：`RepairAdvisor.suggest_for_finding()`, `suggest_repairs_for_findings()`

- 12 个通用修复模板（SQL注入、XSS、越权、加密失效等）
- 3 个行业特定模板（ICS/SCADA、能源SCADA、证券闪电崩盘）
- 合规引用自动丰富（从基准数据的合规要求映射）
- 优先级排序 (priority 1-10)

### 3.4 行业专属规则引擎 (Industry Rules Engine)

功能入口：`IndustryRuleEngine`, `list_industry_rules()`

- 25+ 行业专属检测规则覆盖全部 11 个行业
- 规则按国家合规标准映射（GB/T 22239、JR/T 0071 等）
- 支持技术栈过滤 (`get_rules_for_tech`)
- 规则可启用/禁用

### 3.5 跨行业对比分析 (Cross-Industry Comparison)

功能入口：`CrossIndustryAnalyzer.generate_report()`, `generate_cross_industry_report()`

- 6 个对比维度：修复周期、漏洞密度、严重占比、主导类别占比、合规数、场景数
- 每个维度的行业排名
- 最佳/最差行业识别

### 3.6 数据更新机制 (Data Updater)

功能入口: `BenchmarkUpdater.import_builtin_data()`, `refresh_industry()`

- S1 红线合规：默认无网络，外部源全部禁用
- 内置数据离线导入（始终可用）
- 可配置保留策略（S5：默认 180 天）
- SQLite 持久化（S7：~/.xuanjian/benchmark.db）

---

## 4. 安全红线声明

| 红线 | 实现方式 |
|------|---------|
| **S1 零网络** | 核心引擎完全离线；外部更新默认禁用 |
| **S2 只读** | 基准数据不修改目标代码 |
| **S3 无删除** | 仅操作基准数据库，不触碰业务文件 |
| **S5 保留策略** | update_log 自动清理，默认 180 天 |
| **S6 无泄露** | 仅存储统计聚合数据，不含源代码 |
| **S7 固定路径** | DB 固定在 `~/.xuanjian/benchmark.db` |

---

## 5. 数据流图

```
[扫描发现] → EnterpriseMetrics
                    ↓
            ┌─── BenchmarkEngine.analyze() ───┐
            │                                  │
    [builtin_data]                    [BenchmarkStore]
    (内置数据集)                       (SQLite已存数据)
            │                                  │
            └─────── GapAnalysisReport ←───────┘
                          │
                    [差距分析报告]
                          │
            ┌─────────────┼─────────────┐
            ↓             ↓             ↓
    RepairAdvisor   IndustryRules   CrossIndustry
    (修复建议)      (规则匹配)      (跨行业对比)
            │             │             │
            ↓             ↓             ↓
    RepairSuggestion  IndustryRule  CrossIndustryReport
```

---

## 6. 模块间依赖关系

```
industry_benchmark/  →  pydantic (数据模型)
                    →  sqlite3 (持久化)
                    →  uuid (报告ID生成)
                    →  datetime (时间戳)
                    →  (无外部依赖)

被依赖方:
  ← cli/commands.py (通过 CLI 调用)
  ← reporting/ (报告生成引用)
```

---

## 7. 文档索引

| 文档 | 内容 |
|------|------|
| [A1_industry_data.md](./A1_industry_data.md) | 行业基准数据结构、数据来源、更新机制 |
| [B2_comparison_engine.md](./B2_comparison_engine.md) | 跨行业对比分析功能设计 |
| [C3_industry_rules.md](./C3_industry_rules.md) | 行业专属规则引擎设计 |
| [D4_repair_advisor.md](./D4_repair_advisor.md) | 行业修复建议生成逻辑 |
| [E5_api_reference.md](./E5_api_reference.md) | CLI 命令和 REST API 接口文档 |
| [F6_test_report.md](./F6_test_report.md) | 测试覆盖率、测试用例、质量指标 |
