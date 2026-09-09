# A3. 行业特性精准风险评分模块

## 模块路径
`fp_sentinel/analysis/precision_risk_scorer.py`

## 功能概述

结合行业特性与业务重要性，提升 CVSS 评分的精准度，优先对业务影响大的漏洞进行排序。

在标准 ChainRiskScorer 基础上引入多维修正。

## 行业风控配置

### 11 个行业风险画像

| 行业 | CVSS乘数 | 业务权重 | 合规权重 | 行业因子 |
|------|---------|---------|---------|---------|
| finance | 1.15 | 0.35 | 0.25 | 1.2 |
| healthcare | 1.10 | 0.25 | 0.35 | 1.15 |
| government | 1.10 | 0.25 | 0.35 | 1.15 |
| industrial_ctrl | 1.20 | 0.30 | 0.20 | 1.25 |
| energy | 1.20 | 0.30 | 0.25 | 1.25 |
| telecom | 1.05 | 0.25 | 0.20 | 1.05 |
| transportation | 1.10 | 0.30 | 0.20 | 1.10 |
| insurance | 1.10 | 0.30 | 0.30 | 1.10 |
| securities | 1.15 | 0.35 | 0.30 | 1.2 |
| internet | 1.0 | 0.25 | 0.15 | 1.0 |
| education | 1.0 | 0.15 | 0.20 | 0.95 |

### 各行业的关键漏洞类别

- **金融**: SQL_INJECTION, DESERIALIZATION, AUTH_BYPASS
- **医疗**: SQL_INJECTION, XSS, DATA_LEAKAGE
- **工控/能源**: COMMAND_INJECTION, DESERIALIZATION, SSRF
- **政务**: SQL_INJECTION, XXE, DESERIALIZATION
- **互联网**: SQL_INJECTION, COMMAND_INJECTION, DESERIALIZATION

## 业务关键性模型

### BusinessCriticality 评分 (0-1)

| 维度 | 权重 | 条件 |
|------|------|------|
| 营收影响 | 0.30 | is_revenue_related |
| 用户面影响 | 0.20 | is_user_facing |
| 合规需求 | 0.15 | is_compliance_required |
| 用户数量 | 0.15 | log10(users)/7 |
| SLA等级 | 0.10 | platinum/critical/standard/basic |
| 数据分级 | 0.10 | restricted/confidential/internal/public |

## 评分算法

```
final_score = (cvss_adjusted / 10) * tech_weight
            + business_score * biz_weight
            + category_boost * compliance_weight
            × temporal_adj × industry_factor
```

## 数据结构

### BusinessCriticality -> to_score() -> 0-1 float
### PrecisionRiskScore -> 完整评分结果

对齐的严重度:
- >= 9.0: CRITICAL (立即处理)
- >= 7.0: HIGH (24小时内)
- >= 4.0: MEDIUM (计划内)
- >= 1.0: LOW (可延后)
- < 1.0: INFO (跟踪)

## 公开 API

### 核心类: PrecisionRiskScorer
- `score_finding(finding)` -> PrecisionRiskScore
- `score_findings(findings)` -> List (sorted by risk)
- `sort_findings_by_risk(findings)` -> List[(finding, score)]

### 便捷函数
- `score_with_industry(findings, industry)` -> List[PrecisionRiskScore]
- `prioritize_by_business_impact(findings, industry)` -> List[(finding, score, severity)]

## 依赖

- fp_sentinel.analysis.chain_scorer (基础CVSS/EPSS)
- fp_sentinel.industry_benchmark.models.Industry

## 测试覆盖

- 测试文件: tests/exp_fix/test_precision_risk_scorer.py
- 测试数量: ~55
- 覆盖率: 96%
- 覆盖要点: 业务关键性/行业画像/评分算法/严重度阈值/边界条件/便捷函数
