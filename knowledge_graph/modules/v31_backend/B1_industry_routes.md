# B1 -- 行业基准模块 API (v3.1)

## 文件位置
fp_sentinel/industry_benchmark/routes.py

## 路由前缀
/api/industry

## 端点详情

### 1. 行业列表
- GET /api/industry/list
- 返回所有支持的11个行业的元数据
- 无需请求参数
- 响应含: total, industries[{industry, display_name, description, key_tech_stacks, risk_profile}]

### 2. 行业基准详情
- GET /api/industry/{industry}/benchmark
- 路径参数: industry (finance/internet/government/...)
- 查询参数: include_scenarios(bool=true), include_compliance(bool=true)
- 响应含: 完整BenchmarkDataset

### 3. 差距分析
- POST /api/industry/gap-analysis
- 请求体: GapAnalysisRequest (enterprise_name, industry, project_name, total_findings,
  by_severity, by_category, avg_repair_days, compliance_score, tech_stacks)
- 响应含: GapAnalysisReport (overall_score, overall_severity, category_gaps, highlights,
  improvement_roadmap)

### 4. 示例差距分析
- GET /api/industry/{industry}/gap-analysis/sample
- 使用模拟企业数据生成示例报告

### 5. 行业规则查询
- GET /api/industry/{industry}/rules
- 查询参数: category(可选), severity(可选), enabled_only(bool=true)
- 响应含: 规则列表及rule_set_version

### 6. 单条规则详情
- GET /api/industry/{industry}/rules/{rule_id}
- 返回单条IndustryRule详情

### 7. 跨行业对比
- POST /api/industry/cross-compare
- 请求体: CrossCompareRequest (industries[], dimensions[])
- 响应含: CrossIndustryReport (comparisons, summary, industry_rankings)

### 8. 对比维度列表
- GET /api/industry/cross-compare/dimensions
- 返回所有可用的对比维度及其描述

### 9. 修复建议
- POST /api/industry/repair-suggestions
- 请求体: RepairSuggestionRequest (industry, target_categories[],
  target_severities[], max_suggestions=20)
- 响应含: 按优先级排序的修复建议列表

### 10. 基于发现的修复建议
- POST /api/industry/repair-suggestions/findings
- 请求体: FindingsRepairRequest (industry, findings[])
- 响应含: 按发现分组的修复建议

### 11. 统计
- GET /api/industry/stats
- 返回全局统计数据（行业数、规则数、场景数、合规要求数）

## 安全红线
- 纯本地操作，零网络请求 (S1)
- 只读操作 (S2)
- 不删除文件 (S3)
- 数据保留周期可配置 (S5)
- 不泄露客户代码 (S6)
- 数据库路径固定 (S7)
