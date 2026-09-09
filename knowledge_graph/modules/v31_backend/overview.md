# 玄鉴 v3.1 后端API开发 -- 总览

## 版本: 3.1.0
## 更新日期: 2026-09-09

## 概述

玄鉴 v3.1 后端API在 v2.5.1 基础上进行全面升级，新增七大 REST API 模块：
行业基准、自动修复PR、AI渗透测试、全局事件总线、报表导出、设置页面，
并统一挂载已有的隐私计算和DevOps路由。

## 版本变更摘要

| 组件 | 旧版本 | 新版本 |
|------|--------|--------|
| pyproject.toml | 2.5.1 | 3.1.0 |
| fp_sentinel/__init__.py | 2.5.1 | 3.1.0 |
| industry_benchmark | 3.0.0 | 3.1.0 |
| auto_pr | 3.0.0 | 3.1.0 |
| enterprise_perm | (无) | 3.1.0 |
| notify | 2.5.0 | 3.1.0 |
| rule_optimization | 2.5.1 | 3.1.0 |
| visualization | 2.5.1 | 3.1.0 |

## 新增模块

### 1. 行业基准 (/api/industry)
- 文件: `fp_sentinel/industry_benchmark/routes.py`
- 功能: 行业列表、差距分析、行业规则查询、跨行业对比、修复建议生成

### 2. 自动修复PR (/api/auto-pr)
- 文件: `fp_sentinel/auto_pr/routes.py`
- 功能: 修复预览、三重校验、创建PR（强制dry_run优先+confirm二次确认）

### 3. AI渗透测试 (/api/pentest)
- 文件: `fp_sentinel/attack/v3_ai_pentest/routes.py`
- 功能: 攻击链推理、PoC生成（默认关闭需配置开关）、漏洞验证、靶场生命周期管理

### 4. 全局事件总线 (/api/events)
- 文件: `fp_sentinel/events/__init__.py`, `fp_sentinel/events/event_bus.py`, `fp_sentinel/events/routes.py`
- 9种事件类型: scan_progress/finding_new/scan_completed/system_status/fed_round/fed_completed/pr_status/pipeline_gate/webhook_event

### 5. 报表导出 (/api/reports)
- 文件: `fp_sentinel/reporting/routes.py`
- 功能: HTML报表导出、Excel报表导出、模板列表、导出历史

### 6. 设置页面 (/api/settings)
- 文件: `fp_sentinel/web/settings_routes.py`
- 功能: 配置项掩码返回、配置段更新、配置验证、配置重置

### 7. 路由统一挂载
- 文件: `fp_sentinel/web/app.py` (已更新)
- 新增 /api/privacy, /api/devops, /api/industry, /api/auto-pr,
  /api/pentest, /api/events, /api/reports, /api/settings
- 新增 /api/v3.1/routes (路由索引), /api/v3.1/health (综合健康检查)

## API 端点清单

```
GET    /api/v3.1/routes                  -- v3.1路由索引
GET    /api/v3.1/health                  -- v3.1综合健康检查

# 隐私计算模块
POST   /api/privacy/federate/initialize
POST   /api/privacy/federate/add-node/{session_id}
POST   /api/privacy/federate/run-round/{session_id}
POST   /api/privacy/federate/run-full/{session_id}
GET    /api/privacy/federate/status/{session_id}
POST   /api/privacy/rule/desensitize
POST   /api/privacy/rule/package
POST   /api/privacy/rule/validate
POST   /api/privacy/rule/import/{team_id}
POST   /api/privacy/compliance/check
GET    /api/privacy/compliance/standards
POST   /api/privacy/task/create
POST   /api/privacy/task/assign/{task_id}
POST   /api/privacy/task/start/{task_id}
POST   /api/privacy/task/submit/{task_id}/{team_id}
POST   /api/privacy/task/aggregate/{task_id}
POST   /api/privacy/task/finalize/{task_id}
GET    /api/privacy/task/{task_id}/status
GET    /api/privacy/task/{task_id}/team-view/{team_id}
POST   /api/privacy/audit/check
GET    /api/privacy/audit/logs
GET    /api/privacy/stats

# DevOps模块
POST   /api/devops/sync
POST   /api/devops/gate
POST   /api/devops/close
POST   /api/devops/link
GET    /api/devops/mappings
GET    /api/devops/stats
GET    /api/devops/mappings/{mapping_id}
POST   /api/devops/webhook/{provider}

# 行业基准模块
GET    /api/industry/list
GET    /api/industry/{industry}/benchmark
POST   /api/industry/gap-analysis
GET    /api/industry/{industry}/gap-analysis/sample
GET    /api/industry/{industry}/rules
GET    /api/industry/{industry}/rules/{rule_id}
POST   /api/industry/cross-compare
GET    /api/industry/cross-compare/dimensions
POST   /api/industry/repair-suggestions
POST   /api/industry/repair-suggestions/findings
GET    /api/industry/stats

# 自动修复PR模块
POST   /api/auto-pr/preview
POST   /api/auto-pr/verify
POST   /api/auto-pr/verify/triple
POST   /api/auto-pr/create
GET    /api/auto-pr/status/{record_id}
GET    /api/auto-pr/history
GET    /api/auto-pr/stats
GET    /api/auto-pr/config
PUT    /api/auto-pr/config

# AI渗透测试模块
POST   /api/pentest/attack-chain/reason
POST   /api/pentest/attack-chain/visualize
POST   /api/pentest/poc/generate
POST   /api/pentest/poc/generate-single
POST   /api/pentest/verify
POST   /api/pentest/verify/batch
GET    /api/pentest/lab/status
POST   /api/pentest/lab/start
POST   /api/pentest/lab/stop
DELETE /api/pentest/lab/cleanup
GET    /api/pentest/lab/containers
GET    /api/pentest/stats

# 全局事件总线
GET    /api/events/types
GET    /api/events/history
GET    /api/events/stats
POST   /api/events/publish
WS     /api/events/ws

# 报表导出
POST   /api/reports/export/html
POST   /api/reports/export/excel
GET    /api/reports/templates
GET    /api/reports/history
GET    /api/reports/status/{task_id}

# 设置页面
GET    /api/settings/
GET    /api/settings/{section}
PUT    /api/settings/{section}
GET    /api/settings/masked-fields
POST   /api/settings/validate
POST   /api/settings/reset
```

## 安全红线

1. **PoC生成接口默认关闭**: 需设置 XUANJIAN_POC_ENABLE=true 环境变量才可开启
2. **PR提交强制dry_run优先**: create接口仅当 dry_run=False 且 confirm=True 时才执行真实提交
3. **所有靶场目标锁定localhost**: 所有pentest接口硬性校验目标为127.0.0.1/localhost
4. **敏感信息掩码**: 设置页面的API Token/Secret等字段自动脱敏
5. **配置重置需confirm**: settings/reset接口需要confirm=true
6. **事件数据过滤**: 事件payload中的敏感字段自动替换为***REDACTED***
7. **覆盖率 >= 95%**: pyproject.toml中fail_under=95

## 知识图谱子文档

- [B1_industry_routes.md](B1_industry_routes.md) -- 行业基准API详情
- [B2_auto_pr_routes.md](B2_auto_pr_routes.md) -- 自动修复PR API详情
- [B3_pentest_routes.md](B3_pentest_routes.md) -- AI渗透测试API详情
- [B4_event_bus.md](B4_event_bus.md) -- 全局事件总线详情
- [B5_reports_settings.md](B5_reports_settings.md) -- 报表导出与设置页面详情
- [B6_version_upgrade.md](B6_version_upgrade.md) -- 版本升级详情
