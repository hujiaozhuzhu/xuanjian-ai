# B6 -- 版本升级详情 (2.5.1 to 3.1.0)

## 升级范围

### 主版本号更新
| 文件 | 旧版本 | 新版本 |
|------|--------|--------|
| pyproject.toml | 2.5.1 | 3.1.0 |
| fp_sentinel/__init__.py | 2.5.1 | 3.1.0 |
| fp_sentinel/auto_pr/__init__.py | 3.0.0 | 3.1.0 |
| fp_sentinel/industry_benchmark/__init__.py | 3.0.0 | 3.1.0 |
| fp_sentinel/enterprise_perm/__init__.py | (无) | 3.1.0 |
| fp_sentinel/notify/__init__.py | 2.5.0 | 3.1.0 |
| fp_sentinel/rule_optimization/__init__.py | 2.5.1 | 3.1.0 |
| fp_sentinel/visualization/__init__.py | 2.5.1 | 3.1.0 |

### 新增文件

| 文件 | 说明 |
|------|------|
| fp_sentinel/events/__init__.py | 事件总线包初始化 |
| fp_sentinel/events/event_bus.py | 事件总线核心实现 |
| fp_sentinel/events/routes.py | 事件总线API路由 |
| fp_sentinel/industry_benchmark/routes.py | 行业基准API路由 |
| fp_sentinel/auto_pr/routes.py | 自动修复PR API路由 |
| fp_sentinel/attack/v3_ai_pentest/routes.py | AI渗透测试API路由 |
| fp_sentinel/reporting/routes.py | 报表导出API路由 |
| fp_sentinel/web/settings_routes.py | 设置页面API路由 |

### 修改文件

| 文件 | 修改内容 |
|------|----------|
| fp_sentinel/web/app.py | 新增v3.1路由挂载、/api/v3.1/routes、/api/v3.1/health |

## 兼容性
- 所有v1 API路由保持兼容
- 所有v3.0功能保持兼容
- 新增路由独立挂载，不影响已有功能
- 覆盖率要求 >= 95% (pyproject.toml fail_under=95)
