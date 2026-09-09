# B5 -- 报表导出与设置页面 API (v3.1)

## 文件位置
- 报表: `fp_sentinel/reporting/routes.py`
- 设置: `fp_sentinel/web/settings_routes.py`

## 路由前缀
- `/api/reports/`
- `/api/settings/`

## 报表导出 API

### HTML报表
- `POST /api/reports/export/html`
- 请求体: ExportHTMLRequest (scan_id, title, include_findings,
  include_summary, include_charts, include_remediation, theme, data)
- 响应: HTML文件 (text/html) + Content-Disposition附件头
- 内置暗色主题CSS，零外部依赖

### Excel报表
- `POST /api/reports/export/excel`
- 请求体: ExportExcelRequest (scan_id, sheet_name, findings, summary,
  include_statistics, format_type)
- 响应: XLSX文件 (application/vnd.openxmlformats...)
- 优先使用openpyxl，不可用时回退到CSV

### 其他端点
- GET /api/reports/templates   -- 可用模板列表
- GET /api/reports/history     -- 导出历史
- GET /api/reports/status/{id} -- 任务状态

## 设置页面 API

### 配置获取
- `GET /api/settings/`         -- 全部配置（敏感项掩码）
- `GET /api/settings/{section}` -- 指定配置段
- 敏感字段: token/secret/password等 → 掩码显示(如 ab****34)

### 配置更新
- `PUT /api/settings/{section}`
- 类型不匹配时自动转换
- 更新后返回掩码后的配置

### 掩码字段
- `GET /api/settings/masked-fields` -- 列出所有已掩码字段

### 配置验证
- `POST /api/settings/validate` -- 检查配置有效性（端口范围、超时等）

### 配置重置
- `POST /api/settings/reset?section=x&confirm=true` -- 安全重置

## 配置段
- system: 系统基础配置（版本、监听地址等）
- scan: 扫描配置（扫描器、超时、并行数）
- security: 安全控制（target锁定、PoC开关）
- auto_pr: 自动修复配置
- industry_benchmark: 行业基准配置
- federated: 联邦学习配置
- devops: DevOps配置
- notifications: 通知配置
- reporting: 报表配置

## 安全红线
- 所有敏感字段自动掩码返回（不可逆）
- 配置更新需类型校验
- 配置重置需要confirm=true防止误操作
- 环境变量可覆盖默认配置（XUANJIAN_DEBUG/PORT/HOST等）
