# 玄鉴 XuanJian v3.1 前端架构

## 概述
零构建SPA（Single Page Application），使用原生JavaScript，无外部运行时依赖。
所有图表和图可视化通过Canvas原生API实现，替代ECharts/Cytoscape.js。

## 技术栈
- **架构**: 零构建SPA（原生JS，无Webpack/Vite）
- **路由**: Hash路由（`#/page-name`），支持参数（`#/findings?scan_id=xxx`）
- **图表**: Canvas原生引擎（xj-charts.js），支持Pie/Bar/Line/Radar/Gauge
- **图可视化**: Canvas原生引擎（xj-graph.js），支持力导向布局、拖拽、缩放
- **事件流**: WebSocket自动重连（指数退避1s→2s→4s→8s→max30s）+ 降级轮询（5s间隔）
- **安全**: XSS防御层（输出编码+URL校验+DOM净化+CSP头）
- **样式**: 原CSS变量系统，暗色主题，无预处理器

## 12个页面清单

### v2核心页面（6个）
1. **Dashboard首页** (`#/dashboard`) - 全局统计卡片 + 事件流时间线 + 发现判定环形图
2. **扫描中心** (`#/scan`) - 路径/语言/规则集配置 + 进度条实时显示
3. **发现管理** (`#/findings`) - 过滤搜索 + 三态标注（确认/疑似/排除）
4. **开发者画像** (`#/profile`) - 误报率趋势图 + 优化建议 + TOP误报规则
5. **报表中心** (`#/reports`) - 报告模板卡片 + 导出功能（JSON/MD/SARIF）
6. **系统设置** (`#/settings`) - 通用/扫描器/AI引擎/API密钥/安全设置

### v3新增页面（5个）
7. **AI渗透测试** (`#/ai-pentest`) - 攻击链图可视化 + 三态标注 + POC自动验证器
8. **自动修复PR** (`#/auto-fix`) - Diff预览 + 三重校验面板 + PR列表跟踪
9. **行业基准** (`#/benchmark`) - 6维度雷达图 + 11行业安全评分对标
10. **隐私协同** (`#/privacy`) - 联邦训练监控 + 合规达标 + 协同任务
11. **DevSecOps** (`#/devsecops`) - 门禁看板 + 工单生命周期 + Webhook集成

## 文件结构
```
v31_frontend/
├── index.html              # SPA入口
├── style.css               # 暗色主题样式系统
├── app.js                  # 应用启动（路由注册+导航构建）
├── README.md               # 本文档
├── core/
│   ├── xss-defense.js      # XSS防御层（输出编码/DOM净化）
│   ├── api-client.js       # REST API客户端（fetch封装）
│   ├── event-stream.js     # 事件流管理器（WS+轮询降级）
│   ├── router.js           # Hash路由器（支持参数和钩子）
│   └── ui-engine.js        # UI工具（Toast/Modal/工具函数）
├── vendor/
│   ├── xj-charts.js        # 图表引擎（替代ECharts）
│   └── xj-graph.js         # 图可视化引擎（替代Cytoscape.js）
└── pages/
    ├── pages.js            # 页面注册中心
    ├── page-dashboard.js   # Dashboard首页
    ├── page-scan.js        # 扫描中心
    ├── page-findings.js    # 发现管理
    ├── page-profile.js     # 开发者画像
    ├── page-reports.js     # 报表中心
    ├── page-settings.js    # 系统设置
    ├── page-ai-pentest.js  # AI渗透测试
    ├── page-auto-fix.js    # 自动修复PR
    ├── page-benchmark.js   # 行业基准
    ├── page-privacy.js     # 隐私协同
    └── page-devsecops.js   # DevSecOps
```

## 安全防护措施
1. **输出编码**: 所有用户可控内容通过 `XSS.escapeHtml()` 处理后再插入DOM
2. **URL校验**: `XSS.sanitizeUrl()` 阻止 javascript: data: vbscript: 伪协议
3. **DOM净化**: `XSS.sanitizeHtml()` 使用白名单标签过滤
4. **CSP兼容**: meta标签启用 X-Content-Type-Options/X-Frame-Options/Referrer-Policy
5. **textContent优先**: UI引擎全部使用 textContent 而非 innerHTML 插入文本

## 集成方式
将 `index.html` + 所有子目录挂载到任意静态文件服务器，或集成到 fp_sentinel/web/static/ 目录。

### 与后端API对接
API客户端默认发送请求到 `/api/v1/*` 和 `/api/privacy/*` 和 `/api/devops/*`，
可通过 `API.setBaseUrl()` 配置前缀。

## 浏览器兼容性
- Chrome 80+
- Firefox 75+
- Safari 13+
- Edge 80+
（依赖ES6+特性：const/let、箭头函数、Promise、fetch、class）
