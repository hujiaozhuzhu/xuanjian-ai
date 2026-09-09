```
  ██╗  ██╗██╗   ██╗ █████╗ ███╗   ██╗     ██╗██╗ █████╗ ███╗  ██╗
  ╚██╗██╔╝██║   ██║██╔══██╗████╗  ██║     ██║██║██╔══██╗████╗ ██║
   ╚███╔╝ ██║   ██║███████║██╔██╗ ██║     ██║██║███████║██╔██╗██║
   ██╔██╗ ██║   ██║██╔══██║██║╚██╗██║██   ██║██║██╔══██║██║╚████║
  ██╔╝ ██╗╚██████╔╝██║  ██║██║ ╚████║╚█████╔╝██║██║  ██║██║ ╚███║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝
```

# 玄鉴 XuanJian AI v3.1

> **鉴伪存真，洞察代码风险** — 面向安全研究团队的 AI 驱动代码安全审计与红蓝对抗平台

> v3.1 融合 AI 自主渗透测试、自动化修复 PR、DevSecOps 流水线集成、行业基准对标、隐私计算协同审计五大新模块，全版本号统一。不会执行、解密、动态解包或修改被扫描文件。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![MCP](https://img.shields.io/badge/MCP-1.0-green.svg)](https://modelcontextprotocol.io)

---

## 目录

- [v3.1 新特性](#v31-新特性)
- [快速开始](#快速开始)
- [子命令列表](#子命令列表)
- [Web 仪表板](#web-仪表板)
- [安全红线](#安全红线)
- [文档导航](#文档导航)
- [架构概览](#架构概览)
- [版本历史](#版本历史)
- [License](#license)

---

## v3.1 新特性

### AI 自主渗透测试 (Agent-AI-Pentest)

| 能力 | 说明 |
|------|------|
| GNN 攻击链推理 | 4 头图注意力网络，节点角色分类（entry / intermediate / sink） |
| 5 种可视化 | Mermaid / DOT / JSON / ASCII / D3.js 交互式 HTML |
| PoC 自动生成 | 攻击链感知组合脚本，payload 黑名单防御 |
| 漏洞自动验证 | 三态诚实标注：verified_local / simulated / manual_required |
| 靶场编排 | Docker/Podman 自动检测，端口冲突管理，状态持久化 |

### 自动化修复 (Auto PR)

| 能力 | 说明 |
|------|------|
| 16 类漏洞模板 | 覆盖 OWASP Top 10，含 bad_patterns / good_example |
| 三重校验 | 语法检查 + 原漏洞修复确认 + 新漏洞引入检测 |
| PR 管理 | GitLab / GitHub 双适配器，自动关联漏洞单 |
| dry_run 模式 | 全流程离线测试，不调用外部 API |

### DevSecOps 集成

| 能力 | 说明 |
|------|------|
| Pipeline 门禁 | 支持阻断/警告两种安全策略 |
| 工单引擎 | 全生命周期自动化流转 |
| 多平台适配 | GitLab / Jira / GitHub |
| Webhook | 实时接收 CI/CD 事件 |

### 行业基准对标

| 能力 | 说明 |
|------|------|
| 11 个行业 | 互联网、银行、政务、工业控制、医疗、教育、运营商、能源、交通、保险、证券 |
| 四维差距分析 | 漏洞密度、修复速度、合规评分、覆盖范围 |
| 25+ 行业规则 | GB/T 22239、JR/T 0071 等国家/行业标准映射 |

### 隐私计算协同审计

| 能力 | 说明 |
|------|------|
| 联邦学习 | FedAvg + 差分隐私 + 梯度加密 |
| 规则共享 | 四级敏感度 + 自动脱敏引擎 |
| 合规验证 | 数据安全法、等保2.0、PIPL、ISO 27001 |
| 协同任务 | 六态状态机 + 团队隔离视图 |

### 粒子群反馈优化 (FP Optimize)

基于历史误报反馈的自适应降噪优化，持续提升扫描准确率。

---

## 快速开始

### 安装

```bash
git clone https://github.com/hujiaozhuzhu/xuanjian-ai.git
cd xuanjian-ai

python3 -m venv .venv
source .venv/bin/activate

# 基础安装
pip install -e .

# 完整安装（含浏览器引擎、扫描器、ML、Web、AI 渗透测试）
pip install -e ".[all]"
```

### Windows 用户

```powershell
python -m fp_sentinel --version
python -m fp_sentinel scan C:\path\to\project --lang javascript
```

GBK/CP936 终端自动使用 ASCII 状态标记，不会改动系统代码页。

---

## 子命令列表

### 代码扫描

```bash
# 扫描项目
fp-sentinel scan /path/to/project --format table
fp-sentinel scan /path/to/project --lang {java,python,go,javascript,typescript,auto}

# 列出发现 / 误报标记 / 统计
fp-sentinel list --severity HIGH
fp-sentinel mark <finding-id> --reason "..." --scope rule
fp-sentinel stats
```

### 报告生成

```bash
fp-sentinel scan /path/to/project --report compliance --output ./reports
fp-sentinel scan /path/to/project --report attack --output ./reports
fp-sentinel scan /path/to/project --report all --output ./reports
```

### 攻防测试

```bash
fp-sentinel attack chains /path/to/project           # 攻击链推理
fp-sentinel attack poc <finding-id>                  # PoC 生成
fp-sentinel attack verify /path/to/project           # 自动验证
fp-sentinel attack lab start                         # 启动靶场
fp-sentinel attack purge --days 30                   # 清理记录
```

### 自动化修复

```bash
fp-sentinel auto-pr fix <finding-id> --dry-run       # 生成修复建议
fp-sentinel auto-pr submit <finding-id>              # 提交修复 PR
fp-sentinel auto-pr list                             # 查看 PR 列表
```

### 企业权限管理

```bash
fp-sentinel perm user create <username> --role security_engineer
fp-sentinel perm project grant <project> <user> --role developer
fp-sentinel perm audit                               # 查看审计日志
```

### 企业任务管理

```bash
fp-sentinel task create <project_id> "修复SQL注入" --type vuln_fix --priority P0
fp-sentinel task bulk-create <project_id> <fid1,fid2> --priority P1
fp-sentinel task list --status assigned
fp-sentinel task stats --project <project_id>
```

### 企业通知

```bash
fp-sentinel notify channel add feishu --url https://...
fp-sentinel notify rule add --severity CRITICAL --frequency realtime
fp-sentinel notify history
```

### 开发者画像

```bash
fp-sentinel profile me /path/to/project
fp-sentinel profile team /path/to/project
fp-sentinel profile forget /path/to/project --alias <alias>
```

### 知识图谱

```bash
fp-sentinel scan /path/to/project --kg --kg-version v1.2.0
fp-sentinel kg match --rule-id "java.sql.injection"
fp-sentinel kg search --project my-app --type sql_injection
fp-sentinel kg stats
```

### 可视化

```bash
fp-sentinel viz heatmap /path/to/project --output reports/heatmap.html
fp-sentinel viz trend /path/to/project --output reports/trend.png
```

### 行业对标

```bash
fp-sentinel industry analyze /path/to/project --target finance
fp-sentinel industry compare --baseline internet
fp-sentinel industry rules --industry healthcare
```

### 隐私计算

```bash
fp-sentinel privacy train --rounds 10 --participants 5 --epsilon 1.0
fp-sentinel privacy rule create "SQL Detector" sql_injection --pattern "..."
fp-sentinel privacy validate --standards dsl,djcp
fp-sentinel privacy collab demo --teams 3
```

### DevSecOps

```bash
fp-sentinel devops pipeline check /path/to/project --gate block
fp-sentinel devops ticket list --status open
fp-sentinel devops webhook receive --event push
```

### MCP Server

```bash
fp-sentinel mcp --transport stdio     # AI 客户端集成
fp-sentinel mcp --transport sse --port 8000
```

### 浏览器自动化 (JSRPC)

```bash
fp-sentinel browser start --url "https://target.com/login"
fp-sentinel browser hook --target "encrypt" --type trace
fp-sentinel browser call --func "encryptPassword" --args '["test"]'
fp-sentinel browser keys
```

---

## Web 仪表板

启动 Web 服务后访问 `http://localhost:8080`。

```bash
fp-sentinel web serve --port 8080
```

### 页面说明

| 路径 | 功能 |
|------|------|
| `/` | 安全审计仪表板首页 |
| `/api/projects` | 项目列表 API |
| `/api/scan` | 启动扫描 API |
| `/api/findings` | 发现列表 API |
| `/api/stats` | 统计信息 API |
| `/docs` | Swagger 交互式 API 文档 |
| `/redoc` | ReDoc API 文档 |

### REST API

完整 API 参考见 [docs/api-reference.md](docs/api-reference.md)。

---

## 安全红线

| 红线 | 实现 |
|------|------|
| **S1 零网络** | 核心引擎纯本地计算，攻击 PoC 仅 localhost/127.0.0.1/::1 |
| **S2 不修改代码** | 工具只读被扫描文件，修复建议仅生成 diff/PR |
| **S3 不删除文件** | 仅操作本地 SQLite 数据 |
| **S4 无真实攻击** | Docker 验证必须显式开启，默认 simulated |
| **S5 保留策略** | PoC/通知记录支持按保留期自动清理 |
| **S6 隐私保护** | 开发者 email 不落盘，SHA256 匿名别名 |
| **S7 路径白名单** | 数据库/报告路径固定于 `~/.xuanjian/` |
| **S8 加密传输** | 联邦学习梯度强制加密 |
| **S9 规则脱敏** | 共享规则自动多层清洗 |

---

## 文档导航

| 文档 | 内容 |
|------|------|
| [docs/architecture.md](docs/architecture.md) | 系统架构详解（分层设计、数据流、扫描器适配器） |
| [docs/api-reference.md](docs/api-reference.md) | REST API 参考（13 个端点 + WebSocket） |
| [docs/deployment.md](docs/deployment.md) | 部署指南（裸机 / Docker / 外部依赖） |
| [docs/java-rules.md](docs/java-rules.md) | Java 误报规则库文档 |
| [docs/mcp-integration.md](docs/mcp-integration.md) | MCP 集成方式 |
| [docs/claude-config.md](docs/claude-config.md) | Claude API 配置指南 |
| [docs/web-dashboard.md](docs/web-dashboard.md) | Web 仪表板功能说明 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献指南 |
| [CHANGELOG.md](CHANGELOG.md) | 版本变更日志 |

### 知识图谱归档

| 模块目录 | 覆盖子模块 |
|---------|-----------|
| `knowledge_graph/modules/attack/` | A1~A7: PoC/利用性/靶场/报告/合规/CLI |
| `knowledge_graph/modules/v3_ai_pentest/` | A1~A4: GNN/PoC生成/验证/靶场 |
| `knowledge_graph/modules/v3_auto_pr/` | A1~C3: 修复生成/校验/PR管理 |
| `knowledge_graph/modules/v3_devops/` | A1~H8: 模型/适配器/门禁/工单/Webhook |
| `knowledge_graph/modules/v3_industry/` | A1~F6: 数据/对比/规则/修复/API/测试 |
| `knowledge_graph/modules/v3_industry_full/` | 增强版行业对标（含修复顾问） |
| `knowledge_graph/modules/v3_privacy/` | A1~A4: 联邦/共享/验证/协同 |
| `knowledge_graph/modules/enterprise_notify/` | N1~N6: 通知模型/引擎/Webhook |
| `knowledge_graph/modules/enterprise_perm/` | E1~E5: 权限模型/仓库/检查/审计 |
| `knowledge_graph/modules/enterprise_task/` | A~D: 分配/跟踪/评审/统计 |
| `knowledge_graph/modules/profile/` | P1~P6: 画像模型/归因/算法/报告/隐私/CLI |
| `knowledge_graph/modules/knowledge_integration/` | A1~A2: 查询插件/自动归档 |
| `knowledge_graph/modules/knowledge_visual/` | A~B: 热力图/趋势图 |
| `knowledge_graph/modules/multi_language/` | A~C: Go规则/JS增强/扫描器管理 |
| `knowledge_graph/modules/rule_optimization/` | A1~A3: 自动调优/自定义规则/Java优化 |

---

## 架构概览

```
┌──────────────────────────────────────────────────────────────────────┐
│                          接入层                                       │
│  ┌──────────────┐  ┌───────────────┐  ┌────────────────────────────┐ │
│  │  MCP Server  │  │  Web Server   │  │      CLI (Typer)           │ │
│  │  (FastMCP)   │  │  (FastAPI)    │  │ scan/attack/auto-pr/devops │ │
│  └──────┬───────┘  └──────┬────────┘  └────────────┬───────────────┘ │
└─────────┼─────────────────┼─────────────────────────┼───────────────┘
          │                 │                         │
┌─────────▼─────────────────▼─────────────────────────▼───────────────┐
│                         核心服务层                                    │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                    FPServer 核心服务                            │  │
│  │   扫描调度 │ 降噪流水线 │ GNN推理 │ Auto-PR │ Pipeline门禁     │  │
│  └────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────────┐
│                          引擎层                                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐  │
│  │ GNN Attack│ │ Auto Fix │ │ Privacy  │ │ Industry │ │  规则   │  │
│  │ Reasoner │ │ Generator│ │ Engine   │ │ Benchmark│ │ 优化器  │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └─────────┘  │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    四级降噪流水线                              │   │
│  │          L1 语法 → L2 语义 → L3 统计 → L4 LLM 智能           │   │
│  └──────────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                     扫描器适配层                               │   │
│  │   Semgrep │ FindSecBugs │ Bandit │ Go Scanner │ JS Scanner   │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────────┐
│                          数据层                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  SQLite (WAL) │ 知识图谱 │ 行业基准 │ 联邦学习 │ 配置管理    │   │
│  └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 多语言规则覆盖

### JavaScript/TypeScript (78 条规则)

| 类别 | 规则数 | 覆盖 |
|------|--------|------|
| XSS | 8 | innerHTML, outerHTML, document.write, jQuery.html 等 |
| 注入 | 4 | eval, Function, setTimeout(string), 动态脚本加载 |
| 原型污染 | 3 | Object.assign, 深合并, 动态属性访问 |
| 加密 | 5 | Math.random, MD5, SHA1, DES, ECB 模式 |
| AIGC | 15 | Prompt Injection, LLM 输出执行, 幻觉依赖 |

### Go (29 条规则，v2.3.0 新增)

覆盖 SQL 注入、命令注入、路径遍历、不安全的反序列化、SSRF、硬编码凭据等。

### Java (70+ 条规则)

详见 [docs/java-rules.md](docs/java-rules.md)。

### Python (20 条规则)

覆盖 SQL 注入、命令注入、反序列化、弱加密、认证缺陷等。

---

## 性能基准

| 指标 | 基线 |
|------|------|
| 扫描速度 | > 500 行/秒 |
| 10 万行耗时 | < 3 分钟 |
| 内存占用 | < 2 GB |

---

## 版本历史

详见 [CHANGELOG.md](CHANGELOG.md)。

### 主要里程碑

| 版本 | 日期 | 关键特性 |
|------|------|---------|
| v1.0 | — | MCP Server、Java 规则库、三层过滤 |
| v2.0 | 2026-09-06 | 四级降噪、红蓝对抗、JSRPC 浏览器、攻击链 |
| v2.3 | 2026-09-07 | Go 语言、规则自动调优、YAML 自定义规则 |
| v2.5 | 2026-09-07 | 企业权限、任务管理、通知、画像 |
| **v3.1** | **2026-09-10** | **AI 渗透测试、Auto-PR、DevSecOps、行业对标、隐私计算** |

---

## License

[MIT License](LICENSE) — 自由使用，自由修改，自由分发。

---

<p align="center">
  <sub>由玄鉴团队用 ❤️ 构建 | 鉴伪存真，让代码审计更高效</sub>
</p>
