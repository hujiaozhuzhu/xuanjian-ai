
```
  ██╗  ██╗██╗   ██╗ █████╗ ███╗   ██╗     ██╗██╗ █████╗ ███╗  ██╗
  ╚██╗██╔╝██║   ██║██╔══██╗████╗  ██║     ██║██║██╔══██╗████╗ ██║
   ╚███╔╝ ██║   ██║███████║██╔██╗ ██║     ██║██║███████║██╔██╗██║
   ██╔██╗ ██║   ██║██╔══██║██║╚██╗██║██   ██║██║██╔══██║██║╚████║
  ██╔╝ ██╗╚██████╔╝██║  ██║██║ ╚████║╚█████╔╝██║██║  ██║██║ ╚███║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝
```

# 🔍 玄鉴 XuanJian AI

> **鉴伪存真，洞察代码风险** — 面向安全研究团队的开源代码审计误报排查工具

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![MCP](https://img.shields.io/badge/MCP-1.0-green.svg)](https://modelcontextprotocol.io)

---

## ✨ 功能特性

| 特性 | 说明 |
|------|------|
| 🎯 **三层过滤架构** | L1 规则过滤 → L2 上下文分析 → L3 历史基线，逐层精炼 |
| ☕ **Java 优先** | 深度覆盖 SQL注入、XSS、SSRF、命令注入、反序列化、路径穿越等 Java 安全场景 |
| 🔌 **MCP 集成** | 8 个 MCP 工具，无缝接入 Claude Desktop、Cursor 等 AI 客户端 |
| 🖥️ **Web 仪表板** | 内置暗色主题 Web UI，支持实时扫描进度、结果浏览、误报标记 |
| 🛠️ **多扫描器适配** | 支持 Semgrep、Bandit、FindSecBugs，自动语言检测与扫描器调度 |
| 📊 **历史基线** | 基于指纹的误报记忆，标记一次，永远过滤 |

## 📈 效果展示

典型 Java 项目扫描结果（示例数据）：

```
┌─────────────────────────────────────────────────┐
│  扫描器原始发现:     247 条                       │
│  ─────────────────────────────────               │
│  L1 规则过滤:        -89 条  (路径白名单+Java规则)│
│  L2 上下文分析:      -72 条  (安全守卫+死代码)     │
│  L3 历史基线:        -31 条  (指纹匹配)           │
│  ─────────────────────────────────               │
│  最终待复核:          55 条                       │
│  误报减少率:         77.7%                        │
└─────────────────────────────────────────────────┘
```

## 🚀 快速开始

### 安装

```bash
git clone https://github.com/hujiaozhuzhu/xuanjian-ai.git
cd xuanjian-ai

python3 -m venv .venv
source .venv/bin/activate

# 基础安装
pip install -e .

# 完整安装（含扫描器、ML、Web、开发依赖）
pip install -e ".[all]"
```

### 配置

创建 `xuanjian.yaml` 配置文件（可选，有合理默认值）：

```yaml
project:
  name: my-project
  path: .
  language: auto

scanners:
  semgrep:
    enabled: true
    timeout: 300
  findsecbugs:
    enabled: true
  bandit:
    enabled: true

filters:
  rule_filter:
    enabled: true
  context_filter:
    enabled: true
  ml_filter:
    enabled: true

database:
  path: ~/.xuanjian/data.db
  wal_mode: true
```

### 启动 MCP Server

```bash
# stdio 模式（推荐用于 AI 客户端集成）
fp-sentinel mcp --transport stdio

# SSE 模式
fp-sentinel mcp --transport sse --port 8000
```

### 启动 Web 仪表板

```bash
fp-sentinel web --host 0.0.0.0 --port 8080
```

浏览器访问 `http://localhost:8080` 即可使用。

### CLI 使用

```bash
# 扫描项目
fp-sentinel scan /path/to/project --lang java --format table

# 列出发现
fp-sentinel list --severity HIGH --lang java

# 标记误报
fp-sentinel mark <finding-id> --reason "使用PreparedStatement" --scope rule

# 查看统计
fp-sentinel stats
```

## 🔧 MCP 工具列表

玄鉴提供 8 个 MCP 工具供 AI 客户端调用：

| # | 工具名 | 说明 |
|---|--------|------|
| 1 | `scan_project` | 扫描项目，自动检测语言并调度扫描器，返回 scan_id 和统计信息 |
| 2 | `triage_findings` | 对扫描结果进行分诊，应用三层过滤器识别误报 |
| 3 | `explain_finding` | 解释单条发现，提供详细分析、Java 安全分析和处理建议 |
| 4 | `mark_false_positive` | 将发现标记为误报，写入历史基线供后续自动过滤 |
| 5 | `list_findings` | 列出扫描发现，支持按 verdict、severity 过滤 |
| 6 | `export_report` | 导出扫描报告，支持 JSON 和 Markdown 格式 |
| 7 | `get_statistics` | 获取项目统计信息（误报率、减少率等） |
| 8 | `list_projects` | 列出已扫描的项目及其统计概况 |

## 🏗️ 架构图

```
┌─────────────────────────────────────────────────────────────┐
│                      AI 客户端                               │
│              (Claude Desktop / Cursor / 自研)                 │
└─────────────────────┬───────────────────────────────────────┘
                      │ MCP Protocol (stdio/SSE)
┌─────────────────────▼───────────────────────────────────────┐
│                   MCP Server (FastMCP)                       │
│              fp_sentinel/mcp_server.py                       │
│  ┌──────────┬──────────┬──────────┬──────────┐              │
│  │scan_     │triage_   │explain_  │mark_fp   │ ...×8 工具   │
│  │project   │findings  │finding   │          │              │
│  └────┬─────┴────┬─────┴────┬─────┴────┬─────┘              │
│       │          │          │          │                     │
│  ┌────▼──────────▼──────────▼──────────▼──────┐             │
│  │            核心服务层 (FPServer)             │             │
│  └────────────────┬───────────────────────────┘             │
│                   │                                          │
│  ┌────────────────▼───────────────────────────┐             │
│  │           三层过滤流水线                      │             │
│  │                                              │             │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  │             │
│  │  │ L1 规则  │─→│ L2 上下文│─→│ L3 基线  │  │             │
│  │  │ 过滤器   │  │ 分析器   │  │ 匹配器   │  │             │
│  │  └──────────┘  └──────────┘  └──────────┘  │             │
│  └─────────────────────────────────────────────┘             │
│                   │                                          │
│  ┌────────────────▼───────────────────────────┐             │
│  │           扫描器管理器                       │             │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐   │             │
│  │  │ Semgrep  │ │ FindSec  │ │  Bandit  │   │             │
│  │  │ Scanner  │ │ Bugs     │ │ Scanner  │   │             │
│  │  └──────────┘ └──────────┘ └──────────┘   │             │
│  └─────────────────────────────────────────────┘             │
│                   │                                          │
│  ┌────────────────▼───────────────────────────┐             │
│  │  SQLite (WAL)  │  基线指纹库  │  配置管理   │             │
│  └─────────────────────────────────────────────┘             │
└─────────────────────────────────────────────────────────────┘
         │
┌────────▼────────────────────────────────────────────────────┐
│               Web 仪表板 (FastAPI + 内联 HTML)               │
│         REST API  │  WebSocket 实时推送  │  Dashboard        │
└─────────────────────────────────────────────────────────────┘
```

## ☕ Java 误报规则覆盖范围

| 漏洞类型 | 覆盖的安全模式 | 识别的误报模式 |
|----------|---------------|---------------|
| SQL 注入 | PreparedStatement、MyBatis `#{}`、ORM、参数化查询 | 常量SQL、JpaRepository、CrudRepository |
| XSS | HTML 转义、模板自动转义、JSON 响应 | `@RestController`、`HtmlUtils`、`Jsoup.clean` |
| SSRF | URL 白名单、Host 校验 | `allowlist`、`isValidUrl`、`UriComponentsBuilder` |
| 命令注入 | 常量命令、命令白名单 | `Runtime.exec("常量")`、`allowedCommands` |
| 反序列化 | ObjectInputFilter、可信数据源 | `SerializationFilter`、`whitelistClasses` |
| 路径穿越 | 路径规范化、目录限制 | `normalize()`、`getCanonicalPath()` |
| 硬编码密码 | 测试/示例文件识别 | `*Test.java`、`*/examples/*` |
| 弱加密 | TLS 版本检测 | TLS 1.3 配置 |

详见 [Java 误报规则文档](docs/java-rules.md)。

## 🗺️ 路线图

### Phase 1：核心稳定化 ✅
- [x] MCP Server（8 个工具）
- [x] 三层过滤架构
- [x] CLI 命令行工具
- [x] Web 仪表板
- [x] SQLite 持久化
- [x] Java 误报规则库

### Phase 2：Java 审计增强 🚧
- [x] Semgrep Java 输出标准化
- [x] FindSecBugs 输出解析
- [x] Java 上下文识别器（MyBatis、Spring、JPA）
- [ ] SpotBugs 输出解析
- [ ] 更多 Java 框架支持（Quarkus、Micronaut）

### Phase 3：智能增强 📋
- [ ] LLM 辅助误报判断
- [ ] 团队协作与多用户
- [ ] CI/CD 集成（GitHub Actions、GitLab CI）
- [ ] 插件系统

### Phase 4：生态扩展 🔮
- [ ] Go 语言深度支持
- [ ] JavaScript/TypeScript 支持
- [ ] IDE 插件（VS Code、IntelliJ）
- [ ] SaaS 版本

## 🤝 贡献

欢迎贡献！请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 📄 License

[MIT License](LICENSE) — 自由使用，自由修改，自由分发。

---

<p align="center">
  <sub>由玄鉴团队用 ❤️ 构建 | 鉴伪存真，让代码审计更高效</sub>
</p>
