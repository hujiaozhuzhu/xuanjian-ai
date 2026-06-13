# 系统架构详解

本文档详细描述玄鉴 (XuanJian AI) 的系统架构、核心模块设计和数据流。

## 整体架构

玄鉴采用分层架构设计，从上到下分为：

```
┌─────────────────────────────────────────────────────────┐
│                    接入层 (Access Layer)                  │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  MCP Server │  │  Web Server  │  │   CLI 工具     │  │
│  │  (FastMCP)  │  │  (FastAPI)   │  │   (Typer)     │  │
│  └──────┬──────┘  └──────┬───────┘  └───────┬───────┘  │
└─────────┼────────────────┼──────────────────┼───────────┘
          │                │                  │
┌─────────▼────────────────▼──────────────────▼───────────┐
│                  服务层 (Service Layer)                   │
│  ┌──────────────────────────────────────────────────┐   │
│  │                 FPServer 核心服务                  │   │
│  │  · 扫描调度    · 过滤流水线    · 结果管理          │   │
│  │  · 误报标记    · 报告导出      · 统计分析          │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                  核心层 (Core Layer)                      │
│  ┌─────────────────────────────────────────────────┐    │
│  │              三层过滤引擎                         │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐      │    │
│  │  │ L1 规则  │─→│ L2 上下文│─→│ L3 基线  │      │    │
│  │  │ 过滤器   │  │ 分析器   │  │ 匹配器   │      │    │
│  │  └──────────┘  └──────────┘  └──────────┘      │    │
│  └─────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────┐    │
│  │              扫描器适配器                         │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐      │    │
│  │  │ Semgrep  │  │ FindSec  │  │  Bandit  │      │    │
│  │  │ Adapter  │  │ Bugs     │  │ Adapter  │      │    │
│  │  └──────────┘  └──────────┘  └──────────┘      │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                  数据层 (Data Layer)                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ SQLite   │  │ 基线指纹 │  │ YAML     │              │
│  │ (WAL)    │  │ JSON     │  │ 配置     │              │
│  └──────────┘  └──────────┘  └──────────┘              │
└─────────────────────────────────────────────────────────┘
```

## 三层过滤流程图

每条扫描结果都经过三层过滤器的串行处理：

```
扫描结果 (ScanResult)
       │
       ▼
┌──────────────────────────────────────────┐
│  L1: 规则过滤器 (RuleFilter)              │
│                                          │
│  检查顺序:                                │
│  1. 路径白名单 (测试/示例/vendor/generated)│
│  2. 代码忽略标记 (nosec/NOSONAR/noqa)     │
│  3. 历史误报指纹                          │
│  4. 自定义规则 + Java 内置规则            │
│                                          │
│  匹配 → 判定为 FALSE_POSITIVE            │
│  置信度 ≥ 阈值 → 直接返回                 │
│  不匹配 → 传递到 L2                       │
└──────────────┬───────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│  L2: 上下文过滤器 (ContextFilter)         │
│                                          │
│  分析内容:                                │
│  1. 读取漏洞行前后 20 行代码               │
│  2. 检测死代码路径                        │
│  3. 识别安全守卫 (PreparedStatement 等)    │
│  4. 识别输入验证 (@Valid/@NotNull 等)      │
│  5. Java 特定分析:                        │
│     - MyBatis #{} vs ${}                  │
│     - ORM 框架识别                        │
│     - HTML 转义函数                       │
│     - URL/命令白名单                      │
│                                          │
│  误报分数 ≥ 阈值 → LIKELY_FALSE_POSITIVE  │
│  否则 → 传递到 L3                         │
└──────────────┬───────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│  L3: 历史基线过滤器 (BaselineFilter)      │
│                                          │
│  匹配方式:                                │
│  1. 精确指纹匹配 (MD5: tool+rule+file+   │
│     code+line)                           │
│  2. 模糊指纹匹配 (同规则+同路径+代码      │
│     Jaccard 相似度 ≥ 0.85)               │
│                                          │
│  精确匹配 → FALSE_POSITIVE               │
│  模糊匹配 → LIKELY_FALSE_POSITIVE        │
│  不匹配 → NEEDS_REVIEW                    │
└──────────────────────────────────────────┘
               │
               ▼
      最终判定 (FilterResult)
      ┌────────────────────────────┐
      │ verdict: 判定结果           │
      │ confidence: 置信度          │
      │ risk_score: 风险评分        │
      │ filter_reasons: 过滤原因    │
      │ recommendation: 处理建议    │
      │ context_analysis: 上下文详情│
      │ java_analysis: Java 分析    │
      └────────────────────────────┘
```

### 过滤器决策逻辑

```python
async def _apply_filters(scan_result, filter_level="all", confidence_threshold=0.7):
    # L1: 规则过滤
    if filter_level in ("L1", "all"):
        l1 = await rule_filter.filter(scan_result)
        if l1.is_false_positive and l1.confidence >= confidence_threshold:
            return l1  # 高置信度，提前返回

    # L2: 上下文分析
    if filter_level in ("L2", "all"):
        l2 = await context_filter.filter(scan_result)
        if l2.is_false_positive and l2.confidence >= confidence_threshold:
            return l2
        # 保留置信度更高的结果

    # L3: 历史基线
    if filter_level in ("L3", "all"):
        l3 = await ml_filter.filter(scan_result)
        if l3.is_false_positive and l3.confidence >= confidence_threshold:
            return l3

    # 返回最佳结果或 NEEDS_REVIEW
    return best_result or NEEDS_REVIEW
```

## 数据模型说明

### 核心枚举

| 枚举 | 值 | 说明 |
|------|-----|------|
| `Severity` | CRITICAL, HIGH, MEDIUM, LOW, INFO | 漏洞严重程度 |
| `ScanTool` | semgrep, bandit, gosec, findsecbugs, spotbugs, manual | 扫描工具类型 |
| `Verdict` | true_positive, false_positive, likely_false_positive, needs_review | 判定结果 |
| `Language` | java, python, go, javascript, typescript, auto | 编程语言 |

### 核心模型

```
ScanResult (扫描结果)
├── id: str
├── tool: ScanTool
├── rule_id: str
├── file: str
├── line: int
├── code: str
├── severity: Severity
├── message: str
├── cwe: str (可选)
└── owasp: str (可选)

FilterResult (过滤结果)
├── id: str
├── original: ScanResult
├── verdict: Verdict
├── confidence: float (0-1)
├── filter_reasons: List[FilterReason]
├── risk_score: float (0-10)
├── recommendation: str
├── context_analysis: dict (可选)
└── java_analysis: dict (可选)

Finding (归一化发现)
├── id: str
├── scanner: str
├── rule_id: str
├── severity: Severity
├── file_path: str
├── line_start: int
├── code_snippet: str
├── message: str
├── category: str (如 SQL_INJECTION, XSS)
├── language: str
├── fingerprint: str
├── cwe: str
└── owasp: str
```

### 模型关系

```
ScanResult  ──过滤──→  FilterResult  ──归一化──→  Finding
                           │
                           ├── FilterReason (过滤原因)
                           ├── ContextAnalysisResult (上下文分析)
                           └── JavaAnalysisResult (Java 分析)
```

## MCP 协议集成方式

玄鉴使用 [Model Context Protocol (MCP)](https://modelcontextprotocol.io) 提供工具接口。

### 架构

```
┌─────────────┐     MCP Protocol      ┌──────────────┐
│  AI 客户端   │ ◄──────────────────► │  MCP Server   │
│ (Claude/    │  stdio / SSE / HTTP   │  (FastMCP)    │
│  Cursor)    │                       │               │
└─────────────┘                       └──────┬───────┘
                                             │
                                      ┌──────▼───────┐
                                      │  FPServer    │
                                      │  (核心服务)   │
                                      └──────────────┘
```

### 传输方式

| 传输 | 适用场景 | 启动方式 |
|------|---------|---------|
| `stdio` | 本地 AI 客户端集成 | `fp-sentinel mcp --transport stdio` |
| `sse` | 远程服务 / HTTP 集成 | `fp-sentinel mcp --transport sse --port 8000` |

### 工具注册

使用 FastMCP 装饰器模式注册工具：

```python
from mcp.server.fastmcp import FastMCP

self.mcp = FastMCP("xuanjian-code-audit")

@self.mcp.tool()
async def scan_project(project_path: str, language: str = "auto") -> str:
    """扫描项目"""
    # 实现...
```

## 扫描器适配器设计

### 基类

所有扫描器继承 `BaseScanner` 抽象基类：

```python
class BaseScanner(ABC):
    @abstractmethod
    async def scan(self, target_path: str, **kwargs) -> List[ScanResult]:
        """扫描目标路径，返回归一化的 ScanResult 列表"""
        pass

    @abstractmethod
    def get_tool_type(self) -> ScanTool:
        """返回扫描工具类型枚举"""
        pass
```

### 已实现的适配器

| 适配器 | 目标工具 | 语言 | 输出格式解析 |
|--------|---------|------|-------------|
| `SemgrepScanner` | Semgrep | 多语言 | JSON (`--json`) |
| `BanditScanner` | Bandit | Python | JSON (`-f json`) |
| `FindSecBugsScanner` | FindSecBugs | Java | SARIF/文本 |

### 扫描器管理器

`ScannerManager` 负责：

1. **语言检测** — 根据构建文件（pom.xml、build.gradle、requirements.txt、go.mod）或文件扩展名统计
2. **扫描器选择** — Java → Semgrep+FindSecBugs，Python → Semgrep+Bandit，Go → Semgrep
3. **并发执行** — `asyncio.gather` 并发运行多个扫描器
4. **结果聚合** — 按 `file:line:rule_id` 去重

### 添加新扫描器

```python
# 1. 创建适配器
class MyScanner(BaseScanner):
    async def scan(self, target_path, **kwargs):
        # 调用外部工具，解析输出
        return [ScanResult(...)]

    def get_tool_type(self):
        return ScanTool.MY_TOOL

# 2. 在 ScanTool 枚举中添加
# 3. 在 ScannerManager._init_scanners() 中注册
```

## 前后端通信方式

### REST API

Web 仪表板通过 REST API 与后端通信：

```
GET    /api/projects           → 项目列表
POST   /api/scan               → 启动扫描
GET    /api/findings           → 发现列表（支持过滤）
GET    /api/findings/{id}      → 发现详情
POST   /api/findings/{id}/mark-fp → 标记误报
GET    /api/stats              → 统计信息
GET    /api/scans/{id}         → 扫描状态
```

### WebSocket

扫描进度通过 WebSocket 实时推送：

```
ws://host:port/ws/scan/{scan_id}

消息格式:
{ "type": "status", "status": "running" }
{ "type": "progress", "progress": 30, "phase": "scan_complete" }
{ "type": "completed", "progress": 100, "stats": {...} }
{ "type": "error", "error": "..." }
{ "type": "pong" }  // 心跳响应
```

### 数据库

使用 SQLite（WAL 模式）持久化：

- **projects** — 项目信息
- **findings** — 安全发现
- **fp_marks** — 误报标记
- **scan_history** — 扫描历史

数据库路径默认为 `~/.xuanjian/data.db`，可通过配置文件或环境变量 `XUANJIAN_DB_PATH` 修改。
