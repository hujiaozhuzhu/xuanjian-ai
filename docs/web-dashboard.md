# Web 仪表板

本文档描述玄鉴 Web 仪表板的功能、页面说明、API 接口和配置选项。

## 功能概述

玄鉴 Web 仪表板是一个内置的暗色主题 Web 界面，提供以下功能：

- **实时扫描** — 输入项目路径，一键启动安全扫描
- **进度推送** — WebSocket 实时推送扫描进度
- **结果浏览** — 表格形式展示所有发现，支持过滤
- **误报标记** — 一键标记误报，写入历史基线
- **统计概览** — 总发现、误报数、减少率等关键指标
- **报告导出** — JSON / Markdown 格式导出

## 启动方式

```bash
# 使用 CLI
fp-sentinel web --host 0.0.0.0 --port 8080

# 使用 Python
python -c "import asyncio; from fp_sentinel.server import run_server; asyncio.run(run_server(port=8080))"
```

浏览器访问 `http://localhost:8080`。

## 页面说明

### 首页 — 仪表板总览

```
┌────────────────────────────────────────────────────────────┐
│  🔍 玄鉴 XuanJian                v0.1.0                   │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────┐│
│  │ 总发现  │ │  误报   │ │真实问题 │ │ 待复核  │ │减少率││
│  │  150    │ │   60    │ │   45    │ │   20    │ │56.7% ││
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └──────┘│
│                                                            │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  🚀 启动扫描                                         │ │
│  │                                                      │ │
│  │  项目路径: [/home/user/my-project              ]     │ │
│  │  语言:     [自动检测 ▼]                               │ │
│  │                                                      │ │
│  │  [开始扫描]                                           │ │
│  │  扫描完成！共 42 个发现，耗时 3.45s                    │ │
│  └──────────────────────────────────────────────────────┘ │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  📋 发现列表                                         │ │
│  │                                                      │ │
│  │  严重程度 │ 规则           │ 文件:行      │ 判定     │ │
│  │  ─────────┼────────────────┼──────────────┼──────────│ │
│  │  HIGH     │ sql-injection  │ UserDao:42   │ 误报     │ │
│  │  MEDIUM   │ xss            │ View:18      │ 待复核   │ │
│  │  HIGH     │ ssrf           │ Api:55       │ 真实问题 │ │
│  │  ...      │ ...            │ ...          │ ...      │ │
│  └──────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
```

**功能说明**：

1. **统计卡片** — 顶部 5 个卡片分别显示总发现数、误报数、真实问题数、待复核数、误报减少率
2. **扫描表单** — 输入项目路径和语言，点击"开始扫描"
3. **发现列表** — 表格展示所有发现，每行显示严重程度（彩色标签）、规则ID、文件位置、判定结果、置信度、操作按钮
4. **标记误报** — 每行末尾的"标记误报"按钮，点击后输入原因即可标记

### 实时进度

扫描过程中，通过 WebSocket 推送进度：

```
扫描中... [████████░░░░░░░░░░░░] 30% - 扫描完成，开始过滤
扫描中... [████████████████░░░░] 80% - 过滤进行中
扫描完成！共 42 个发现，耗时 3.45s
```

## REST API 接口文档

### 项目列表

```
GET /api/projects
```

**响应**：
```json
[
  {
    "name": "my-spring-app",
    "path": "/home/user/projects/my-spring-app",
    "language": "java",
    "scan_count": 3,
    "last_scan": "2024-01-15T10:30:00"
  }
]
```

### 启动扫描

```
POST /api/scan
Content-Type: application/json
```

**请求体**：
```json
{
  "project_path": "/path/to/project",
  "language": "auto",
  "scanners": ["semgrep", "findsecbugs"]
}
```

**响应**：
```json
{
  "scan_id": "a1b2c3d4-...",
  "total_findings": 42,
  "statistics": {
    "total": 42,
    "false_positives": 15,
    "likely_false_positives": 8,
    "true_positives": 12,
    "needs_review": 7,
    "reduction_rate": "54.8%",
    "processing_time_ms": 1234.5
  },
  "duration_seconds": 3.45
}
```

### 获取发现列表

```
GET /api/findings?scan_id={scan_id}&verdict={verdict}&severity={severity}
```

**查询参数**：
| 参数 | 类型 | 说明 |
|------|------|------|
| `scan_id` | string | 按扫描ID过滤 |
| `verdict` | string | 按判定过滤 (false_positive/true_positive/needs_review/likely_false_positive) |
| `severity` | string | 按严重程度过滤 (CRITICAL/HIGH/MEDIUM/LOW/INFO) |

**响应**：
```json
[
  {
    "id": "...",
    "original": {
      "tool": "semgrep",
      "rule_id": "java.lang.security.audit.sql-injection",
      "file": "src/UserDao.java",
      "line": 42,
      "code": "jdbcTemplate.query(sql, args)",
      "severity": "HIGH",
      "message": "Potential SQL injection"
    },
    "verdict": "false_positive",
    "confidence": 0.85,
    "risk_score": 1.35,
    "recommendation": "高置信度误报，建议忽略",
    "filter_reasons": ["..."]
  }
]
```

### 获取发现详情

```
GET /api/findings/{finding_id}
```

**响应**：单个 FilterResult 对象（同上）。

### 标记误报

```
POST /api/findings/{finding_id}/mark-fp
Content-Type: application/json
```

**请求体**：
```json
{
  "reason": "使用PreparedStatement",
  "scope": "instance"
}
```

**响应**：
```json
{
  "status": "ok"
}
```

### 获取统计信息

```
GET /api/stats?project_path={project_path}
```

**响应**：
```json
{
  "total_findings": 150,
  "false_positives": 60,
  "likely_false_positives": 25,
  "true_positives": 45,
  "needs_review": 20,
  "reduction_rate": "56.7%",
  "baseline_size": 120
}
```

### 获取扫描状态

```
GET /api/scans/{scan_id}
```

**响应**：
```json
{
  "id": "a1b2c3d4-...",
  "project_path": "/path/to/project",
  "language": "java",
  "status": "completed",
  "started_at": "2024-01-15T10:30:00",
  "completed_at": "2024-01-15T10:30:03",
  "total_findings": 42,
  "duration_seconds": 3.45,
  "stats": { "..." }
}
```

### WebSocket 扫描进度

```
ws://host:port/ws/scan/{scan_id}
```

**服务器推送消息**：
```json
{"type": "status", "status": "running"}
{"type": "progress", "progress": 30, "phase": "scan_complete"}
{"type": "progress", "progress": 60}
{"type": "completed", "progress": 100, "stats": {"..."}}
{"type": "error", "error": "Scanner failed: ..."}
```

**客户端心跳**：
```
发送: "ping"
接收: {"type": "pong"}
```

## 配置选项

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `XUANJIAN_HOST` | Web 服务器监听地址 | `0.0.0.0` |
| `XUANJIAN_PORT` | Web 服务器端口 | `8080` |
| `XUANJIAN_DB_PATH` | SQLite 数据库路径 | `~/.xuanjian/data.db` |

### 配置文件

在 `xuanjian.yaml` 中配置：

```yaml
database:
  path: ~/.xuanjian/data.db
  wal_mode: true

output:
  format: table    # table / json
  verbose: false
```

### CLI 参数

```bash
fp-sentinel web \
  --host 0.0.0.0 \
  --port 8080 \
  --config /path/to/xuanjian.yaml
```
