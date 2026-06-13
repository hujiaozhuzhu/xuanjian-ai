# REST API 参考文档

本文档描述玄鉴 Web 仪表板提供的所有 REST API 端点。

**Base URL**: `http://localhost:8080`

**Content-Type**: `application/json`（除特殊说明外）

---

## 端点列表

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/` | Web 仪表板首页 |
| `GET` | `/api/projects` | 获取项目列表 |
| `POST` | `/api/scan` | 启动扫描 |
| `GET` | `/api/findings` | 获取发现列表 |
| `GET` | `/api/findings/{finding_id}` | 获取发现详情 |
| `POST` | `/api/findings/{finding_id}/mark-fp` | 标记误报 |
| `GET` | `/api/stats` | 获取统计信息 |
| `GET` | `/api/scans/{scan_id}` | 获取扫描状态 |
| `WS` | `/ws/scan/{scan_id}` | WebSocket 扫描进度 |

---

## GET /

返回 Web 仪表板 HTML 页面。

**响应**: `text/html`

---

## GET /api/projects

获取已扫描的项目列表。

**请求参数**: 无

**响应示例**:

```json
[
  {
    "name": "my-spring-app",
    "path": "/home/user/projects/my-spring-app",
    "language": "java",
    "scan_count": 3,
    "last_scan": "2024-01-15T10:30:00"
  },
  {
    "name": "my-python-app",
    "path": "/home/user/projects/my-python-app",
    "language": "python",
    "scan_count": 1,
    "last_scan": "2024-01-14T08:00:00"
  }
]
```

**响应字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | 项目名称（目录名） |
| `path` | string | 项目路径 |
| `language` | string | 主要语言 |
| `scan_count` | int | 扫描次数 |
| `last_scan` | string\|null | 最后扫描时间 (ISO 8601) |

---

## POST /api/scan

启动项目扫描。扫描过程会自动执行三层过滤。

**请求体**:

```json
{
  "project_path": "/path/to/project",
  "language": "auto",
  "scanners": ["semgrep", "findsecbugs"]
}
```

**请求字段**:

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `project_path` | string | ✅ | — | 项目路径 |
| `language` | string | ❌ | `"auto"` | 编程语言: `auto`/`java`/`python`/`go` |
| `scanners` | string[] | ❌ | `null` | 指定扫描器: `semgrep`/`bandit`/`findsecbugs` |

**成功响应** (`200 OK`):

```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "total_findings": 42,
  "statistics": {
    "total": 42,
    "false_positives": 15,
    "likely_false_positives": 8,
    "true_positives": 12,
    "needs_review": 7,
    "reduction_rate": "54.8%",
    "processing_time_ms": 1234.5,
    "filter_level_stats": {
      "L1": 15,
      "L2": 8,
      "L3": 0
    }
  },
  "duration_seconds": 3.45
}
```

**错误响应** (`500 Internal Server Error`):

```json
{
  "detail": "Scanner failed: semgrep not found"
}
```

---

## GET /api/findings

获取发现列表，支持多条件过滤。

**查询参数**:

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `scan_id` | string | ❌ | 按扫描 ID 过滤 |
| `verdict` | string | ❌ | 按判定过滤 |
| `severity` | string | ❌ | 按严重程度过滤 |

**verdict 可选值**:
- `false_positive` — 误报
- `likely_false_positive` — 疑似误报
- `true_positive` — 真实问题
- `needs_review` — 待复核

**severity 可选值**:
- `CRITICAL` — 严重
- `HIGH` — 高危
- `MEDIUM` — 中危
- `LOW` — 低危
- `INFO` — 信息

**请求示例**:

```
GET /api/findings?scan_id=a1b2c3d4&severity=HIGH&verdict=needs_review
```

**响应示例**:

```json
[
  {
    "id": "a1b2c3d4-...:0",
    "original": {
      "id": null,
      "tool": "semgrep",
      "rule_id": "java.lang.security.audit.sql-injection",
      "file": "src/main/java/com/example/UserDao.java",
      "line": 42,
      "column": null,
      "end_line": null,
      "code": "jdbcTemplate.query(sql, args)",
      "severity": "HIGH",
      "message": "Potential SQL injection",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "metadata": {},
      "timestamp": null
    },
    "verdict": "false_positive",
    "confidence": 0.85,
    "filter_reasons": [
      {
        "filter_level": "L1",
        "rule_name": "java_sql_prepared_statement",
        "description": "使用PreparedStatement或ORM参数化查询",
        "confidence": 0.85
      }
    ],
    "risk_score": 1.35,
    "recommendation": "高置信度误报，建议忽略",
    "context_analysis": null,
    "java_analysis": null
  }
]
```

---

## GET /api/findings/{finding_id}

获取单条发现的详细信息。

**路径参数**:

| 参数 | 类型 | 说明 |
|------|------|------|
| `finding_id` | string | 发现 ID |

**成功响应** (`200 OK`):

返回与列表相同的单个 FilterResult 对象。

**错误响应** (`404 Not Found`):

```json
{
  "detail": "Finding not found"
}
```

---

## POST /api/findings/{finding_id}/mark-fp

将发现标记为误报，同时写入历史基线。

**路径参数**:

| 参数 | 类型 | 说明 |
|------|------|------|
| `finding_id` | string | 发现 ID |

**请求体**:

```json
{
  "reason": "使用PreparedStatement参数化查询",
  "scope": "instance"
}
```

**请求字段**:

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `reason` | string | ✅ | — | 标记原因 |
| `scope` | string | ❌ | `"instance"` | 作用域: `instance`/`rule`/`global` |

**scope 说明**:

| 值 | 说明 |
|-----|------|
| `instance` | 仅标记此条发现 |
| `rule` | 同规则的类似发现也视为误报 |
| `global` | 全局标记 |

**成功响应** (`200 OK`):

```json
{
  "status": "ok"
}
```

**错误响应** (`404 Not Found`):

```json
{
  "detail": "Finding not found"
}
```

---

## GET /api/stats

获取统计信息。

**查询参数**:

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `project_path` | string | ❌ | 按项目路径过滤（不传则返回全部） |

**响应示例**:

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

**响应字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| `total_findings` | int | 总发现数 |
| `false_positives` | int | 误报数 |
| `likely_false_positives` | int | 疑似误报数 |
| `true_positives` | int | 真实问题数 |
| `needs_review` | int | 待复核数 |
| `reduction_rate` | string | 误报减少率 |
| `baseline_size` | int | 基线指纹库大小 |

---

## GET /api/scans/{scan_id}

获取扫描状态和详情。

**路径参数**:

| 参数 | 类型 | 说明 |
|------|------|------|
| `scan_id` | string | 扫描 ID |

**成功响应** (`200 OK`):

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
  "progress": 100,
  "findings": ["finding-id-1", "finding-id-2", "..."],
  "stats": {
    "total": 42,
    "false_positives": 15,
    "likely_false_positives": 8,
    "true_positives": 12,
    "needs_review": 7,
    "reduction_rate": "54.8%",
    "processing_time_ms": 1234.5,
    "filter_level_stats": {"L1": 15, "L2": 8, "L3": 0}
  }
}
```

**status 可选值**:
- `running` — 扫描进行中
- `completed` — 扫描完成
- `failed` — 扫描失败

**错误响应** (`404 Not Found`):

```json
{
  "detail": "Scan not found"
}
```

---

## WebSocket /ws/scan/{scan_id}

实时获取扫描进度。

**连接**: `ws://localhost:8080/ws/scan/{scan_id}`

### 服务器推送消息

#### 状态消息

```json
{
  "type": "status",
  "status": "running"
}
```

#### 进度消息

```json
{
  "type": "progress",
  "progress": 30,
  "phase": "scan_complete"
}
```

`progress` 范围: 0-100

`phase` 可选值:
- `scan_complete` — 扫描完成，开始过滤
- 过滤进度（无特定 phase）

#### 完成消息

```json
{
  "type": "completed",
  "progress": 100,
  "stats": {
    "total": 42,
    "false_positives": 15,
    "likely_false_positives": 8,
    "true_positives": 12,
    "needs_review": 7,
    "reduction_rate": "54.8%",
    "processing_time_ms": 1234.5,
    "filter_level_stats": {"L1": 15, "L2": 8, "L3": 0}
  }
}
```

#### 错误消息

```json
{
  "type": "error",
  "error": "Scanner failed: ..."
}
```

### 客户端心跳

发送: `ping`
接收: `{"type": "pong"}`

### JavaScript 连接示例

```javascript
const scanId = "a1b2c3d4-...";
const ws = new WebSocket(`ws://localhost:8080/ws/scan/${scanId}`);

ws.onopen = () => {
  console.log("WebSocket connected");
  // 心跳
  setInterval(() => ws.send("ping"), 30000);
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  switch (data.type) {
    case "status":
      console.log("Status:", data.status);
      break;
    case "progress":
      console.log(`Progress: ${data.progress}%`);
      break;
    case "completed":
      console.log("Scan completed!", data.stats);
      ws.close();
      break;
    case "error":
      console.error("Error:", data.error);
      ws.close();
      break;
    case "pong":
      break;
  }
};

ws.onclose = () => console.log("WebSocket closed");
```

### Python 连接示例

```python
import asyncio
import websockets
import json

async def monitor_scan(scan_id: str):
    uri = f"ws://localhost:8080/ws/scan/{scan_id}"
    async with websockets.connect(uri) as ws:
        while True:
            msg = await ws.recv()
            data = json.loads(msg)
            if data["type"] == "completed":
                print(f"Done! Stats: {data['stats']}")
                break
            elif data["type"] == "error":
                print(f"Error: {data['error']}")
                break
            elif data["type"] == "progress":
                print(f"Progress: {data['progress']}%")

asyncio.run(monitor_scan("a1b2c3d4-..."))
```

---

## 错误码

| HTTP 状态码 | 说明 |
|-------------|------|
| `200` | 成功 |
| `404` | 资源不存在（Finding/Scan） |
| `422` | 请求参数验证失败 |
| `500` | 服务器内部错误 |

---

## 速率限制

当前版本未实现速率限制。建议在反向代理（如 Nginx）层面配置。

---

## OpenAPI 文档

FastAPI 自动生成交互式 API 文档：

- **Swagger UI**: `http://localhost:8080/docs`
- **ReDoc**: `http://localhost:8080/redoc`
