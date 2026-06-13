# MCP 集成指南

本文档详细说明玄鉴 fp-sentinel 的 MCP (Model Context Protocol) 集成方式。

## MCP 协议简介

[Model Context Protocol (MCP)](https://modelcontextprotocol.io) 是一个开放协议，用于标准化 AI 应用与外部工具/数据源之间的通信。MCP 允许 AI 助手（如 Claude）直接调用外部工具，获取结构化数据。

玄鉴通过 MCP 协议暴露 8 个工具，让 AI 客户端能够：
- 直接扫描代码项目
- 自动过滤误报
- 获取结构化的安全分析结果
- 标记和管理误报

## 传输方式

### stdio（推荐）

标准输入/输出模式，适用于本地 AI 客户端集成。客户端启动 MCP Server 进程，通过 stdin/stdout 通信。

```bash
fp-sentinel mcp --transport stdio
```

### SSE (Server-Sent Events)

HTTP 模式，适用于远程服务或 Web 集成。

```bash
fp-sentinel mcp --transport sse --host 0.0.0.0 --port 8000
```

## 8 个 MCP 工具详细说明

### 1. scan_project

扫描项目，发现安全问题。

**输入 Schema**：

```json
{
  "project_path": "/path/to/project",   // 必填，项目路径
  "language": "auto",                    // 可选，auto/java/python/go
  "scanners": ["semgrep", "findsecbugs"] // 可选，指定扫描器
}
```

**输出示例**：

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
    "processing_time_ms": 1234.5,
    "filter_level_stats": {"L1": 15, "L2": 8, "L3": 0}
  },
  "duration_seconds": 3.45
}
```

### 2. triage_findings

对扫描结果进行分诊，应用三层过滤器识别误报。

**输入 Schema**：

```json
{
  "scan_id": "a1b2c3d4-...",       // 必填，扫描 ID
  "use_rule_filter": true,          // 可选，启用 L1
  "use_context_filter": true,       // 可选，启用 L2
  "use_baseline": true              // 可选，启用 L3
}
```

**输出示例**：

```json
{
  "scan_id": "a1b2c3d4-...",
  "filter_level": "all",
  "results": [
    {
      "id": "a1b2c3d4-...:0",
      "verdict": "false_positive",
      "confidence": 0.85,
      "risk_score": 1.35,
      "recommendation": "高置信度误报，建议忽略",
      "filter_reasons": [
        {
          "filter_level": "L1",
          "rule_name": "java_sql_prepared_statement",
          "description": "使用PreparedStatement或ORM参数化查询",
          "confidence": 0.85
        }
      ]
    }
  ],
  "statistics": { "..." }
}
```

### 3. explain_finding

解释单条发现，提供详细分析和处理建议。

**输入 Schema**：

```json
{
  "finding_id": "a1b2c3d4-...:0"   // 必填，发现 ID
}
```

**输出示例**：

```json
{
  "finding_id": "a1b2c3d4-...:0",
  "rule_id": "java.lang.security.audit.sql-injection",
  "severity": "HIGH",
  "file": "src/main/java/com/example/UserDao.java",
  "line": 42,
  "code": "jdbcTemplate.query(sql, args)",
  "message": "Potential SQL injection",
  "cwe": "CWE-89",
  "verdict": "false_positive",
  "confidence": 0.85,
  "risk_score": 1.35,
  "recommendation": "高置信度误报，建议忽略",
  "filter_reasons": ["..."],
  "context_analysis": {
    "is_dead_code": false,
    "has_security_guards": true,
    "has_input_validation": true,
    "is_in_test": false,
    "context_features": {
      "guard_keywords": ["PreparedStatement", "setParameter"],
      "validation_keywords": ["@Valid", "@NotNull"]
    }
  },
  "java_analysis": {
    "uses_prepared_statement": true,
    "uses_orm": false,
    "uses_mybatis_hash": false,
    "framework_hints": ["spring", "jpa"],
    "confidence_adjustment": 0.3
  },
  "explanation": "此发现被判定为误报..."
}
```

### 4. mark_false_positive

将发现标记为误报，写入基线。

**输入 Schema**：

```json
{
  "finding_id": "a1b2c3d4-...:0",   // 必填，发现 ID
  "reason": "使用PreparedStatement",  // 必填，标记原因
  "scope": "instance"                // 可选，instance/rule/global
}
```

**输出示例**：

```json
{
  "status": "ok",
  "finding_id": "a1b2c3d4-...:0",
  "fingerprint": "e4d7f1b4e...",
  "scope": "instance",
  "reason": "使用PreparedStatement"
}
```

### 5. list_findings

列出扫描发现。

**输入 Schema**：

```json
{
  "scan_id": "a1b2c3d4-...",        // 必填，扫描 ID
  "verdict": "false_positive",       // 可选，按判定过滤
  "severity": "HIGH"                 // 可选，按严重程度过滤
}
```

**输出示例**：

```json
{
  "scan_id": "a1b2c3d4-...",
  "total": 42,
  "findings": [
    {
      "id": "...",
      "original": { "..." },
      "verdict": "false_positive",
      "confidence": 0.85,
      "risk_score": 1.35,
      "recommendation": "..."
    }
  ]
}
```

### 6. export_report

导出扫描报告。

**输入 Schema**：

```json
{
  "scan_id": "a1b2c3d4-...",   // 必填，扫描 ID
  "format": "json"             // 可选，json/markdown
}
```

**输出**：JSON 格式或 Markdown 格式的报告内容字符串。

### 7. get_statistics

获取项目统计信息。

**输入 Schema**：

```json
{
  "project_path": "/path/to/project"  // 可选，项目路径
}
```

**输出示例**：

```json
{
  "project_path": "/path/to/project",
  "total_findings": 150,
  "false_positives": 60,
  "likely_false_positives": 25,
  "true_positives": 45,
  "needs_review": 20,
  "reduction_rate": "56.7%",
  "baseline_size": 120,
  "scans_completed": 5
}
```

### 8. list_projects

列出已扫描的项目。

**输入 Schema**：无参数

**输出示例**：

```json
[
  {
    "name": "my-spring-app",
    "path": "/home/user/projects/my-spring-app",
    "language": "java",
    "scan_count": 3,
    "last_scan": "2024-01-15T10:30:00",
    "total_findings": 42
  }
]
```

## 客户端配置方法

### Claude Desktop

编辑 `~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）或 `%APPDATA%\Claude\claude_desktop_config.json`（Windows）：

```json
{
  "mcpServers": {
    "fp-sentinel": {
      "command": "fp-sentinel",
      "args": ["mcp", "--transport", "stdio"],
      "env": {
        "XUANJIAN_DB_PATH": "~/.xuanjian/data.db"
      }
    }
  }
}
```

如果使用虚拟环境：

```json
{
  "mcpServers": {
    "fp-sentinel": {
      "command": "/path/to/xuanjian-ai/.venv/bin/fp-sentinel",
      "args": ["mcp", "--transport", "stdio"]
    }
  }
}
```

### Cursor

在 Cursor 设置中，找到 MCP Servers 配置，添加：

```json
{
  "fp-sentinel": {
    "command": "fp-sentinel",
    "args": ["mcp", "--transport", "stdio"]
  }
}
```

或在 `.cursor/mcp.json` 中配置：

```json
{
  "mcpServers": {
    "fp-sentinel": {
      "command": "fp-sentinel",
      "args": ["mcp", "--transport", "stdio"],
      "env": {
        "XUANJIAN_PROJECT_LANGUAGE": "java"
      }
    }
  }
}
```

### 其他 MCP 客户端

任何支持 MCP 协议的客户端都可以使用。通用配置格式：

```json
{
  "servers": {
    "fp-sentinel": {
      "transport": "stdio",
      "command": "fp-sentinel",
      "args": ["mcp", "--transport", "stdio"]
    }
  }
}
```

## 调用示例

### 在 Claude 中使用

配置完成后，在 Claude Desktop 中可以直接对话：

```
用户：帮我扫描 /home/user/my-java-project 项目的安全问题

Claude（调用 fp-sentinel）：
  → scan_project(project_path="/home/user/my-java-project", language="java")
  → 返回 scan_id 和统计信息

Claude：扫描完成，共发现 42 个安全问题，其中 23 个被识别为误报。
  我来详细查看高危发现...

  → list_findings(scan_id="...", severity="HIGH")
  → explain_finding(finding_id="...")

Claude：以下是 HIGH 级别的发现详情...
```

### Python SDK 调用

```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

server_params = StdioServerParameters(
    command="fp-sentinel",
    args=["mcp", "--transport", "stdio"],
)

async with stdio_client(server_params) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()

        # 扫描项目
        result = await session.call_tool(
            "scan_project",
            arguments={
                "project_path": "/path/to/project",
                "language": "java",
            }
        )
        print(result)

        # 列出发现
        findings = await session.call_tool(
            "list_findings",
            arguments={"scan_id": "...", "severity": "HIGH"}
        )
        print(findings)
```

### SSE 模式调用

```python
from mcp import ClientSession
from mcp.client.sse import sse_client

async with sse_client("http://localhost:8000/sse") as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()

        result = await session.call_tool(
            "scan_project",
            arguments={"project_path": "/path/to/project"}
        )
```


## SSE 模式客户端接入

SSE 模式适用于远程服务器部署，多个客户端可共享同一个 MCP 服务。

### 1. 启动 SSE 服务



启动后 SSE 端点为：

### 2. Claude Desktop 配置

编辑配置文件：
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`



### 3. Claude Code 配置

在项目根目录创建 `.mcp.json`：



或全局配置 `~/.claude/mcp.json`。

### 4. Cursor 配置

在 Cursor Settings → MCP Servers 中添加，或编辑 `.cursor/mcp.json`：



### 5. Cline (VS Code) 配置

在 VS Code 设置中找到 Cline MCP Settings，添加：



### 6. Windsurf 配置

编辑 `~/.codeium/windsurf/mcp_config.json`：



### 7. 通用 MCP 客户端 (Python)



### 常见问题

**Q: 连接超时？**
- 检查防火墙是否开放端口：`sudo ufw allow 8000`
- 确认服务绑定 `0.0.0.0` 而非 `127.0.0.1`

**Q: 多客户端同时连接？**
- SSE 模式支持多客户端并发，无需额外配置

**Q: 如何加密传输？**
- 建议使用 Nginx 反向代理 + HTTPS
- 或通过 SSH 隧道：`ssh -L 8000:localhost:8000 user@server`
