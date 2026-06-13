# 部署指南

本文档提供玄鉴 (XuanJian AI) 的多种部署方式。

## 系统要求

| 项目 | 最低要求 | 推荐配置 |
|------|---------|---------|
| CPU | 2 核 | 4 核 |
| 内存 | 2 GB | 4 GB |
| 磁盘 | 1 GB | 5 GB |
| Python | 3.10+ | 3.12+ |
| OS | Linux / macOS / Windows (WSL) | Linux |

### 外部依赖（可选）

| 工具 | 用途 | 安装方式 |
|------|------|---------|
| Semgrep | 多语言静态扫描 | `pip install semgrep` |
| Bandit | Python 安全扫描 | `pip install bandit` |
| SpotBugs + FindSecBugs | Java 安全扫描 | 需要 JDK + SpotBugs |

## 裸机部署

### 1. 克隆代码

```bash
git clone https://github.com/hujiaozhuzhu/xuanjian-ai.git
cd xuanjian-ai
```

### 2. 创建虚拟环境

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. 安装依赖

```bash
# 基础安装
pip install -e .

# 完整安装（含扫描器、ML、Web、开发依赖）
pip install -e ".[all]"

# 仅安装 Web 依赖
pip install -e ".[web]"

# 仅安装扫描器依赖
pip install -e ".[scanners]"
```

### 4. 配置

```bash
# 创建配置目录
mkdir -p ~/.xuanjian

# 创建配置文件（可选，有合理默认值）
cat > xuanjian.yaml << 'EOF'
project:
  name: my-project
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
EOF
```

### 5. 验证安装

```bash
# 检查版本
fp-sentinel version

# 运行测试
pytest -q
```

### 6. 启动服务

```bash
# MCP Server（stdio 模式）
fp-sentinel mcp --transport stdio

# MCP Server（SSE 模式）
fp-sentinel mcp --transport sse --port 8000

# Web 仪表板
fp-sentinel web --host 0.0.0.0 --port 8080

# CLI 扫描
fp-sentinel scan /path/to/project --lang java
```

## Docker 部署

### Dockerfile

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# 复制项目文件
COPY pyproject.toml .
COPY fp_sentinel/ fp_sentinel/
COPY tests/ tests/

# 安装 Python 依赖
RUN pip install --no-cache-dir -e ".[all]" 2>/dev/null || \
    pip install --no-cache-dir .

# 创建数据目录
RUN mkdir -p /data /root/.xuanjian

# 暴露端口
EXPOSE 8080 8000

# 默认启动 Web 仪表板
CMD ["fp-sentinel", "web", "--host", "0.0.0.0", "--port", "8080"]
```

### 构建镜像

```bash
docker build -t xuanjian-ai .
```

### 运行容器

```bash
# Web 仪表板模式
docker run -d \
  --name xuanjian \
  -p 8080:8080 \
  -v xuanjian-data:/data \
  -e XUANJIAN_DB_PATH=/data/data.db \
  xuanjian-ai

# MCP SSE 模式
docker run -d \
  --name xuanjian-mcp \
  -p 8000:8000 \
  -v xuanjian-data:/data \
  -v /path/to/projects:/projects:ro \
  xuanjian-ai \
  fp-sentinel mcp --transport sse --port 8000

# 扫描项目（一次性）
docker run --rm \
  -v /path/to/project:/project:ro \
  -v xuanjian-data:/data \
  xuanjian-ai \
  fp-sentinel scan /project --lang java --format json
```

### Docker Compose

```yaml
version: '3.8'

services:
  xuanjian-web:
    build: .
    command: fp-sentinel web --host 0.0.0.0 --port 8080
    ports:
      - "8080:8080"
    volumes:
      - xuanjian-data:/data
      - /path/to/projects:/projects:ro
    environment:
      - XUANJIAN_DB_PATH=/data/data.db
    restart: unless-stopped

  xuanjian-mcp:
    build: .
    command: fp-sentinel mcp --transport sse --port 8000
    ports:
      - "8000:8000"
    volumes:
      - xuanjian-data:/data
      - /path/to/projects:/projects:ro
    environment:
      - XUANJIAN_DB_PATH=/data/data.db
    restart: unless-stopped

volumes:
  xuanjian-data:
```

## 配置文件说明

### 配置文件查找顺序

1. 命令行参数 `--config` 指定的路径
2. 当前目录 `xuanjian.yaml` 或 `xuanjian.yml`
3. `~/.xuanjian/config.yaml` 或 `~/.xuanjian/config.yml`
4. 内置默认配置

### 完整配置示例

```yaml
# xuanjian.yaml

project:
  name: my-project          # 项目名称
  path: .                    # 项目路径
  language: auto             # 语言: auto/java/python/go

scanners:
  semgrep:
    enabled: true            # 是否启用
    timeout: 300             # 超时(秒)
    jobs: 2                  # 并行度
    ignore_paths: []         # 忽略路径
  bandit:
    enabled: true
    timeout: 300
    ignore_paths: []
  findsecbugs:
    enabled: true
    spotbugs_path: spotbugs  # SpotBugs 可执行文件
    findsecbugs_jar: ""      # FindSecBugs JAR 路径
    timeout: 600
    effort: max              # 分析力度: min/default/max

filters:
  rule_filter:
    enabled: true
    path_whitelist:          # 路径白名单
      - ".*/test/.*"
      - ".*/generated/.*"
    code_ignore_patterns:    # 代码忽略模式
      - "#\\s*nosec"
      - "//\\s*NOSONAR"
    custom_rules: []         # 自定义规则
  context_filter:
    enabled: true
    false_positive_threshold: 0.5
  ml_filter:
    enabled: true
    confidence_threshold: 0.7
    baseline_path: ".fp_sentinel/baseline.json"
    similarity_threshold: 0.85

database:
  path: ~/.xuanjian/data.db  # SQLite 路径
  wal_mode: true             # WAL 模式

output:
  format: table              # 输出格式: table/json
  verbose: false             # 详细输出
```

## 环境变量说明

所有环境变量以 `XUANJIAN_` 为前缀，优先级高于配置文件。

| 环境变量 | 对应配置路径 | 说明 | 示例 |
|----------|-------------|------|------|
| `XUANJIAN_DB_PATH` | `database.path` | SQLite 数据库路径 | `~/.xuanjian/data.db` |
| `XUANJIAN_DB_WAL` | `database.wal_mode` | 启用 WAL 模式 | `true` / `false` |
| `XUANJIAN_PROJECT_PATH` | `project.path` | 项目路径 | `/app` |
| `XUANJIAN_PROJECT_LANGUAGE` | `project.language` | 项目语言 | `java` |
| `XUANJIAN_SEMGREP_ENABLED` | `scanners.semgrep.enabled` | 启用 Semgrep | `true` / `false` |
| `XUANJIAN_SEMGREP_TIMEOUT` | `scanners.semgrep.timeout` | Semgrep 超时 | `300` |
| `XUANJIAN_BANDIT_ENABLED` | `scanners.bandit.enabled` | 启用 Bandit | `true` / `false` |
| `XUANJIAN_FINDSECBUGS_ENABLED` | `scanners.findsecbugs.enabled` | 启用 FindSecBugs | `true` / `false` |
| `XUANJIAN_FINDSECBUGS_JAR` | `scanners.findsecbugs.findsecbugs_jar` | FindSecBugs JAR | `/opt/findsecbugs.jar` |
| `CONFIG_PATH` | — | 配置文件路径 | `/app/xuanjian.yaml` |

**优先级**：默认值 < 配置文件 < 环境变量 < 命令行参数

## 常见问题排查

### 1. Semgrep 未找到

```
错误: semgrep: command not found
```

**解决**：
```bash
pip install semgrep
# 或
pip install -e ".[scanners]"
```

### 2. FindSecBugs/SpotBugs 未找到

```
错误: spotbugs: command not found
```

**解决**：
```bash
# 安装 SpotBugs (需要 JDK)
# macOS
brew install spotbugs

# Linux - 下载二进制包
wget https://github.com/spotbugs/spotbugs/releases/download/4.8.3/spotbugs-4.8.3.tgz
tar xzf spotbugs-4.8.3.tgz
export PATH=$PATH:$(pwd)/spotbugs-4.8.3/bin

# 配置 FindSecBugs 插件
# 下载 find-sec-bugs-plugin.jar 放入 SpotBugs plugin 目录
```

### 3. 数据库锁定

```
错误: database is locked
```

**解决**：
```bash
# 确保没有其他进程使用数据库
lsof ~/.xuanjian/data.db

# 如果持续出现，关闭 WAL 模式（不推荐）
export XUANJIAN_DB_WAL=false
```

### 4. 内存不足

```
错误: MemoryError
```

**解决**：
```bash
# 减少 Semgrep 并行度
export XUANJIAN_SEMGREP_TIMEOUT=600
# 在配置中设置 jobs: 1
```

### 5. 权限问题

```
错误: Permission denied
```

**解决**：
```bash
# 确保数据目录可写
chmod 755 ~/.xuanjian
# 确保扫描目标可读
chmod -R o+r /path/to/project
```

### 6. Python 版本不兼容

```
错误: Python version 3.x is not supported
```

**解决**：
```bash
# 检查 Python 版本
python3 --version

# 需要 3.10+
# 推荐使用 pyenv 安装
pyenv install 3.12.0
pyenv local 3.12.0
```

### 7. Web 仪表板无法访问

```bash
# 检查端口是否被占用
lsof -i :8080

# 检查防火墙
sudo ufw allow 8080

# 检查 FastAPI 依赖
pip install fastapi uvicorn
```

### 8. MCP 客户端连接失败

```bash
# 测试 MCP Server
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{},"clientInfo":{"name":"test"},"protocolVersion":"2024-11-05"}}' | fp-sentinel mcp --transport stdio

# 检查日志
LOG_LEVEL=DEBUG fp-sentinel mcp --transport stdio
```
