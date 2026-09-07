# Claude API 配置状态

## 配置完成情况

### 1. 环境变量配置 ✅

已在 `.env` 文件中配置以下环境变量：

```bash
# Claude API 配置
CLAUDE_API_KEY=<REDACTED-见 .env 中的 CLAUDE_API_KEY>
CLAUDE_API_URL=https://token-plan-cn.xiaomimimo.com/v1
CLAUDE_API_URL_ANTHROPIC=https://token-plan-cn.xiaomimimo.com/anthropic
CLAUDE_MODEL=mimo-v2.5-pro
LLM_CLIENT_TYPE=anthropic

# 其他配置
XUANJIAN_API_KEY=<REDACTED-见 .env 中的 XUANJIAN_API_KEY>
```

### 2. 配置文件更新 ✅

已更新以下配置文件：

1. **config.json** - 添加 LLM 配置部分
2. **fp_sentinel/config.py** - 添加 LLM 配置支持
3. **fp_sentinel/llm_client.py** - 创建 Claude 客户端模块
4. **requirements.txt** - 添加 httpx 依赖
5. **pyproject.toml** - 添加 httpx 依赖

### 3. 代码集成 ✅

已完成以下代码集成：

1. **ClaudeClient** - Anthropic 兼容客户端
2. **OpenAICompatibleClient** - OpenAI 兼容客户端
3. **create_llm_client** - 工厂函数
4. **get_llm_client** - 配置加载函数
5. **FPServer** - 服务器集成 LLM 客户端

### 4. 测试验证 ✅

配置测试结果：

```
[OK] CLAUDE_API_KEY: <REDACTED>
[OK] CLAUDE_API_URL: https://token-plan-cn.xiaomimimo.com/v1
[OK] CLAUDE_API_URL_ANTHROPIC: https://token-plan-cn.xiaomimimo.com/anthropic
[OK] CLAUDE_MODEL: mimo-v2.5-pro
[OK] LLM_CLIENT_TYPE: anthropic
[OK] 配置加载成功
[OK] LLM 客户端创建成功: ClaudeClient
[OK] Claude 客户端创建成功
[OK] OpenAI 兼容客户端创建成功
[OK] 工厂函数创建 Anthropic 客户端成功
```

## 使用方法

### 方法 1: 直接使用 Claude 客户端

```python
from fp_sentinel.llm_client import ClaudeClient

# 创建客户端
client = ClaudeClient()

# 发送请求
response = await client.chat([
    {"role": "user", "content": "请解释什么是 SQL 注入？"}
])
```

### 方法 2: 使用 OpenAI 兼容接口

```python
from fp_sentinel.llm_client import OpenAICompatibleClient

# 创建客户端
client = OpenAICompatibleClient()

# 发送请求
response = await client.chat([
    {"role": "user", "content": "请列举 3 个常见的 Web 安全漏洞。"}
])
```

### 方法 3: 使用工厂函数

```python
from fp_sentinel.llm_client import create_llm_client

# 创建 Anthropic 客户端
client = create_llm_client(client_type="anthropic")

# 创建 OpenAI 客户端
client = create_llm_client(client_type="openai")
```

### 方法 4: 从配置文件加载

```python
from fp_sentinel.config import load_config, get_llm_client

# 加载配置
config = load_config()

# 获取 LLM 客户端
client = get_llm_client(config)
```

## 项目集成

### 1. L4 智能降噪

```python
from fp_sentinel.filters.noise_reducer import NoisePipeline
from fp_sentinel.llm_client import ClaudeClient

# 创建 LLM 客户端
llm_client = ClaudeClient()

# 创建降噪流水线
pipeline = NoisePipeline(
    enable_l1=True,
    enable_l2=True,
    enable_l3=True,
    enable_l4=True,
    llm_client=llm_client,
)

# 处理发现
filtered_findings = await pipeline.process(findings)
```

### 2. 红队攻击用例生成

```python
from fp_sentinel.redteam.generator import RedTeamGenerator
from fp_sentinel.llm_client import ClaudeClient

# 创建 LLM 客户端
llm_client = ClaudeClient()

# 创建红队生成器
generator = RedTeamGenerator(llm_client=llm_client)

# 生成绕过用例
result = await generator.generate_bypasses(
    rule_id="python.lang.security.injection.sql-injection",
    description="SQL 注入漏洞",
    pattern=r"execute\s*\(\s*['\"].*%s",
    category="INJECTION",
    severity="HIGH",
    language="python",
    count=10,
)
```

### 3. 服务器自动加载

服务器会自动加载 LLM 客户端：

```python
from fp_sentinel.server import create_server

# 创建服务器（自动加载 LLM 客户端）
server = create_server()

# 检查 LLM 客户端是否可用
if server.llm_client:
    print("LLM 客户端已加载")
```

## 测试脚本

### 配置测试

```bash
python test_config.py
```

### 客户端测试

```bash
python test_claude_client.py
```

### 示例脚本

```bash
python examples/claude_example.py
```

## 文档

- [Claude 配置指南](docs/claude-config.md)
- [README.md](README.md) - 包含 Claude 配置说明

## 注意事项

1. **API 密钥安全**: 不要将 API 密钥提交到版本控制系统
2. **网络代理**: 如果需要代理，请设置 `HTTP_PROXY` 或 `HTTPS_PROXY` 环境变量
3. **模型可用性**: 确保 `mimo-v2.5-pro` 模型在您的账户中可用
4. **API 限制**: 注意 API 调用频率限制

## 故障排除

### 1. 网络连接错误

错误信息：`httpx.ConnectError`

解决方案：
- 检查网络连接
- 配置代理（如果需要）
- 检查防火墙设置

### 2. API 密钥错误

错误信息：`Claude API key is required`

解决方案：
- 检查 `.env` 文件中的 `CLAUDE_API_KEY` 配置
- 确保 API 密钥有效

### 3. 模型不存在

错误信息：`model not found`

解决方案：
- 检查 `CLAUDE_MODEL` 配置
- 确认模型名称正确

## 配置参数说明

| 参数 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| API 密钥 | `CLAUDE_API_KEY` | - | Claude API 密钥 |
| API URL | `CLAUDE_API_URL` | `https://token-plan-cn.xiaomimimo.com/v1` | OpenAI 兼容接口 URL |
| Anthropic URL | `CLAUDE_API_URL_ANTHROPIC` | `https://token-plan-cn.xiaomimimo.com/anthropic` | Anthropic 兼容接口 URL |
| 模型名称 | `CLAUDE_MODEL` | `mimo-v2.5-pro` | 使用的模型名称 |
| 客户端类型 | `LLM_CLIENT_TYPE` | `anthropic` | 客户端类型（anthropic/openai） |
| 超时时间 | - | `30.0` | 请求超时时间（秒） |

## 下一步

1. 测试 API 调用是否正常工作
2. 集成到现有的代码审计流程中
3. 配置 L4 智能降噪
4. 配置红队攻击用例生成

---

**配置状态**: ✅ 完成  
**最后更新**: 2026-09-04  
**配置版本**: v2.2.3