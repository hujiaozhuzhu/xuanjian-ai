# Claude API 配置指南

本文档说明如何配置和使用 Claude API 客户端。

## 配置方法

### 方法 1: 使用 .env 文件（推荐）

在项目根目录创建 `.env` 文件，添加以下配置：

```bash
# Claude API 配置
CLAUDE_API_KEY=your_api_key_here
CLAUDE_API_URL=https://token-plan-cn.xiaomimimo.com/v1
CLAUDE_API_URL_ANTHROPIC=https://token-plan-cn.xiaomimimo.com/anthropic
CLAUDE_MODEL=mimo-v2.5-pro

# 客户端类型：anthropic 或 openai
LLM_CLIENT_TYPE=anthropic

# 其他配置
XUANJIAN_API_KEY=your_xuanjian_api_key_here
```

### 方法 2: 使用配置文件

在 `config.json` 或 `xuanjian.yaml` 中添加 LLM 配置：

```json
{
  "llm": {
    "client_type": "anthropic",
    "model": "mimo-v2.5-pro",
    "timeout": 30.0
  }
}
```

### 方法 3: 使用环境变量

直接设置环境变量：

```bash
export CLAUDE_API_KEY=your_api_key_here
export CLAUDE_API_URL=https://token-plan-cn.xiaomimimo.com/v1
export CLAUDE_API_URL_ANTHROPIC=https://token-plan-cn.xiaomimimo.com/anthropic
export CLAUDE_MODEL=mimo-v2.5-pro
export LLM_CLIENT_TYPE=anthropic
```

## 支持的客户端类型

### 1. Anthropic 客户端（默认）

使用 Anthropic 兼容接口，支持 Claude 原生 API。

- **环境变量**: `LLM_CLIENT_TYPE=anthropic`
- **URL**: `https://token-plan-cn.xiaomimimo.com/anthropic`
- **认证方式**: `x-api-key` 头部

### 2. OpenAI 兼容客户端

使用 OpenAI 兼容接口，支持大多数 LLM 服务提供商。

- **环境变量**: `LLM_CLIENT_TYPE=openai`
- **URL**: `https://token-plan-cn.xiaomimimo.com/v1`
- **认证方式**: `Authorization: Bearer` 头部

## 使用示例

### 示例 1: 直接使用 Claude 客户端

```python
import asyncio
from fp_sentinel.llm_client import ClaudeClient

async def main():
    # 从环境变量加载配置
    client = ClaudeClient()
    
    messages = [
        {"role": "user", "content": "请解释什么是 SQL 注入？"}
    ]
    
    response = await client.chat(messages)
    print(response)

asyncio.run(main())
```

### 示例 2: 使用 OpenAI 兼容接口

```python
import asyncio
from fp_sentinel.llm_client import OpenAICompatibleClient

async def main():
    # 创建 OpenAI 兼容客户端
    client = OpenAICompatibleClient()
    
    messages = [
        {"role": "user", "content": "请列举 3 个常见的 Web 安全漏洞。"}
    ]
    
    response = await client.chat(messages)
    print(response)

asyncio.run(main())
```

### 示例 3: 使用工厂函数

```python
import asyncio
from fp_sentinel.llm_client import create_llm_client

async def main():
    # 创建 Anthropic 客户端
    client = create_llm_client(client_type="anthropic")
    
    messages = [
        {"role": "user", "content": "什么是 XSS 攻击？"}
    ]
    
    response = await client.chat(messages)
    print(response)

asyncio.run(main())
```

### 示例 4: 从配置文件加载

```python
import asyncio
from fp_sentinel.config import load_config, get_llm_client

async def main():
    # 加载配置
    config = load_config()
    
    # 获取 LLM 客户端
    client = get_llm_client(config)
    
    if client:
        messages = [
            {"role": "user", "content": "请解释 CSRF 攻击的原理。"}
        ]
        
        response = await client.chat(messages)
        print(response)

asyncio.run(main())
```

## 在项目中使用

### 1. L4 智能降噪

在噪声过滤流水线中使用 LLM 客户端：

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

使用 LLM 生成绕过用例：

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

print(f"生成了 {len(result.cases)} 个绕过用例")
```

### 3. 在服务器中使用

服务器会自动加载 LLM 客户端：

```python
from fp_sentinel.server import create_server

# 创建服务器（自动加载 LLM 客户端）
server = create_server()

# 检查 LLM 客户端是否可用
if server.llm_client:
    print("LLM 客户端已加载")
else:
    print("LLM 客户端未加载")
```

## 运行示例

```bash
# 运行 Claude 客户端示例
python examples/claude_example.py
```

## 故障排除

### 1. API 密钥错误

错误信息：`Claude API key is required`

解决方案：
- 检查 `.env` 文件中的 `CLAUDE_API_KEY` 配置
- 确保 API 密钥有效

### 2. 网络连接错误

错误信息：`Claude API call failed`

解决方案：
- 检查网络连接
- 确认 API URL 正确
- 检查防火墙设置

### 3. 模型不存在

错误信息：`model not found`

解决方案：
- 检查 `CLAUDE_MODEL` 配置
- 确认模型名称正确

### 4. 配置加载失败

错误信息：`Failed to load LLM client`

解决方案：
- 检查配置文件格式
- 确认环境变量设置正确

## 配置参数说明

| 参数 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| API 密钥 | `CLAUDE_API_KEY` | - | Claude API 密钥 |
| API URL | `CLAUDE_API_URL` | `https://token-plan-cn.xiaomimimo.com/v1` | OpenAI 兼容接口 URL |
| Anthropic URL | `CLAUDE_API_URL_ANTHROPIC` | `https://token-plan-cn.xiaomimimo.com/anthropic` | Anthropic 兼容接口 URL |
| 模型名称 | `CLAUDE_MODEL` | `mimo-v2.5-pro` | 使用的模型名称 |
| 客户端类型 | `LLM_CLIENT_TYPE` | `anthropic` | 客户端类型（anthropic/openai） |
| 超时时间 | - | `30.0` | 请求超时时间（秒） |

## 安全注意事项

1. **不要提交 API 密钥到版本控制系统**
   - 将 `.env` 文件添加到 `.gitignore`
   - 使用环境变量或密钥管理服务

2. **限制 API 访问权限**
   - 使用最小权限原则
   - 定期轮换 API 密钥

3. **监控 API 使用情况**
   - 记录 API 调用日志
   - 设置使用量警报

4. **保护敏感数据**
   - 不要在提示词中包含敏感信息
   - 使用数据脱敏技术