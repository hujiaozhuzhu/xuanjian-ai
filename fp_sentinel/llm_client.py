"""
LLM 客户端模块

支持 OpenAI 兼容接口和 Anthropic 接口
"""

import os
import logging
from typing import Optional, Dict, Any, List
import httpx

logger = logging.getLogger(__name__)


class ClaudeClient:
    """Claude API 客户端"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "mimo-v2.5-pro",
        timeout: float = 30.0,
    ):
        """
        初始化 Claude 客户端

        Args:
            api_key: API 密钥，优先使用参数，否则从环境变量读取
            base_url: API 基础 URL，默认使用 Anthropic 兼容接口
            model: 模型名称，默认 mimo-v2.5-pro
            timeout: 请求超时时间（秒）
        """
        self.api_key = api_key or os.environ.get("CLAUDE_API_KEY")
        if not self.api_key:
            raise ValueError("Claude API key is required. Set CLAUDE_API_KEY environment variable or pass api_key parameter.")

        self.base_url = base_url or os.environ.get("CLAUDE_API_URL_ANTHROPIC", "https://token-plan-cn.xiaomimimo.com/anthropic")
        self.model = model or os.environ.get("CLAUDE_MODEL", "mimo-v2.5-pro")
        self.timeout = timeout

        # 移除尾部斜杠
        self.base_url = self.base_url.rstrip("/")

        logger.info(f"Claude client initialized with model: {self.model}, base_url: {self.base_url}")

    async def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4000,
        system: Optional[str] = None,
    ) -> str:
        """
        发送聊天请求

        Args:
            messages: 消息列表，格式为 [{"role": "user", "content": "..."}]
            temperature: 温度参数
            max_tokens: 最大 token 数
            system: 系统提示词

        Returns:
            str: 模型响应内容
        """
        headers = {
            "x-api-key": self.api_key,
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
        }

        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
        }

        if system:
            payload["system"] = system

        url = f"{self.base_url}/messages"

        try:
            # 检查是否需要代理
            proxy = os.environ.get("HTTP_PROXY") or os.environ.get("HTTPS_PROXY")
            async with httpx.AsyncClient(timeout=self.timeout, proxy=proxy) as client:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()

                data = response.json()

                # 提取响应内容
                content = ""
                for block in data.get("content", []):
                    if block.get("type") == "text":
                        content += block.get("text", "")

                return content

        except httpx.HTTPStatusError as e:
            logger.error(f"Claude API HTTP error: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"Claude API call failed: {e}")
            raise

    async def generate(self, prompt: str, **kwargs) -> str:
        """
        生成文本（兼容接口）

        Args:
            prompt: 输入提示
            **kwargs: 其他参数

        Returns:
            str: 生成的文本
        """
        messages = [{"role": "user", "content": prompt}]
        return await self.chat(messages, **kwargs)


class OpenAICompatibleClient:
    """OpenAI 兼容接口客户端"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "mimo-v2.5-pro",
        timeout: float = 30.0,
    ):
        """
        初始化 OpenAI 兼容客户端

        Args:
            api_key: API 密钥
            base_url: API 基础 URL
            model: 模型名称
            timeout: 请求超时时间（秒）
        """
        self.api_key = api_key or os.environ.get("CLAUDE_API_KEY")
        if not self.api_key:
            raise ValueError("API key is required. Set CLAUDE_API_KEY environment variable or pass api_key parameter.")

        self.base_url = base_url or os.environ.get("CLAUDE_API_URL", "https://token-plan-cn.xiaomimimo.com/v1")
        self.model = model or os.environ.get("CLAUDE_MODEL", "mimo-v2.5-pro")
        self.timeout = timeout

        # 移除尾部斜杠
        self.base_url = self.base_url.rstrip("/")

        logger.info(f"OpenAI compatible client initialized with model: {self.model}, base_url: {self.base_url}")

    async def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4000,
        **kwargs,
    ) -> str:
        """
        发送聊天请求（OpenAI 兼容接口）

        Args:
            messages: 消息列表
            temperature: 温度参数
            max_tokens: 最大 token 数
            **kwargs: 其他参数

        Returns:
            str: 模型响应内容
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        url = f"{self.base_url}/chat/completions"

        try:
            # 检查是否需要代理
            proxy = os.environ.get("HTTP_PROXY") or os.environ.get("HTTPS_PROXY")
            async with httpx.AsyncClient(timeout=self.timeout, proxy=proxy) as client:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()

                data = response.json()

                # 提取响应内容
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                return content

        except httpx.HTTPStatusError as e:
            logger.error(f"OpenAI compatible API HTTP error: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"OpenAI compatible API call failed: {e}")
            raise

    async def generate(self, prompt: str, **kwargs) -> str:
        """
        生成文本（兼容接口）

        Args:
            prompt: 输入提示
            **kwargs: 其他参数

        Returns:
            str: 生成的文本
        """
        messages = [{"role": "user", "content": prompt}]
        return await self.chat(messages, **kwargs)


def create_llm_client(
    client_type: str = "anthropic",
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
) -> Any:
    """
    创建 LLM 客户端工厂函数

    Args:
        client_type: 客户端类型，"anthropic" 或 "openai"
        api_key: API 密钥
        base_url: API 基础 URL
        model: 模型名称

    Returns:
        LLM 客户端实例
    """
    if client_type == "anthropic":
        return ClaudeClient(api_key=api_key, base_url=base_url, model=model)
    elif client_type == "openai":
        return OpenAICompatibleClient(api_key=api_key, base_url=base_url, model=model)
    else:
        raise ValueError(f"Unsupported client type: {client_type}")


def load_llm_client_from_env() -> Any:
    """
    从环境变量加载 LLM 客户端

    Returns:
        LLM 客户端实例
    """
    client_type = os.environ.get("LLM_CLIENT_TYPE", "anthropic")
    return create_llm_client(client_type=client_type)
