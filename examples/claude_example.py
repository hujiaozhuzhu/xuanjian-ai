#!/usr/bin/env python3
"""
Claude 客户端使用示例

演示如何使用 Claude 客户端进行代码审计和红队攻击用例生成
"""

import asyncio
import os
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from fp_sentinel.llm_client import ClaudeClient, OpenAICompatibleClient, create_llm_client
from fp_sentinel.config import load_config, get_llm_client


async def example_claude_client():
    """示例：直接使用 Claude 客户端"""
    print("=" * 60)
    print("示例 1: 直接使用 Claude 客户端")
    print("=" * 60)
    
    # 从环境变量加载配置
    client = ClaudeClient()
    
    # 简单对话
    messages = [
        {"role": "user", "content": "请用一句话解释什么是代码审计中的误报（false positive）？"}
    ]
    
    response = await client.chat(messages)
    print(f"问题: {messages[0]['content']}")
    print(f"回答: {response}")
    print()


async def example_openai_compatible():
    """示例：使用 OpenAI 兼容接口"""
    print("=" * 60)
    print("示例 2: 使用 OpenAI 兼容接口")
    print("=" * 60)
    
    # 创建 OpenAI 兼容客户端
    client = OpenAICompatibleClient()
    
    # 简单对话
    messages = [
        {"role": "user", "content": "请列举 3 个常见的 JavaScript 安全漏洞类型。"}
    ]
    
    response = await client.chat(messages)
    print(f"问题: {messages[0]['content']}")
    print(f"回答: {response}")
    print()


async def example_factory_function():
    """示例：使用工厂函数创建客户端"""
    print("=" * 60)
    print("示例 3: 使用工厂函数创建客户端")
    print("=" * 60)
    
    # 创建 Anthropic 客户端
    client = create_llm_client(client_type="anthropic")
    
    # 简单对话
    messages = [
        {"role": "user", "content": "什么是 Prompt Injection？如何防御？"}
    ]
    
    response = await client.chat(messages)
    print(f"问题: {messages[0]['content']}")
    print(f"回答: {response}")
    print()


async def example_with_system_prompt():
    """示例：使用系统提示词"""
    print("=" * 60)
    print("示例 4: 使用系统提示词")
    print("=" * 60)
    
    client = ClaudeClient()
    
    system_prompt = """你是一个专业的代码安全审计专家。
请用简洁、专业的语言回答问题。"""
    
    messages = [
        {"role": "user", "content": "请分析以下代码的安全风险：\n```javascript\nconst query = `SELECT * FROM users WHERE id = ${userId}`;\n```"}
    ]
    
    response = await client.chat(messages, system=system_prompt)
    print(f"系统提示: {system_prompt}")
    print(f"问题: {messages[0]['content']}")
    print(f"回答: {response}")
    print()


async def example_config_loading():
    """示例：从配置文件加载客户端"""
    print("=" * 60)
    print("示例 5: 从配置文件加载客户端")
    print("=" * 60)
    
    # 加载配置
    config = load_config()
    
    # 获取 LLM 客户端
    client = get_llm_client(config)
    
    if client:
        messages = [
            {"role": "user", "content": "请简要介绍 SQL 注入的原理。"}
        ]
        
        response = await client.chat(messages)
        print(f"问题: {messages[0]['content']}")
        print(f"回答: {response}")
    else:
        print("无法加载 LLM 客户端，请检查配置。")
    
    print()


async def example_red_team_generation():
    """示例：红队攻击用例生成"""
    print("=" * 60)
    print("示例 6: 红队攻击用例生成")
    print("=" * 60)
    
    from fp_sentinel.redteam.generator import RedTeamGenerator
    
    # 创建 LLM 客户端
    client = ClaudeClient()
    
    # 创建红队生成器
    generator = RedTeamGenerator(llm_client=client)
    
    # 生成 SQL 注入绕过用例
    result = await generator.generate_bypasses(
        rule_id="python.lang.security.injection.sql-injection",
        description="SQL 注入漏洞",
        pattern=r"execute\s*\(\s*['\"].*%s",
        category="INJECTION",
        severity="HIGH",
        language="python",
        count=5,
    )
    
    print(f"生成了 {len(result.cases)} 个绕过用例：")
    for i, case in enumerate(result.cases[:3], 1):
        print(f"\n用例 {i}:")
        print(f"  策略: {case.strategy}")
        print(f"  难度: {case.difficulty}")
        print(f"  描述: {case.description}")
        print(f"  绕过代码: {case.bypass_code[:100]}...")
    
    print()


async def main():
    """主函数"""
    print("Claude 客户端使用示例")
    print("=" * 60)
    print()
    
    # 检查环境变量
    if not os.environ.get("CLAUDE_API_KEY"):
        print("警告: 未设置 CLAUDE_API_KEY 环境变量")
        print("请在 .env 文件中配置 API 密钥")
        print()
    
    try:
        # 运行示例
        await example_claude_client()
        await example_openai_compatible()
        await example_factory_function()
        await example_with_system_prompt()
        await example_config_loading()
        await example_red_team_generation()
        
    except Exception as e:
        print(f"错误: {e}")
        print("请检查 API 配置和网络连接。")


if __name__ == "__main__":
    asyncio.run(main())