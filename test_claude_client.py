#!/usr/bin/env python3
"""
Claude 客户端测试脚本

测试 Claude API 客户端是否正常工作
"""

import asyncio
import os
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# 手动加载 .env 文件
def load_dotenv():
    """手动加载 .env 文件"""
    env_path = project_root / ".env"
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    os.environ[key.strip()] = value.strip()

# 加载环境变量
load_dotenv()

from fp_sentinel.llm_client import ClaudeClient, OpenAICompatibleClient


async def test_claude_client():
    """测试 Claude 客户端"""
    print("=" * 60)
    print("测试 Claude 客户端")
    print("=" * 60)
    
    try:
        # 创建客户端
        client = ClaudeClient()
        print("[OK] Claude 客户端创建成功")
        
        # 测试聊天功能
        messages = [
            {"role": "user", "content": "请用一句话介绍自己。"}
        ]
        
        print("正在发送请求...")
        response = await client.chat(messages)
        
        print(f"[OK] 收到响应: {response[:100]}...")
        return True
        
    except Exception as e:
        import traceback
        print(f"[ERROR] 错误: {e}")
        traceback.print_exc()
        return False


async def test_openai_compatible():
    """测试 OpenAI 兼容客户端"""
    print("\n" + "=" * 60)
    print("测试 OpenAI 兼容客户端")
    print("=" * 60)
    
    try:
        # 创建客户端
        client = OpenAICompatibleClient()
        print("[OK] OpenAI 兼容客户端创建成功")
        
        # 测试聊天功能
        messages = [
            {"role": "user", "content": "请用一句话介绍代码审计。"}
        ]
        
        print("正在发送请求...")
        response = await client.chat(messages)
        
        print(f"[OK] 收到响应: {response[:100]}...")
        return True
        
    except Exception as e:
        print(f"[ERROR] 错误: {e}")
        return False


async def test_factory_function():
    """测试工厂函数"""
    print("\n" + "=" * 60)
    print("测试工厂函数")
    print("=" * 60)
    
    try:
        from fp_sentinel.llm_client import create_llm_client
        
        # 测试创建 Anthropic 客户端
        client = create_llm_client(client_type="anthropic")
        print("[OK] Anthropic 客户端创建成功")
        
        # 测试创建 OpenAI 客户端
        client = create_llm_client(client_type="openai")
        print("[OK] OpenAI 客户端创建成功")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] 错误: {e}")
        return False


async def test_config_loading():
    """测试配置加载"""
    print("\n" + "=" * 60)
    print("测试配置加载")
    print("=" * 60)
    
    try:
        from fp_sentinel.config import load_config, get_llm_client
        
        # 加载配置
        config = load_config()
        print("[OK] 配置加载成功")
        
        # 获取 LLM 客户端
        client = get_llm_client(config)
        
        if client:
            print("[OK] LLM 客户端创建成功")
        else:
            print("[WARN] LLM 客户端未创建（可能未配置）")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] 错误: {e}")
        return False


async def main():
    """主函数"""
    print("Claude 客户端测试")
    print("=" * 60)
    print()
    
    # 检查环境变量
    api_key = os.environ.get("CLAUDE_API_KEY")
    if not api_key:
        print("警告: 未设置 CLAUDE_API_KEY 环境变量")
        print("请在 .env 文件中配置 API 密钥")
        print()
    else:
        print(f"[OK] 找到 API 密钥: {api_key[:10]}...")
    
    print()
    
    # 运行测试
    results = []
    
    # 测试工厂函数（不需要 API 调用）
    results.append(await test_factory_function())
    
    # 测试配置加载（不需要 API 调用）
    results.append(await test_config_loading())
    
    # 测试 Claude 客户端（需要 API 调用）
    if api_key:
        results.append(await test_claude_client())
        results.append(await test_openai_compatible())
    else:
        print("跳过 API 调用测试（未配置 API 密钥）")
    
    # 总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    
    passed = sum(results)
    total = len(results)
    
    print(f"通过: {passed}/{total}")
    
    if passed == total:
        print("[OK] 所有测试通过")
        return 0
    else:
        print("[ERROR] 部分测试失败")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)