#!/usr/bin/env python3
"""
配置测试脚本

测试配置加载是否正常工作
"""

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

from fp_sentinel.config import load_config, get_llm_client


def test_config_loading():
    """测试配置加载"""
    print("=" * 60)
    print("测试配置加载")
    print("=" * 60)
    
    try:
        # 加载配置
        config = load_config()
        print("[OK] 配置加载成功")
        
        # 显示 LLM 配置
        print("\nLLM 配置:")
        print(f"  配置内容: {config.llm}")
        
        # 获取 LLM 客户端
        client = get_llm_client(config)
        
        if client:
            print(f"[OK] LLM 客户端创建成功: {type(client).__name__}")
        else:
            print("[WARN] LLM 客户端未创建（可能未配置）")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] 错误: {e}")
        return False


def test_env_variables():
    """测试环境变量"""
    print("\n" + "=" * 60)
    print("测试环境变量")
    print("=" * 60)
    
    env_vars = [
        "CLAUDE_API_KEY",
        "CLAUDE_API_URL",
        "CLAUDE_API_URL_ANTHROPIC",
        "CLAUDE_MODEL",
        "LLM_CLIENT_TYPE",
    ]
    
    for var in env_vars:
        value = os.environ.get(var)
        if value:
            # 隐藏敏感信息
            if "KEY" in var or "SECRET" in var:
                display_value = f"{value[:10]}..."
            else:
                display_value = value
            print(f"[OK] {var}: {display_value}")
        else:
            print(f"[WARN] {var}: 未设置")
    
    return True


def test_llm_client_creation():
    """测试 LLM 客户端创建"""
    print("\n" + "=" * 60)
    print("测试 LLM 客户端创建")
    print("=" * 60)
    
    try:
        from fp_sentinel.llm_client import ClaudeClient, OpenAICompatibleClient, create_llm_client
        
        # 测试 Claude 客户端
        try:
            client = ClaudeClient()
            print(f"[OK] Claude 客户端创建成功")
            print(f"  模型: {client.model}")
            print(f"  基础 URL: {client.base_url}")
        except Exception as e:
            print(f"[ERROR] Claude 客户端创建失败: {e}")
        
        # 测试 OpenAI 兼容客户端
        try:
            client = OpenAICompatibleClient()
            print(f"[OK] OpenAI 兼容客户端创建成功")
            print(f"  模型: {client.model}")
            print(f"  基础 URL: {client.base_url}")
        except Exception as e:
            print(f"[ERROR] OpenAI 兼容客户端创建失败: {e}")
        
        # 测试工厂函数
        try:
            client = create_llm_client(client_type="anthropic")
            print(f"[OK] 工厂函数创建 Anthropic 客户端成功")
        except Exception as e:
            print(f"[ERROR] 工厂函数创建 Anthropic 客户端失败: {e}")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] 错误: {e}")
        return False


def main():
    """主函数"""
    print("配置测试")
    print("=" * 60)
    print()
    
    # 运行测试
    results = []
    
    results.append(test_env_variables())
    results.append(test_config_loading())
    results.append(test_llm_client_creation())
    
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
    exit_code = main()
    sys.exit(exit_code)