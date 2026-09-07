#!/usr/bin/env python3
"""
网络诊断脚本

诊断 Claude API 连接问题
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


async def test_basic_connectivity():
    """测试基本网络连接"""
    print("=" * 60)
    print("测试基本网络连接")
    print("=" * 60)
    
    import httpx
    
    # 测试常见网站
    test_urls = [
        "https://www.baidu.com",
        "https://www.google.com",
        "https://api.github.com",
    ]
    
    for url in test_urls:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url)
                print(f"[OK] {url} - 状态码: {response.status_code}")
        except Exception as e:
            print(f"[ERROR] {url} - 错误: {type(e).__name__}")
    
    print()


async def test_api_url():
    """测试 API URL"""
    print("=" * 60)
    print("测试 API URL")
    print("=" * 60)
    
    import httpx
    
    api_url = os.environ.get("CLAUDE_API_URL", "https://token-plan-cn.xiaomimimo.com/v1")
    anthropic_url = os.environ.get("CLAUDE_API_URL_ANTHROPIC", "https://token-plan-cn.xiaomimimo.com/anthropic")
    
    urls = [
        ("OpenAI 兼容 URL", api_url),
        ("Anthropic URL", anthropic_url),
    ]
    
    for name, url in urls:
        print(f"\n测试 {name}: {url}")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # 尝试 GET 请求（可能返回 404 或 405，但能连接）
                response = await client.get(url)
                print(f"  [OK] 连接成功 - 状态码: {response.status_code}")
        except httpx.ConnectError as e:
            print(f"  [ERROR] 连接失败: {e}")
        except httpx.TimeoutException:
            print(f"  [ERROR] 连接超时")
        except Exception as e:
            print(f"  [ERROR] 错误: {type(e).__name__}: {e}")
    
    print()


async def test_proxy():
    """测试代理配置"""
    print("=" * 60)
    print("测试代理配置")
    print("=" * 60)
    
    proxy_vars = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    
    found_proxy = False
    for var in proxy_vars:
        value = os.environ.get(var)
        if value:
            print(f"[OK] 找到代理配置: {var}={value}")
            found_proxy = True
    
    if not found_proxy:
        print("[WARN] 未找到代理配置")
        print("如果需要代理，请设置以下环境变量之一：")
        print("  - HTTP_PROXY=http://proxy:port")
        print("  - HTTPS_PROXY=http://proxy:port")
        print("  - ALL_PROXY=http://proxy:port")
    
    print()


async def test_dns():
    """测试 DNS 解析"""
    print("=" * 60)
    print("测试 DNS 解析")
    print("=" * 60)
    
    import socket
    
    domains = [
        "token-plan-cn.xiaomimimo.com",
        "www.baidu.com",
        "api.github.com",
    ]
    
    for domain in domains:
        try:
            ip = socket.gethostbyname(domain)
            print(f"[OK] {domain} -> {ip}")
        except socket.gaierror as e:
            print(f"[ERROR] {domain} - DNS 解析失败: {e}")
    
    print()


async def test_ssl():
    """测试 SSL 连接"""
    print("=" * 60)
    print("测试 SSL 连接")
    print("=" * 60)
    
    import ssl
    import socket
    
    hostname = "token-plan-cn.xiaomimimo.com"
    port = 443
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print(f"[OK] SSL 连接成功")
                print(f"  协议: {ssock.version()}")
                print(f"  加密套件: {ssock.cipher()[0]}")
    except Exception as e:
        print(f"[ERROR] SSL 连接失败: {e}")
    
    print()


async def main():
    """主函数"""
    print("网络诊断工具")
    print("=" * 60)
    print()
    
    # 显示环境变量
    print("环境变量：")
    print(f"  CLAUDE_API_URL: {os.environ.get('CLAUDE_API_URL', '未设置')}")
    print(f"  CLAUDE_API_URL_ANTHROPIC: {os.environ.get('CLAUDE_API_URL_ANTHROPIC', '未设置')}")
    print(f"  HTTP_PROXY: {os.environ.get('HTTP_PROXY', '未设置')}")
    print(f"  HTTPS_PROXY: {os.environ.get('HTTPS_PROXY', '未设置')}")
    print()
    
    # 运行测试
    await test_dns()
    await test_proxy()
    await test_basic_connectivity()
    await test_api_url()
    await test_ssl()
    
    print("=" * 60)
    print("诊断完成")
    print("=" * 60)
    print()
    print("如果 API 连接失败，可能的原因：")
    print("1. 网络代理问题 - 请配置 HTTP_PROXY 或 HTTPS_PROXY")
    print("2. 防火墙阻止 - 请检查防火墙设置")
    print("3. API URL 不正确 - 请确认 API 地址")
    print("4. 网络连接问题 - 请检查网络连接")
    print()
    print("解决方案：")
    print("1. 如果需要代理，在 .env 文件中添加：")
    print("   HTTP_PROXY=http://your-proxy:port")
    print("   HTTPS_PROXY=http://your-proxy:port")
    print()
    print("2. 或者在命令行设置：")
    print("   set HTTP_PROXY=http://your-proxy:port")
    print("   set HTTPS_PROXY=http://your-proxy:port")


if __name__ == "__main__":
    asyncio.run(main())