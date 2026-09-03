"""
浏览器相关 CLI 命令

提供 JSRPC 浏览器自动化命令
"""

import asyncio
import json
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

console = Console()
app = typer.Typer(name="browser", help="浏览器自动化 (JSRPC)")


@app.command()
def start(
    url: Optional[str] = typer.Option(None, "--url", "-u", help="初始导航URL"),
    headless: bool = typer.Option(True, "--headless/--no-headless", help="无头模式"),
    stealth: bool = typer.Option(True, "--stealth/--no-stealth", help="反检测模式"),
    rpc_port: int = typer.Option(18800, "--rpc-port", help="RPC服务器端口"),
):
    """启动浏览器实例"""
    async def _run():
        from ..models import BrowserConfig, RPCConfig
        from ..browser.engine import BrowserEngine

        browser_config = BrowserConfig(headless=headless, stealth_mode=stealth)
        rpc_config = RPCConfig(port=rpc_port)
        engine = BrowserEngine(browser_config, rpc_config)

        session = await engine.start(enable_rpc=True)

        console.print(Panel(
            f"[bold green]浏览器已启动[/bold green]\n\n"
            f"会话ID: [cyan]{session.session_id}[/cyan]\n"
            f"RPC端口: [cyan]{rpc_port}[/cyan]\n"
            f"无头模式: {'是' if headless else '否'}\n"
            f"反检测: {'启用' if stealth else '禁用'}",
            title="JSRPC 引擎"
        ))

        if url:
            result = await engine.navigate(session.session_id, url)
            console.print("\n[bold]导航结果:[/bold]")
            console.print(f"  URL: {result.get('url')}")
            console.print(f"  标题: {result.get('title')}")
            console.print(f"  状态: {result.get('status')}")

        console.print(f"\n[yellow]RPC 服务运行在 ws://127.0.0.1:{rpc_port}/ws[/yellow]")
        console.print("[dim]按 Ctrl+C 停止...[/dim]")

        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await engine.stop()
            console.print("\n[red]浏览器已关闭[/red]")

    asyncio.run(_run())


@app.command()
def call(
    func: str = typer.Argument(..., help="函数名"),
    args: str = typer.Option("[]", "--args", "-a", help="参数(JSON数组)"),
    port: int = typer.Option(18800, "--port", "-p", help="RPC端口"),
):
    """远程调用页面函数"""
    import aiohttp

    async def _run():
        parsed_args = json.loads(args)
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"http://127.0.0.1:{port}/call",
                json={"func": func, "args": parsed_args}
            ) as resp:
                result = await resp.json()
                console.print_json(json.dumps(result, ensure_ascii=False, indent=2))

    asyncio.run(_run())


@app.command()
def hook(
    target: str = typer.Argument(..., help="目标函数路径"),
    hook_type: str = typer.Option("trace", "--type", "-t", help="Hook类型"),
    port: int = typer.Option(18800, "--port", "-p", help="RPC端口"),
):
    """注入函数Hook"""
    import aiohttp

    async def _run():
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"http://127.0.0.1:{port}/hook",
                json={"target": target, "type": hook_type}
            ) as resp:
                result = await resp.json()
                console.print_json(json.dumps(result, ensure_ascii=False, indent=2))

    asyncio.run(_run())


@app.command()
def navigate(
    url: str = typer.Argument(..., help="目标URL"),
    port: int = typer.Option(18800, "--port", "-p", help="RPC端口"),
):
    """导航到目标URL"""
    import aiohttp

    async def _run():
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"http://127.0.0.1:{port}/navigate",
                json={"url": url}
            ) as resp:
                result = await resp.json()
                console.print_json(json.dumps(result, ensure_ascii=False, indent=2))

    asyncio.run(_run())


@app.command()
def script(
    code: str = typer.Argument(..., help="JS代码"),
    port: int = typer.Option(18800, "--port", "-p", help="RPC端口"),
):
    """执行JavaScript代码"""
    import aiohttp

    async def _run():
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"http://127.0.0.1:{port}/script",
                json={"code": code}
            ) as resp:
                result = await resp.json()
                console.print_json(json.dumps(result, ensure_ascii=False, indent=2))

    asyncio.run(_run())


@app.command()
def status(
    port: int = typer.Option(18800, "--port", "-p", help="RPC端口"),
):
    """查看浏览器状态"""
    import aiohttp

    async def _run():
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/status") as resp:
                result = await resp.json()
                console.print_json(json.dumps(result, ensure_ascii=False, indent=2))

    asyncio.run(_run())


@app.command()
def keys(
    port: int = typer.Option(18800, "--port", "-p", help="RPC端口"),
):
    """获取捕获的密钥"""
    import aiohttp

    async def _run():
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/keys") as resp:
                result = await resp.json()
                console.print_json(json.dumps(result, ensure_ascii=False, indent=2))

    asyncio.run(_run())


if __name__ == "__main__":
    app()
