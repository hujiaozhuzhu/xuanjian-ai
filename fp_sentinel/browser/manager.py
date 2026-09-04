"""
浏览器生命周期管理器

管理 Playwright 浏览器实例的创建、配置和销毁
"""

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class BrowserManager:
    """浏览器生命周期管理器"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.headless = self.config.get("headless", True)
        self.browser_type = self.config.get("browser_type", "chromium")
        self.user_data_dir = self.config.get("user_data_dir")
        self.proxy = self.config.get("proxy")
        self.timeout = self.config.get("timeout", 30000)
        self.stealth_mode = self.config.get("stealth_mode", True)
        self.viewport_width = self.config.get("viewport_width", 1920)
        self.viewport_height = self.config.get("viewport_height", 1080)
        self.user_agent = self.config.get("user_agent")

        self._playwright = None
        self._browser = None
        self._context = None

    async def launch(self):
        """启动浏览器"""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise ImportError(
                "Playwright is not installed. "
                "Install it with: pip install playwright && playwright install chromium"
            )

        self._playwright = await async_playwright().start()

        # 选择浏览器类型
        launcher = getattr(self._playwright, self.browser_type, None)
        if not launcher:
            raise ValueError(f"Unsupported browser type: {self.browser_type}")

        # 启动参数
        launch_args = {
            "headless": self.headless,
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
                "--no-sandbox",
            ],
        }

        if self.proxy:
            launch_args["proxy"] = {"server": self.proxy}

        # 启动浏览器
        if self.user_data_dir:
            # 持久化上下文
            self._context = await launcher.launch_persistent_context(
                user_data_dir=self.user_data_dir,
                **launch_args,
                viewport={"width": self.viewport_width, "height": self.viewport_height},
            )
            self._browser = None
        else:
            self._browser = await launcher.launch(**launch_args)
            self._context = await self._browser.new_context(
                viewport={"width": self.viewport_width, "height": self.viewport_height},
            )

        # 设置 User-Agent
        if self.user_agent:
            await self._context.set_extra_http_headers({
                "User-Agent": self.user_agent
            })

        # 反检测脚本
        if self.stealth_mode:
            await self._apply_stealth_mode()

        logger.info(f"Browser launched: {self.browser_type} (headless={self.headless})")

    async def _apply_stealth_mode(self):
        """应用反检测模式"""
        stealth_script = """
        // 隐藏 webdriver 标志
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });

        // 修改 navigator.plugins
        Object.defineProperty(navigator, 'plugins', {
            get: () => [1, 2, 3, 4, 5]
        });

        // 修改 navigator.languages
        Object.defineProperty(navigator, 'languages', {
            get: () => ['zh-CN', 'zh', 'en-US', 'en']
        });

        // 隐藏 Chrome DevTools Protocol
        window.chrome = {
            runtime: {}
        };

        // 修改 permissions
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
                Promise.resolve({ state: Notification.permission }) :
                originalQuery(parameters)
        );
        """

        if self._context:
            await self._context.add_init_script(stealth_script)

    async def new_page(self):
        """创建新页面"""
        if not self._context:
            raise RuntimeError("Browser not launched. Call launch() first.")

        page = await self._context.new_page()
        page.set_default_timeout(self.timeout)
        return page

    async def close(self):
        """关闭浏览器"""
        try:
            if self._context:
                await self._context.close()
                self._context = None
            if self._browser:
                await self._browser.close()
                self._browser = None
            if self._playwright:
                await self._playwright.stop()
                self._playwright = None
            logger.info("Browser closed")
        except Exception as e:
            logger.error(f"Error closing browser: {e}")

    @property
    def is_running(self) -> bool:
        """浏览器是否正在运行"""
        return self._context is not None

    async def get_page_snapshot(self, page) -> Dict[str, Any]:
        """获取页面快照"""
        try:
            return {
                "url": page.url,
                "title": await page.title(),
                "cookies": await self._context.cookies() if self._context else [],
                "localStorage": await page.evaluate("() => ({...localStorage})"),
                "sessionStorage": await page.evaluate("() => ({...sessionStorage})"),
            }
        except Exception as e:
            logger.error(f"Failed to get page snapshot: {e}")
            return {"url": page.url, "error": str(e)}
