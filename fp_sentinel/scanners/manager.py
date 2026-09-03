"""
扫描器管理器

统一调度多个扫描工具，聚合结果
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from .semgrep_scanner import SemgrepScanner
from .findsecbugs_scanner import FindSecBugsScanner
from .bandit_scanner import BanditScanner
from ..models import ScanResult, ScanTool


logger = logging.getLogger(__name__)

# JS/TS 文件扩展名
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


class ScannerManager:
    """扫描器管理器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.scanners = {}
        self._init_scanners()

    def _init_scanners(self):
        """初始化扫描器"""
        scanner_configs = self.config.get("scanners", {})

        # Semgrep (通用)
        semgrep_config = scanner_configs.get("semgrep", {"enabled": True})
        if semgrep_config.get("enabled", True):
            self.scanners[ScanTool.SEMGREP] = SemgrepScanner(semgrep_config)

        # FindSecBugs (Java)
        findsecbugs_config = scanner_configs.get("findsecbugs", {"enabled": True})
        if findsecbugs_config.get("enabled", True):
            self.scanners[ScanTool.FINDSECBUGS] = FindSecBugsScanner(findsecbugs_config)

        # Bandit (Python)
        bandit_config = scanner_configs.get("bandit", {"enabled": True})
        if bandit_config.get("enabled", True):
            self.scanners[ScanTool.BANDIT] = BanditScanner(bandit_config)

        # JS Scanner (JavaScript/TypeScript)
        try:
            from .js_scanner import JSScanner
            js_config = scanner_configs.get("js_scanner", {"enabled": True})
            if js_config.get("enabled", True):
                self.scanners[ScanTool.JS_SCANNER] = JSScanner(js_config)
        except ImportError:
            logger.debug("JS Scanner not available")

        # Python Scanner (Python 规则正则扫描)
        try:
            from .python_scanner import PythonScanner
            py_config = scanner_configs.get("python_scanner", {"enabled": True})
            if py_config.get("enabled", True):
                self.scanners[ScanTool.PY_SCANNER] = PythonScanner(py_config)
        except ImportError:
            logger.debug("Python Scanner not available")

    async def scan(
        self,
        target_path: str,
        language: str = "auto",
        scanners: Optional[List[ScanTool]] = None,
        **kwargs
    ) -> List[ScanResult]:
        """
        扫描目标路径

        Args:
            target_path: 目标路径
            language: 语言
            scanners: 指定扫描器列表，None则自动选择

        Returns:
            List[ScanResult]: 聚合后的扫描结果
        """
        # 自动检测语言
        if language == "auto":
            language = self._detect_language(target_path)

        # 选择扫描器
        if scanners is None:
            scanners = self._select_scanners(language)

        # 并发执行扫描
        tasks = []
        for tool in scanners:
            if tool in self.scanners:
                scanner = self.scanners[tool]
                tasks.append(scanner.scan(target_path, language=language, **kwargs))

        if not tasks:
            logger.warning("No scanners available for the target")
            return []

        results_lists = await asyncio.gather(*tasks, return_exceptions=True)

        # 聚合结果，去重
        all_results = []
        seen = set()
        for results in results_lists:
            if isinstance(results, Exception):
                logger.error(f"Scanner failed: {results}")
                continue
            for r in results:
                key = f"{r.file}:{r.line}:{r.rule_id}"
                if key not in seen:
                    seen.add(key)
                    all_results.append(r)

        return all_results

    def _detect_language(self, target_path: str) -> str:
        """自动检测项目语言"""
        import os

        # 检查构建文件
        if os.path.exists(os.path.join(target_path, "pom.xml")):
            return "java"
        if os.path.exists(os.path.join(target_path, "build.gradle")):
            return "java"
        if os.path.exists(os.path.join(target_path, "build.gradle.kts")):
            return "java"
        if os.path.exists(os.path.join(target_path, "requirements.txt")):
            return "python"
        if os.path.exists(os.path.join(target_path, "setup.py")):
            return "python"
        if os.path.exists(os.path.join(target_path, "pyproject.toml")):
            return "python"
        if os.path.exists(os.path.join(target_path, "go.mod")):
            return "go"
        if os.path.exists(os.path.join(target_path, "package.json")):
            return "javascript"
        if os.path.exists(os.path.join(target_path, "tsconfig.json")):
            return "typescript"

        # 按文件扩展名统计
        ext_count = {}
        for root, _, files in os.walk(target_path):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                ext_count[ext] = ext_count.get(ext, 0) + 1

        # JavaScript/TypeScript 检测
        js_count = sum(ext_count.get(ext, 0) for ext in JS_EXTENSIONS)
        if js_count > 0 and js_count >= ext_count.get(".java", 0):
            if ext_count.get(".ts", 0) > 0 or ext_count.get(".tsx", 0) > 0:
                return "typescript"
            return "javascript"

        if ext_count.get(".java", 0) > ext_count.get(".py", 0):
            return "java"
        if ext_count.get(".py", 0) > 0:
            return "python"
        if ext_count.get(".go", 0) > 0:
            return "go"

        return "java"  # 默认 Java

    def _select_scanners(self, language: str) -> List[ScanTool]:
        """根据语言选择扫描器"""
        if language == "java":
            return [ScanTool.SEMGREP, ScanTool.FINDSECBUGS]
        elif language == "python":
            tools = [ScanTool.SEMGREP, ScanTool.BANDIT]
            if ScanTool.PY_SCANNER in self.scanners:
                tools.append(ScanTool.PY_SCANNER)
            return tools
        elif language in ("javascript", "typescript"):
            tools = [ScanTool.SEMGREP]
            if ScanTool.JS_SCANNER in self.scanners:
                tools.append(ScanTool.JS_SCANNER)
            return tools
        elif language == "go":
            return [ScanTool.SEMGREP]
        else:
            return [ScanTool.SEMGREP]

    def get_available_scanners(self) -> List[str]:
        """获取已配置且可执行的扫描器列表。"""
        return [
            tool.value
            for tool, scanner in self.scanners.items()
            if getattr(scanner, "available", True)
        ]

    def get_unavailable_scanner_messages(self) -> List[str]:
        """返回已配置但未启用的扫描器提示，供 CLI 在扫描后集中展示。"""
        return [
            scanner.unavailable_reason
            for scanner in self.scanners.values()
            if getattr(scanner, "available", True) is False
            and getattr(scanner, "unavailable_reason", None)
        ]

    def get_runtime_warnings(self) -> List[str]:
        """返回扫描过程中产生的可操作提示，例如压缩代码预处理状态。"""
        warnings: List[str] = []
        for scanner in self.scanners.values():
            getter = getattr(scanner, "get_preprocess_warnings", None)
            if getter:
                warnings.extend(getter())
        return list(dict.fromkeys(warnings))
