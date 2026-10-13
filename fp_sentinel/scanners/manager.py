"""
扫描器管理器

统一调度多个扫描工具，聚合结果
v2.3.0: 新增 Go 语言自动识别与 GoScanner 注册；增强 JS/TS 扩展名覆盖
"""

import asyncio
import logging
import time
from copy import deepcopy
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from .base import (
    ScannerParseError,
    canonical_error_code,
)
from .semgrep_scanner import SemgrepScanner
from .findsecbugs_scanner import FindSecBugsScanner
from .bandit_scanner import BanditScanner
from ..models import ScanResult, ScanTool


logger = logging.getLogger(__name__)

# JS/TS 文件扩展名
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
# Go 文件扩展名
GO_EXTENSIONS = {".go"}


class ScannerManager:
    """扫描器管理器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Create a manager from either app-level or scanner-only config.

        Older callers passed the complete application configuration while the
        CLI passes ``AppConfig.scanners``.  Accept both shapes so scanner
        settings are applied consistently across entry points.
        """
        raw_config = config or {}
        nested_scanners = raw_config.get("scanners")
        self.config = (
            nested_scanners
            if isinstance(nested_scanners, dict)
            else raw_config
        )
        self.scanners = {}
        self.last_execution = self._new_execution_state("idle", None, [], {})
        self._init_scanners()

    def _init_scanners(self):
        """初始化扫描器"""
        scanner_configs = self.config

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

        # Go Scanner (Go 规则正则扫描 v2.3.0)
        try:
            from .go_scanner import GoScanner
            go_config = scanner_configs.get("go_scanner", {"enabled": True})
            if go_config.get("enabled", True):
                self.scanners[ScanTool.GO_SCANNER] = GoScanner(go_config)
        except ImportError:
            logger.debug("Go Scanner not available")

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

        selected_tools = list(scanners)
        started_at = datetime.now(timezone.utc).isoformat()
        started_monotonic = time.monotonic()
        available_scanners: List[Tuple[ScanTool, Any]] = []
        failures: List[Dict[str, Any]] = []
        scanner_states: Dict[str, Dict[str, Any]] = {}
        requested_names = [getattr(tool, "value", str(tool)) for tool in selected_tools]
        available_names = [
            getattr(tool, "value", str(tool)) for tool in self.scanners
            if getattr(self.scanners[tool], "available", True) is not False
        ]

        for tool in selected_tools:
            scanner = self.scanners.get(tool)
            tool_name = getattr(tool, "value", str(tool))
            if scanner is None:
                failure = self._failure(tool, "SCANNER_UNAVAILABLE", "Scanner is not registered")
                failures.append(failure)
                scanner_states[tool_name] = self._scanner_state("failed", "SCANNER_UNAVAILABLE", [failure])
                continue
            if getattr(scanner, "available", True) is False:
                message = getattr(scanner, "unavailable_reason", None) or "Scanner tool is unavailable"
                failure = self._failure(tool, "TOOL_MISSING", message)
                failures.append(failure)
                scanner_states[tool_name] = self._scanner_state("failed", "TOOL_MISSING", [failure])
                continue
            available_scanners.append((tool, scanner))

        if not available_scanners:
            if not failures:
                failures.append(self._failure(None, "NO_SCANNER_AVAILABLE", "No scanners available for the target"))
            self.last_execution = self._new_execution_state(
                "no_scanners", "NO_SCANNER_AVAILABLE", failures, scanner_states,
                requested_scanners=requested_names,
                available_scanners=available_names,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                duration_ms=round((time.monotonic() - started_monotonic) * 1000, 3),
            )
            logger.warning("No scanners available for the target")
            return []

        tasks = [scanner.scan(target_path, language=language, **kwargs) for _, scanner in available_scanners]
        results_lists = await asyncio.gather(*tasks, return_exceptions=True)

        # 聚合结果，去重
        all_results = []
        seen = set()
        for (tool, scanner), results in zip(available_scanners, results_lists):
            state = deepcopy(getattr(scanner, "last_execution", {}))
            state.pop("_started_monotonic", None)
            if isinstance(results, Exception):
                code = getattr(results, "error_code", "SCANNER_EXCEPTION")
                if isinstance(results, asyncio.TimeoutError):
                    code = "TIMEOUT"
                elif isinstance(results, ScannerParseError):
                    code = "PARSE_ERROR"
                failure = self._failure(tool, code, str(results) or results.__class__.__name__)
                failures.append(failure)
                scanner_states[getattr(tool, "value", str(tool))] = self._scanner_state("failed", code, [failure], state)
                logger.error(f"Scanner failed: {results}")
                continue

            scanner_failures = state.get("failures") or []
            scanner_status = state.get("status") or "completed"
            scanner_error = state.get("error_code")
            if scanner_failures or scanner_status in {"failed", "incomplete"} or scanner_error:
                normalized_failures = [self._normalize_failure(tool, failure) for failure in scanner_failures]
                if not normalized_failures:
                    normalized_failures = [
                        self._failure(tool, scanner_error or "SCANNER_FAILED", "Scanner reported failure")
                    ]
                failures.extend(normalized_failures)
                scanner_states[getattr(tool, "value", str(tool))] = self._scanner_state(
                    scanner_status if scanner_status in {"failed", "incomplete"} else "failed",
                    scanner_error or normalized_failures[0]["error_code"],
                    normalized_failures,
                    state,
                )
                continue

            scanner_states[getattr(tool, "value", str(tool))] = self._scanner_state(
                "completed", None, [], state
            )
            for r in results:
                key = self._result_dedup_key(r)
                if key not in seen:
                    seen.add(key)
                    all_results.append(r)

        executed_names = [
            getattr(tool, "value", str(tool)) for tool, _ in available_scanners
        ]
        if failures:
            status = "failed" if not all_results else "partial"
            self.last_execution = self._new_execution_state(
                status, failures[0]["error_code"], failures, scanner_states,
                requested_scanners=requested_names,
                available_scanners=available_names,
                executed_scanners=executed_names,
                result_count=len(all_results),
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                duration_ms=round((time.monotonic() - started_monotonic) * 1000, 3),
                legacy_status="incomplete" if status == "partial" else None,
            )
        else:
            self.last_execution = self._new_execution_state(
                "completed", None, [], scanner_states,
                requested_scanners=requested_names,
                available_scanners=available_names,
                executed_scanners=executed_names,
                result_count=len(all_results),
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                duration_ms=round((time.monotonic() - started_monotonic) * 1000, 3),
            )

        return all_results

    @staticmethod
    def _failure(tool: Optional[ScanTool], error_code: str, message: str) -> Dict[str, Any]:
        failure: Dict[str, Any] = {
            "error_code": error_code,
            "canonical_error_code": canonical_error_code(error_code),
            "message": message,
        }
        if tool is not None:
            failure["scanner"] = getattr(tool, "value", str(tool))
        return failure

    @staticmethod
    def _normalize_failure(tool: ScanTool, failure: Dict[str, Any]) -> Dict[str, Any]:
        normalized = dict(failure)
        normalized.setdefault("scanner", getattr(tool, "value", str(tool)))
        normalized.setdefault("error_code", "SCANNER_FAILED")
        normalized.setdefault(
            "canonical_error_code", canonical_error_code(normalized["error_code"])
        )
        normalized.setdefault("message", "Scanner failed")
        return normalized

    @staticmethod
    def _scanner_state(
        status: str,
        error_code: Optional[str],
        failures: List[Dict[str, Any]],
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        state = dict(details or {})
        state.update({
            "status": status,
            "error_code": error_code,
            "canonical_error_code": canonical_error_code(error_code),
            "failures": failures,
            "errors": failures,
        })
        return state

    @staticmethod
    def _new_execution_state(
        status: str,
        error_code: Optional[str],
        failures: List[Dict[str, Any]],
        scanner_states: Dict[str, Dict[str, Any]],
        *,
        requested_scanners: Optional[List[str]] = None,
        available_scanners: Optional[List[str]] = None,
        executed_scanners: Optional[List[str]] = None,
        result_count: int = 0,
        started_at: Optional[str] = None,
        completed_at: Optional[str] = None,
        duration_ms: Optional[float] = None,
        legacy_status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """创建 JSON 可序列化的执行状态并兼容旧字段。"""
        state = {
            "status": status,
            "error_code": error_code,
            "canonical_error_code": canonical_error_code(error_code),
            "failures": failures,
            "errors": failures,
            "scanner_states": scanner_states,
            "requested_scanners": requested_scanners or [],
            "available_scanners": available_scanners or [],
            "executed_scanners": executed_scanners or [],
            "result_count": result_count,
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_ms": duration_ms,
        }
        if legacy_status is not None:
            state["legacy_status"] = legacy_status
        return state

    @staticmethod
    def _result_dedup_key(result: ScanResult) -> str:
        """Keep distinct static locations in a minified bundle from being collapsed."""
        metadata = result.metadata or {}
        preprocess_location = metadata.get("original_offset_hint") or {}
        original_offset = preprocess_location.get("original_start")
        beautified_line = metadata.get("beautified_line")
        if original_offset is not None or beautified_line is not None:
            return (
                f"{result.file}:{result.rule_id}:"
                f"offset={original_offset}:formatted={beautified_line}"
            )
        return f"{result.file}:{result.line}:{result.rule_id}"

    def _detect_language(self, target_path: str) -> str:
        """自动检测项目或单个源文件的语言。"""
        import os

        # 单文件扫描不能通过 os.walk() 统计扩展名，先直接识别文件类型。
        if os.path.isfile(target_path):
            extension = os.path.splitext(target_path)[1].lower()
            if extension in {".js", ".jsx", ".mjs", ".cjs"}:
                return "javascript"
            if extension in {".ts", ".tsx"}:
                return "typescript"
            if extension == ".py":
                return "python"
            if extension == ".java":
                return "java"
            if extension == ".go":
                return "go"

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

        java_count = ext_count.get(".java", 0)
        py_count = ext_count.get(".py", 0)

        # A1-Fix: 反编译 Java 代码目录检测（无 pom.xml 但有大量 .java 文件）
        if java_count >= 3 and java_count >= py_count:
            return "java"
        if java_count > py_count:
            return "java"
        if py_count > 0:
            return "python"
        if ext_count.get(".go", 0) > 0:
            return "go"

        # A1-Fix: 默认回退时优先 Java（反编译代码最常见的目标语言）
        if java_count > 0:
            return "java"

        return "java"  # 默认 Java

    def _select_scanners(self, language: str) -> List[ScanTool]:
        """根据语言选择扫描器

        v2.3.0 更新：
        - go: Semgrep + GoScanner (自定义规则引擎)
        - 所有已注册扫描仪语言均自动匹配对应规则库，无需手动指定
        """
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
            tools = [ScanTool.SEMGREP]
            if ScanTool.GO_SCANNER in self.scanners:
                tools.append(ScanTool.GO_SCANNER)
            return tools
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
