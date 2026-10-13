"""
扫描器基类

定义所有扫描器的通用接口
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import time
from typing import List, Dict, Any, Optional
from ..models import ScanResult, ScanTool


ERROR_CODE_ALIASES = {
    "NO_SCANNER_AVAILABLE": "NO_AVAILABLE_SCANNERS",
    "SCANNER_UNAVAILABLE": "SCANNER_NOT_REGISTERED",
    "TOOL_MISSING": "SCANNER_TOOL_UNAVAILABLE",
    "TIMEOUT": "SCANNER_TIMEOUT",
    "PARSE_ERROR": "SCANNER_PARSE_FAILED",
    "NON_ZERO_EXIT": "SCANNER_NON_ZERO_EXIT",
    "SCANNER_EXCEPTION": "SCANNER_EXECUTION_FAILED",
}


def canonical_error_code(error_code: Optional[str]) -> Optional[str]:
    """将旧错误码映射为稳定的扫描运行时错误码。"""
    if error_code is None:
        return None
    return ERROR_CODE_ALIASES.get(error_code, error_code)


def _timestamp() -> str:
    """生成可序列化的 UTC 时间戳。"""
    return datetime.now(timezone.utc).isoformat()


class ScannerParseError(RuntimeError):
    """Raised when a scanner produced output that cannot be parsed."""

    error_code = "PARSE_ERROR"


class ScannerExecutionError(RuntimeError):
    """Base error for scanner execution failures."""

    error_code = "SCANNER_EXCEPTION"


class BaseScanner(ABC):
    """扫描器基类"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        # The manager consumes this state without changing the scanner API.
        # Keep it plain (JSON serialisable) for CLI/MCP callers.
        self.last_execution: Dict[str, Any] = self._new_execution_state("idle")

    @staticmethod
    def _new_execution_state(status: str) -> Dict[str, Any]:
        """创建扫描器状态并保留旧字段兼容。"""
        return {
            "status": status,
            "failures": [],
            "errors": [],
            "error_code": None,
            "canonical_error_code": None,
            "result_count": 0,
            "started_at": None,
            "completed_at": None,
            "duration_ms": None,
        }

    def _execution_started(self) -> None:
        self.last_execution = self._new_execution_state("running")
        self.last_execution["started_at"] = _timestamp()
        self.last_execution["_started_monotonic"] = time.monotonic()

    def _execution_completed(self, result_count: int = 0) -> None:
        self.last_execution["status"] = "completed"
        self.last_execution["result_count"] = result_count
        self._close_execution()

    def _execution_failed(
        self,
        error_code: str,
        message: str,
        *,
        status: str = "failed",
    ) -> None:
        failure = {"error_code": error_code, "message": message}
        canonical = canonical_error_code(error_code)
        self.last_execution.update({
            "status": status,
            "failures": [failure],
            "errors": [failure],
            "error_code": error_code,
            "canonical_error_code": canonical,
        })
        self._close_execution()

    def _close_execution(self) -> None:
        """封存完成时间与耗时并移除内部计时字段。"""
        self.last_execution["completed_at"] = _timestamp()
        started = self.last_execution.pop("_started_monotonic", None)
        if started is not None:
            self.last_execution["duration_ms"] = round(
                (time.monotonic() - started) * 1000, 3
            )

    @abstractmethod
    async def scan(self, target_path: str, **kwargs) -> List[ScanResult]:
        """
        扫描目标路径

        Args:
            target_path: 目标路径
            **kwargs: 额外参数

        Returns:
            List[ScanResult]: 扫描结果列表
        """
        pass

    @abstractmethod
    def get_tool_type(self) -> ScanTool:
        """获取扫描工具类型"""
        pass

    def _generate_id(self, tool: str, rule_id: str, file: str, line: int) -> str:
        """生成结果唯一ID"""
        return f"{tool}:{rule_id}:{file}:{line}"
