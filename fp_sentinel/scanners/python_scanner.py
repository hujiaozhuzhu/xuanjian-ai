"""
Python 专用安全扫描器

支持:
- 自定义规则模式匹配（fp_sentinel/rules/python）
- 上下文窗口 guard（前后 6 行出现安全守卫则抑制）

v2.5.1 P1 性能优化:
- 大文件阈值限制（>MAX_FILE_SIZE_BYTES 跳过）
- 文件缓存上限，防内存泄漏
- 检查完成后主动释放文件缓存
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseScanner
from ..models import ScanResult, ScanTool, Severity
from ..filters.py_guard import py_suppressed_by_guard
from ..rules.python import PYTHON_SECURITY_RULES

logger = logging.getLogger(__name__)

# ── v2.5.1 性能调优常量 ──
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024   # 单文件 2MB 上限
MAX_FILE_CACHE_ENTRIES = 50              # 文件缓存最大条目数（防内存泄漏）

# Python 文件扩展名
PY_EXTENSIONS = {".py"}

# Severity 映射
SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


class PythonScanner(BaseScanner):
    """Python 专用安全扫描器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.timeout = self.config.get("timeout", 300)
        self.check_dependencies = self.config.get("check_dependencies", True)
        self.use_window_guard = self.config.get("window_guard", True)
        # v2.5.1: 有界缓存，防内存泄漏
        self._file_cache: Dict[str, str] = {}
        self._compiled: Dict[str, Any] = {}

    def get_tool_type(self) -> ScanTool:
        return ScanTool.PY_SCANNER

    async def scan(
        self,
        target_path: str,
        language: Optional[str] = None,
        **kwargs
    ) -> List[ScanResult]:
        """扫描目标路径的 Python 文件"""
        results: List[ScanResult] = []
        target = Path(target_path)

        if target.is_file():
            files = [target]
        elif target.is_dir():
            files = self._collect_py_files(target)
        else:
            logger.warning(f"Target path does not exist: {target_path}")
            return []

        logger.info(f"Scanning {len(files)} Python files")

        results.extend(await self._scan_with_rules(files))

        # v2.5.1: 扫描结束后清缓存
        self.clear_cache()
        logger.info(f"Python Scanner found {len(results)} issues")
        return results

    def _collect_py_files(self, directory: Path) -> List[Path]:
        """收集目录中的 Python 文件（v2.5.1: 跳过超大文件）"""
        files = []
        skip_dirs = {
            ".git", "__pycache__", ".venv", "venv", "dist", "build",
            ".mypy_cache", ".pytest_cache", "node_modules", ".tox",
        }

        for path in directory.rglob("*.py"):
            if any(skip in path.parts for skip in skip_dirs):
                continue
            if path.is_file():
                # v2.5.1: 跳过超大文件
                try:
                    if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                        logger.debug(f"Skipping large file: {path} (> {MAX_FILE_SIZE_BYTES} bytes)")
                        continue
                except OSError:
                    pass
                files.append(path)

        return files

    async def _scan_with_rules(self, files: List[Path]) -> List[ScanResult]:
        """使用自定义规则扫描文件（每条规则独立容错，坏规则不中断其他规则）

        v2.5.1: 每处理 N 个文件后有界清理缓存，防内存泄漏。
        """
        results: List[ScanResult] = []
        files_since_cleanup = 0

        for file_path in files:
            try:
                content = self._read_file(file_path)
                if not content:
                    continue

                lines = content.split("\n")
                for rule in PYTHON_SECURITY_RULES:
                    if not rule.code_pattern:
                        continue
                    try:
                        results.extend(
                            self._apply_rule(rule, file_path, lines)
                        )
                    except re.error as e:
                        logger.warning(f"Bad regex in rule {rule.rule_id}: {e}")
                        continue
                    except Exception as e:
                        logger.warning(f"Rule {rule.rule_id} failed on {file_path}: {e}")
                        continue
            except Exception as e:
                logger.error(f"Error scanning {file_path}: {e}")

            # v2.5.1: 定期清理缓存
            files_since_cleanup += 1
            if files_since_cleanup >= 10:
                self._evict_cache_if_needed()
                files_since_cleanup = 0

        return results

    def _apply_rule(self, rule, file_path: Path, lines: List[str]) -> List[ScanResult]:
        """应用单条规则到单个文件"""
        pattern = self._get_compiled(rule)
        results: List[ScanResult] = []

        for line_num, line in enumerate(lines, 1):
            if not pattern.search(line):
                continue

            # 行内误报指标检查
            if self._check_false_positive_indicators(line, rule.false_positive_indicators):
                continue

            # 上下文窗口 guard
            if self.use_window_guard and py_suppressed_by_guard(
                lines, line_num - 1, rule.category, rule.rule_id
            ):
                logger.debug(
                    f"Finding suppressed by window guard: {rule.rule_id} "
                    f"{file_path}:{line_num}"
                )
                continue

            results.append(ScanResult(
                tool=ScanTool.PY_SCANNER,
                rule_id=rule.rule_id,
                file=str(file_path),
                line=line_num,
                code=line.strip()[:200],
                severity=SEVERITY_MAP.get(rule.severity, Severity.MEDIUM),
                message=rule.description,
                cwe=rule.cwe,
                owasp=rule.owasp,
                metadata={
                    "category": rule.category,
                    "confidence": rule.confidence,
                    "scanner": "python_scanner",
                },
            ))

        return results

    def _get_compiled(self, rule) -> "re.Pattern":
        """缓存编译后的正则（进程级缓存）"""
        if rule.rule_id not in self._compiled:
            self._compiled[rule.rule_id] = re.compile(rule.code_pattern, re.IGNORECASE)
        return self._compiled[rule.rule_id]

    def _read_file(self, file_path: Path) -> Optional[str]:
        """读取文件内容（带大小上限的缓存，v2.5.1: 有界）"""
        path_str = str(file_path)
        if path_str in self._file_cache:
            return self._file_cache[path_str]

        try:
            # v2.5.1: 超大文件防御性跳过
            if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                logger.debug(f"Skipping large file at read time: {path_str}")
                return None
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            # v2.5.1: 有界缓存（写入前先检查上限）
            self._evict_cache_if_needed()
            self._file_cache[path_str] = content
            return content
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return None

    def _check_false_positive_indicators(
        self, line: str, indicators: List[str]
    ) -> bool:
        """检查误报指标"""
        if not indicators:
            return False
        for indicator in indicators:
            if indicator.lower() in line.lower():
                return True
        return False

    # ── v2.5.1 缓存管理（防内存泄漏） ──

    def _evict_cache_if_needed(self, force: bool = False) -> None:
        """若缓存超过上限，驱逐最早写入的条目"""
        if not force and len(self._file_cache) <= MAX_FILE_CACHE_ENTRIES:
            return
        if force:
            self._file_cache.clear()
            return
        keys_to_remove = list(self._file_cache.keys())[:20]
        for k in keys_to_remove:
            self._file_cache.pop(k, None)

    def clear_cache(self):
        """清除缓存"""
        self._file_cache.clear()
        self._compiled.clear()
