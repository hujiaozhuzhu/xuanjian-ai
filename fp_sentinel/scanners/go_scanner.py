"""
Go 专用安全扫描器 v2.3.0

支持:
- 自定义规则模式匹配（fp_sentinel/rules/go）
- 上下文窗口 guard（前后 GO_GUARD_WINDOW 行出现安全守卫则抑制）
- 误报文件模式过滤（_test.go / example 等）
- 敏感信息熵检测（Go 特有私钥/AWS 密钥等）
- 编译安全：所有规则正则预编译缓存，单规则异常不中断其他规则

架构参照：PythonScanner / JSScanner（维持独立的 go_ 前缀实现，避免并行开发冲突）
"""

import logging
import math
import re
import fnmatch
from pathlib import Path
from typing import List, Dict, Any, Optional

from .base import BaseScanner
from ..models import ScanResult, ScanTool, Severity

# Go rules - lazy import (rules/__init__.py transitively imports models only;
# direct import avoids the server transitive chain)
try:
    from ..rules.go.rules import (
        GO_SECURITY_RULES,
        GO_SECURITY_GUARD_PATTERNS,
        GO_FALSE_POSITIVE_RULES,
    )
except ImportError:
    GO_SECURITY_RULES = []
    GO_SECURITY_GUARD_PATTERNS = {}
    GO_FALSE_POSITIVE_RULES = []

logger = logging.getLogger(__name__)

# Go 文件扩展名
GO_EXTENSIONS = {".go"}

# 上下文窗口半径（命中行前后各 5 行）
GO_GUARD_WINDOW = 5

# Severity 映射
SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

# Go 特有敏感信息模式
GO_SENSITIVE_PATTERNS = {
    "aws_access_key": (r"AKIA[0-9A-Z]{16}", Severity.CRITICAL),
    "private_key": (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", Severity.CRITICAL),
    "google_api_key": (r"AIza[0-9A-Za-z_-]{35}", Severity.HIGH),
    "slack_token": (r"xox[baprs]-[0-9a-zA-Z-]{10,}", Severity.HIGH),
    "github_token": (r"gh[pousr]_[A-Za-z0-9_]{36,}", Severity.HIGH),
    "jwt_token": (r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+", Severity.MEDIUM),
    "password_in_url": (r"://[^:]+:[^@]+@", Severity.HIGH),
}

# category -> GO_SECURITY_GUARD_PATTERNS guard 组映射（v2.3.0）
CATEGORY_GUARD_GROUPS = {
    "COMMAND_INJECTION": ["command_injection"],
    "PATH_TRAVERSAL": ["path_traversal"],
    "SSRF": ["ssrf"],
    "SQL_INJECTION": ["sql_injection"],
    "SECRETS": ["secrets"],
    "CRYPTO": ["crypto"],
}


class GoScanner(BaseScanner):
    """Go 专用安全扫描器 v2.3.0"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.timeout = self.config.get("timeout", 300)
        self.check_secrets = self.config.get("check_hardcoded_secrets", True)
        self.use_window_guard = self.config.get("window_guard", True)
        self._file_cache: Dict[str, str] = {}
        self._compiled: Dict[str, Any] = {}
        self._preprocess_warnings: List[str] = []

    def get_tool_type(self) -> ScanTool:
        return ScanTool.GO_SCANNER

    async def scan(
        self,
        target_path: str,
        language: Optional[str] = None,
        **kwargs,
    ) -> List[ScanResult]:
        """扫描目标路径中的 Go 文件"""
        results: List[ScanResult] = []
        self._preprocess_warnings.clear()
        target = Path(target_path)

        if target.is_file():
            files = [target]
        elif target.is_dir():
            files = self._collect_go_files(target)
        else:
            logger.warning(f"Target path does not exist: {target_path}")
            return []

        logger.info(f"Scanning {len(files)} Go files")

        # 1. 自定义规则扫描
        rule_results = await self._scan_with_rules(files)
        results.extend(rule_results)

        # 2. 敏感信息检测
        if self.check_secrets:
            secret_results = await self._scan_secrets(files)
            results.extend(secret_results)

        logger.info(f"Go Scanner found {len(results)} issues")
        return results

    def _collect_go_files(self, directory: Path) -> List[Path]:
        """收集目录中的 Go 文件"""
        files = []
        skip_dirs = {
            ".git", "vendor", "node_modules", "dist", "build",
            ".cache", "third_party", "testdata",
        }

        for path in directory.rglob("*.go"):
            if any(skip in path.parts for skip in skip_dirs):
                continue
            if path.is_file():
                files.append(path)

        return files

    async def _scan_with_rules(self, files: List[Path]) -> List[ScanResult]:
        """使用自定义规则扫描文件（每条规则独立容错，坏规则不中断其他规则）"""
        results: List[ScanResult] = []

        for file_path in files:
            try:
                content = self._read_file(file_path)
                if not content:
                    continue

                # 文件模式误报检查
                if self._is_false_positive_file(str(file_path)):
                    continue

                lines = content.split("\n")
                for rule in GO_SECURITY_RULES:
                    try:
                        # 文件模式匹配
                        if rule.file_pattern and not self._match_file_pattern(
                            str(file_path), rule.file_pattern
                        ):
                            continue

                        # 代码模式匹配
                        if not rule.code_pattern:
                            continue

                        pattern = self._get_compiled(rule)
                        if pattern is None:
                            continue

                        for line_num, line in enumerate(lines, 1):
                            if not pattern.search(line):
                                continue

                            # 行内误报指标检查
                            if self._check_false_positive_indicators(
                                line, rule.false_positive_indicators
                            ):
                                continue

                            # 上下文窗口 guard
                            if self.use_window_guard and self._suppressed_by_guard(
                                lines, line_num - 1, rule.category
                            ):
                                logger.debug(
                                    f"Finding suppressed by guard: {rule.rule_id} "
                                    f"{file_path}:{line_num}"
                                )
                                continue

                            results.append(ScanResult(
                                tool=ScanTool.GOSEC,
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
                                    "scanner": "go_scanner",
                                },
                            ))
                    except re.error as e:
                        logger.warning(f"Bad regex in rule {rule.rule_id}: {e}")
                        continue
                    except Exception as e:
                        logger.warning(
                            f"Rule {getattr(rule, 'rule_id', '?')} failed on "
                            f"{file_path}, skipped: {e}"
                        )
                        continue
            except Exception as e:
                logger.error(f"Error scanning {file_path}: {e}")

        return results

    def _get_compiled(self, rule) -> Optional[re.Pattern]:
        """缓存编译后的正则（进程级缓存）；非法正则返回 None"""
        if rule.rule_id not in self._compiled:
            try:
                self._compiled[rule.rule_id] = re.compile(
                    rule.code_pattern, re.IGNORECASE
                )
            except re.error as e:
                logger.warning(f"Invalid rule regex skipped: {e}: {rule.code_pattern!r}")
                self._compiled[rule.rule_id] = None
        return self._compiled[rule.rule_id]

    def _suppressed_by_guard(
        self, lines: List[str], line_idx: int, category: Optional[str]
    ) -> bool:
        """上下文窗口 guard（v2.3.0）

        取命中行前后 GO_GUARD_WINDOW 行窗口文本，按 rule.category 映射到
        GO_SECURITY_GUARD_PATTERNS 对应 guard 组；窗口内命中任一 guard 模式则认为该处已有防护。
        """
        if not category:
            return False
        guard_sources = [
            src
            for group in CATEGORY_GUARD_GROUPS.get(category, [])
            for src in GO_SECURITY_GUARD_PATTERNS.get(group, [])
        ]
        if not guard_sources:
            return False

        start = max(0, line_idx - GO_GUARD_WINDOW)
        end = min(len(lines), line_idx + GO_GUARD_WINDOW + 1)
        window_text = "\n".join(lines[start:end])

        for src in guard_sources:
            try:
                if re.search(src, window_text, re.IGNORECASE):
                    return True
            except re.error:
                continue
        return False

    def _is_false_positive_file(self, file_path: str) -> bool:
        """检查文件是否匹配误报文件模式"""
        for fp_rule in GO_FALSE_POSITIVE_RULES:
            if fp_rule.file_pattern and self._match_file_pattern(
                file_path, fp_rule.file_pattern
            ):
                return True
        return False

    async def _scan_secrets(self, files: List[Path]) -> List[ScanResult]:
        """扫描 Go 代码中的敏感信息"""
        results: List[ScanResult] = []

        for file_path in files:
            try:
                content = self._read_file(file_path)
                if not content:
                    continue

                lines = content.split("\n")
                for line_num, line in enumerate(lines, 1):
                    # 跳过注释行
                    stripped = line.strip()
                    if stripped.startswith("//"):
                        continue

                    for secret_name, (pattern, severity) in GO_SENSITIVE_PATTERNS.items():
                        if re.search(pattern, line, re.IGNORECASE):
                            entropy = self._calculate_entropy(line)

                            # 跳过明显假密码
                            if self._is_obvious_fake_password(line):
                                continue

                            metadata = {
                                "category": "SECRETS",
                                "confidence": min(entropy / 5.0, 1.0),
                                "entropy": entropy,
                                "scanner": "go_scanner",
                            }
                            results.append(ScanResult(
                                tool=ScanTool.GOSEC,
                                rule_id=f"go.secrets.{secret_name}",
                                file=str(file_path),
                                line=line_num,
                                code=stripped[:200],
                                severity=severity,
                                message=f"Potential {secret_name.replace('_', ' ')} detected",
                                cwe="CWE-798",
                                owasp="A07:2021 - Identification and Authentication Failures",
                                metadata=metadata,
                            ))
            except Exception as e:
                logger.error(f"Error scanning secrets in {file_path}: {e}")

        return results

    @staticmethod
    def _is_obvious_fake_password(line: str) -> bool:
        """跳过明显的假密码"""
        fake_patterns = [
            r"""["'](?:test|example|123456|admin|password|changeme|secret|foo|bar)["']""",
            r"""["']\*+["']""",
            r"""["']xxx["']""",
            r"""["']??\?["']""",
        ]
        for fp in fake_patterns:
            if re.search(fp, line, re.IGNORECASE):
                return True
        return False

    def _read_file(self, file_path: Path) -> Optional[str]:
        """读取文件内容（带缓存）"""
        path_str = str(file_path)
        if path_str in self._file_cache:
            return self._file_cache[path_str]

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            self._file_cache[path_str] = content
            return content
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return None

    @staticmethod
    def _match_file_pattern(file_path: str, pattern: str) -> bool:
        """匹配文件路径模式（支持 | 分隔多模式）"""
        patterns = pattern.split("|") if "|" in pattern else [pattern]
        return any(fnmatch.fnmatch(file_path.lower(), p.lower()) for p in patterns)

    @staticmethod
    def _check_false_positive_indicators(
        line: str, indicators: List[str]
    ) -> bool:
        """检查误报指标"""
        if not indicators:
            return False
        for indicator in indicators:
            if indicator.lower() in line.lower():
                return True
        return False

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """计算字符串的信息熵"""
        if not text:
            return 0.0

        freq: Dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    def clear_cache(self):
        """清除缓存"""
        self._file_cache.clear()
        self._compiled.clear()
