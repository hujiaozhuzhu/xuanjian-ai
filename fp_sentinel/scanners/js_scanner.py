"""
JavaScript/TypeScript 专用安全扫描器

支持:
- 自定义规则模式匹配
- Semgrep JS/TS 规则扫描
- npm 依赖漏洞检查
- 敏感信息熵检测
"""

import asyncio
import json
import logging
import re
import math
from pathlib import Path
from typing import List, Dict, Any, Optional

from .base import BaseScanner
from ..models import ScanResult, ScanTool, Severity
from ..rules.js import JS_SECURITY_RULES, JS_RULES_INDEX, JS_SECURITY_GUARD_PATTERNS

logger = logging.getLogger(__name__)

# 规则 compile 缓存（进程级，pattern -> 已编译对象；编译失败缓存 None）
_RULE_COMPILE_CACHE: Dict[str, Optional["re.Pattern"]] = {}
# guard 模式 compile 缓存
_GUARD_COMPILE_CACHE: Dict[str, Optional["re.Pattern"]] = {}

# guard 上下文窗口半径（命中行前后各 6 行）
GUARD_WINDOW = 6

# rule.category -> JS_SECURITY_GUARD_PATTERNS guard 组映射（v2.1.0 A3）
CATEGORY_GUARD_GROUPS = {
    "INJECTION": ["command_injection"],
    "PATH_TRAVERSAL": ["path_traversal"],
    "SSRF": ["ssrf"],
    "SQL_INJECTION": ["sql_injection"],
    # 其余 category（XSS/AIGC/SECRETS 等）维持行内 false_positive_indicators 机制
}

# JS/TS 文件扩展名
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
TS_EXTENSIONS = {".ts", ".tsx"}

# Severity 映射
SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

# 敏感信息正则模式
SENSITIVE_PATTERNS = {
    "aws_key": (r"AKIA[0-9A-Z]{16}", Severity.CRITICAL),
    "github_token": (r"gh[pousr]_[A-Za-z0-9_]{36,}", Severity.HIGH),
    "slack_token": (r"xox[baprs]-[0-9a-zA-Z-]{10,}", Severity.HIGH),
    "jwt_token": (r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+", Severity.MEDIUM),
    "private_key": (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", Severity.CRITICAL),
    "password_in_url": (r"://[^:]+:[^@]+@", Severity.HIGH),
    "ip_address": (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", Severity.INFO),
}


class JSScanner(BaseScanner):
    """JavaScript/TypeScript 专用安全扫描器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.timeout = self.config.get("timeout", 300)
        self.check_dependencies = self.config.get("check_dependencies", True)
        self.check_secrets = self.config.get("check_hardcoded_secrets", True)
        self.ast_analysis = self.config.get("ast_analysis", False)
        self._file_cache: Dict[str, str] = {}

    def get_tool_type(self) -> ScanTool:
        return ScanTool.JS_SCANNER

    async def scan(
        self,
        target_path: str,
        language: Optional[str] = None,
        **kwargs
    ) -> List[ScanResult]:
        """扫描目标路径的 JS/TS 文件"""
        results = []
        target = Path(target_path)

        if target.is_file():
            files = [target]
        elif target.is_dir():
            files = self._collect_js_files(target)
        else:
            logger.warning(f"Target path does not exist: {target_path}")
            return []

        logger.info(f"Scanning {len(files)} JS/TS files")

        # 1. 自定义规则扫描
        rule_results = await self._scan_with_rules(files)
        results.extend(rule_results)

        # 2. 敏感信息检测
        if self.check_secrets:
            secret_results = await self._scan_secrets(files)
            results.extend(secret_results)

        # 3. npm 依赖漏洞检查
        if self.check_dependencies and target.is_dir():
            dep_results = await self._check_npm_audit(target)
            results.extend(dep_results)

        logger.info(f"JS Scanner found {len(results)} issues")
        return results

    def _collect_js_files(self, directory: Path) -> List[Path]:
        """收集目录中的 JS/TS 文件"""
        files = []
        skip_dirs = {
            "node_modules", ".git", "dist", "build", "vendor",
            ".next", ".nuxt", "coverage", "__tests__", ".cache",
        }

        for path in directory.rglob("*"):
            # 跳过特殊目录
            if any(skip in path.parts for skip in skip_dirs):
                continue
            if path.suffix.lower() in JS_EXTENSIONS and path.is_file():
                files.append(path)

        return files

    async def _scan_with_rules(self, files: List[Path]) -> List[ScanResult]:
        """使用自定义规则扫描文件

        容错策略（v2.1.0 A2）：单条规则 compile/匹配异常仅跳过该规则自身，
        不中断同文件剩余规则。
        """
        results = []

        for file_path in files:
            try:
                content = self._read_file(file_path)
                if not content:
                    continue

                lines = content.split("\n")
                for rule in JS_SECURITY_RULES:
                    try:
                        # 文件模式匹配
                        if rule.file_pattern and not self._match_file_pattern(
                            str(file_path), rule.file_pattern
                        ):
                            continue

                        # 代码模式匹配（compile 走缓存，坏正则返回 None 跳过）
                        if rule.code_pattern:
                            pattern = self._compile_rule_pattern(rule.code_pattern)
                            if pattern is None:
                                continue
                            for line_num, line in enumerate(lines, 1):
                                if not pattern.search(line):
                                    continue
                                # 行内误报指标
                                if self._check_false_positive_indicators(
                                    line, rule.false_positive_indicators
                                ):
                                    continue
                                # 上下文窗口 guard（v2.1.0 A3）
                                if self._suppressed_by_guard(
                                    lines, line_num - 1, rule.category
                                ):
                                    logger.debug(
                                        f"Finding suppressed by guard: rule={rule.rule_id} "
                                        f"file={file_path} line={line_num}"
                                    )
                                    continue

                                results.append(ScanResult(
                                    tool=ScanTool.JS_SCANNER,
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
                                        "scanner": "js_scanner",
                                    },
                                ))
                    except Exception as e:
                        # per-rule 容错：坏规则只影响自身
                        logger.warning(
                            f"Rule {getattr(rule, 'rule_id', '?')} failed on "
                            f"{file_path}, skipped: {e}"
                        )
                        continue
            except Exception as e:
                logger.error(f"Error scanning {file_path}: {e}")

        return results

    @staticmethod
    def _compile_rule_pattern(pattern: str) -> Optional["re.Pattern"]:
        """编译规则正则（带进程级缓存）；非法正则返回 None 并告警"""
        if pattern not in _RULE_COMPILE_CACHE:
            try:
                _RULE_COMPILE_CACHE[pattern] = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                logger.warning(f"Invalid rule regex skipped: {e}: {pattern!r}")
                _RULE_COMPILE_CACHE[pattern] = None
        return _RULE_COMPILE_CACHE[pattern]

    def _suppressed_by_guard(
        self, lines: List[str], line_idx: int, category: Optional[str]
    ) -> bool:
        """上下文窗口 guard（v2.1.0 A3）

        取命中行前后 GUARD_WINDOW 行窗口文本，按 rule.category 映射到
        JS_SECURITY_GUARD_PATTERNS 对应 guard 组；窗口内命中任一 guard
        模式则认为该处已有防护，抑制报告。
        """
        if not category:
            return False
        guard_sources = [
            src
            for group in CATEGORY_GUARD_GROUPS.get(category, [])
            for src in JS_SECURITY_GUARD_PATTERNS.get(group, [])
        ]
        if not guard_sources:
            return False

        start = max(0, line_idx - GUARD_WINDOW)
        end = min(len(lines), line_idx + GUARD_WINDOW + 1)
        window_text = "\n".join(lines[start:end])

        for src in guard_sources:
            if src not in _GUARD_COMPILE_CACHE:
                try:
                    _GUARD_COMPILE_CACHE[src] = re.compile(src, re.IGNORECASE)
                except re.error as e:
                    logger.warning(f"Invalid guard pattern skipped: {e}: {src!r}")
                    _GUARD_COMPILE_CACHE[src] = None
            pattern = _GUARD_COMPILE_CACHE[src]
            if pattern and pattern.search(window_text):
                return True
        return False

    async def _scan_secrets(self, files: List[Path]) -> List[ScanResult]:
        """扫描敏感信息"""
        results = []

        for file_path in files:
            try:
                content = self._read_file(file_path)
                if not content:
                    continue

                lines = content.split("\n")
                for line_num, line in enumerate(lines, 1):
                    # 跳过注释行
                    stripped = line.strip()
                    if stripped.startswith("//") or stripped.startswith("*"):
                        continue

                    for secret_name, (pattern, severity) in SENSITIVE_PATTERNS.items():
                        if re.search(pattern, line, re.IGNORECASE):
                            # 计算信息熵
                            entropy = self._calculate_entropy(line)
                            if entropy < 3.0 and secret_name == "ip_address":
                                continue  # 低熵IP地址跳过

                            results.append(ScanResult(
                                tool=ScanTool.JS_SCANNER,
                                rule_id=f"js.secrets.{secret_name}",
                                file=str(file_path),
                                line=line_num,
                                code=stripped[:200],
                                severity=severity,
                                message=f"Potential {secret_name.replace('_', ' ')} detected",
                                cwe="CWE-798",
                                metadata={
                                    "category": "SECRETS",
                                    "confidence": min(entropy / 5.0, 1.0),
                                    "entropy": entropy,
                                    "scanner": "js_scanner",
                                },
                            ))
            except Exception as e:
                logger.error(f"Error scanning secrets in {file_path}: {e}")

        return results

    async def _check_npm_audit(self, project_dir: Path) -> List[ScanResult]:
        """检查 npm 依赖漏洞"""
        results = []
        package_json = project_dir / "package.json"

        if not package_json.exists():
            return results

        try:
            proc = await asyncio.create_subprocess_exec(
                "npm", "audit", "--json",
                cwd=str(project_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )

            if proc.returncode in (0, 1):
                data = json.loads(stdout.decode())
                for vuln_id, vuln in data.get("vulnerabilities", {}).items():
                    severity_str = vuln.get("severity", "info").upper()
                    results.append(ScanResult(
                        tool=ScanTool.JS_SCANNER,
                        rule_id=f"js.dependency.{vuln_id}",
                        file=str(package_json),
                        line=0,
                        message=f"Vulnerable dependency: {vuln_id} - {vuln.get('title', 'N/A')}",
                        severity=SEVERITY_MAP.get(severity_str, Severity.INFO),
                        cwe=vuln.get("cwe", [None])[0] if vuln.get("cwe") else None,
                        metadata={
                            "category": "DEPENDENCY",
                            "via": vuln.get("via", []),
                            "range": vuln.get("range", ""),
                            "scanner": "js_scanner",
                        },
                    ))
        except FileNotFoundError:
            logger.debug("npm not found, skipping dependency check")
        except asyncio.TimeoutError:
            logger.warning("npm audit timed out")
        except Exception as e:
            logger.error(f"npm audit failed: {e}")

        return results

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

    def _match_file_pattern(self, file_path: str, pattern: str) -> bool:
        """匹配文件路径模式"""
        import fnmatch
        return fnmatch.fnmatch(file_path.lower(), pattern.lower())

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

    def _calculate_entropy(self, text: str) -> float:
        """计算字符串的信息熵"""
        if not text:
            return 0.0

        freq = {}
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
        """清除文件缓存"""
        self._file_cache.clear()
