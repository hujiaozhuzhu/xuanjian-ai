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
from ..rules.js import JS_SECURITY_RULES, JS_RULES_INDEX

logger = logging.getLogger(__name__)

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
        """使用自定义规则扫描文件"""
        results = []

        for file_path in files:
            try:
                content = self._read_file(file_path)
                if not content:
                    continue

                lines = content.split("\n")
                for rule in JS_SECURITY_RULES:
                    # 文件模式匹配
                    if rule.file_pattern and not self._match_file_pattern(
                        str(file_path), rule.file_pattern
                    ):
                        continue

                    # 代码模式匹配
                    if rule.code_pattern:
                        pattern = re.compile(rule.code_pattern, re.IGNORECASE)
                        for line_num, line in enumerate(lines, 1):
                            if pattern.search(line):
                                # 检查误报指标
                                if self._check_false_positive_indicators(
                                    line, rule.false_positive_indicators
                                ):
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
                logger.error(f"Error scanning {file_path}: {e}")

        return results

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
