"""
Semgrep 扫描器

支持 Java 和 Python 的 Semgrep 扫描集成
"""

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional
from . import BaseScanner
from ..models import ScanResult, ScanTool, Severity


logger = logging.getLogger(__name__)

# Severity 映射
SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# Java 安全规则集
JAVA_SECURITY_RULESETS = [
    "p/java",
    "p/owasp-java",
    "p/security-audit",
    "p/secrets",
]

# Python 安全规则集
PYTHON_SECURITY_RULESETS = [
    "p/python",
    "p/owasp-python",
    "p/security-audit",
    "p/bandit",
]

# JavaScript/TypeScript 安全规则集
JAVASCRIPT_SECURITY_RULESETS = [
    "p/javascript",
    "p/typescript",
    "p/owasp-top-ten",
    "p/security-audit",
]

# Go 安全规则集 (v2.3.0)
GO_SECURITY_RULESETS = [
    "p/golang",
    "p/owasp-top-ten",
    "p/security-audit",
    "p/secrets",
    "p/r2c-security-audit",
    "p/command-injection",
    "p/insecure-transport",
    "p/sql-injection",
]

# PHP 安全规则集 (v2.5.1)
PHP_SECURITY_RULESETS = [
    "p/php",
    "p/security-audit",
    "p/secrets",
]


def _builtin_rule_path(filename: str) -> Optional[str]:
    """Resolve a bundled Semgrep YAML rule file shipped with fp-sentinel."""
    rules_dir = Path(__file__).resolve().parent.parent / "rules" / "semgrep"
    candidate = rules_dir / filename
    return str(candidate) if candidate.is_file() else None


# P1-Fix: 反序列化专项 Semgrep 规则（Python pickle + PHP Phar 触发点）
DESER_RULE_FILES = (
    _builtin_rule_path("python-deserialization-rules.yaml"),
    _builtin_rule_path("php-phar-deserialization-rules.yaml"),
)


class SemgrepScanner(BaseScanner):
    """Semgrep 扫描器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.timeout = self.config.get("timeout", 300)
        self.max_memory = self.config.get("max_memory", 512)
        self.jobs = self.config.get("jobs", 2)
        self.available = shutil.which("semgrep") is not None
        self.unavailable_reason: Optional[str] = None
        if not self.available:
            self.unavailable_reason = "Semgrep 未安装；高级规则未启用。安装命令: pip install fp-sentinel[scanners]"
            logger.warning(self.unavailable_reason)

    def get_tool_type(self) -> ScanTool:
        return ScanTool.SEMGREP

    async def scan(
        self,
        target_path: str,
        language: Optional[str] = None,
        rulesets: Optional[List[str]] = None,
        config_files: Optional[List[str]] = None,
        **kwargs
    ) -> List[ScanResult]:
        """
        使用 Semgrep 扫描目标路径

        Args:
            target_path: 目标路径
            language: 语言(java/python/go)
            rulesets: 规则集列表
            config_files: 自定义规则文件列表

        Returns:
            List[ScanResult]: 扫描结果
        """
        if not self.available:
            logger.warning(self.unavailable_reason)
            return []

        cmd = self._build_command(
            target_path, language, rulesets, config_files
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )

            if proc.returncode not in (0, 1):
                logger.warning(f"Semgrep exited with code {proc.returncode}: {stderr.decode()}")
                return []

            return self._parse_output(stdout.decode())

        except FileNotFoundError:
            self.available = False
            self.unavailable_reason = "Semgrep 未安装；高级规则未启用。安装命令: pip install fp-sentinel[scanners]"
            logger.warning(self.unavailable_reason)
            return []
        except asyncio.TimeoutError:
            logger.error(f"Semgrep scan timed out after {self.timeout}s")
            return []
        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}")
            return []

    def _build_command(
        self,
        target_path: str,
        language: Optional[str],
        rulesets: Optional[List[str]],
        config_files: Optional[List[str]],
    ) -> List[str]:
        """构建 Semgrep 命令

        v2.5.1 P0-Fix: 修复 --config 与 --lang 参数冲突。
        Semgrep 不允许 --config 和 --lang 同时出现：当指定 --config 时，
        Semgrep 从规则声明中推断语言；--lang 仅在不提供任何 --config 的
        纯语言过滤模式下使用。重构逻辑确保二者互斥。
        """
        cmd = ["semgrep", "scan", "--json", "--quiet"]

        # 设置并行数
        cmd.extend(["--jobs", str(self.jobs)])

        # 收集所有 --config 条目
        config_entries: List[str] = []

        if config_files:
            config_entries.extend(config_files)
        elif rulesets:
            config_entries.extend(rulesets)
        else:
            # 使用默认规则集 (v2.3.0 新增 Go 规则集路由; v2.5.1 新增 PHP)
            default_rulesets = {
                "java": JAVA_SECURITY_RULESETS,
                "javascript": JAVASCRIPT_SECURITY_RULESETS,
                "typescript": JAVASCRIPT_SECURITY_RULESETS,
                "go": GO_SECURITY_RULESETS,
                "php": PHP_SECURITY_RULESETS,
            }.get(language, PYTHON_SECURITY_RULESETS)
            config_entries.extend(default_rulesets)

        # v2.5.1 P0-Fix: 按语言过滤反序列化专项规则，避免规则与语言不匹配
        for builtin_rule in DESER_RULE_FILES:
            if not builtin_rule:
                continue
            # 仅追加与当前语言匹配的反序列化规则
            if language == "python" and "python-deserialization" in builtin_rule:
                config_entries.append(builtin_rule)
            elif language == "php" and "php-phar-deserialization" in builtin_rule:
                config_entries.append(builtin_rule)
            elif language in (None, "auto"):
                # auto 模式保留全部（向后兼容）
                config_entries.append(builtin_rule)

        # 添加 --config 参数
        for entry in config_entries:
            cmd.extend(["--config", entry])

        # v2.5.1 P0-Fix: 仅在没有 --config 时才使用 --lang
        # Semgrep CLI 不支持同时传入 --config 和 --lang
        if not config_entries and language and language != "auto":
            cmd.extend(["--lang", language])

        # 忽略路径
        ignore_paths = self.config.get("ignore_paths", [])
        for p in ignore_paths:
            cmd.extend(["--exclude", p])

        cmd.append(target_path)
        return cmd

    def _parse_output(self, output: str) -> List[ScanResult]:
        """解析 Semgrep JSON 输出"""
        results = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            logger.error("Failed to parse Semgrep JSON output")
            return []

        for item in data.get("results", []):
            try:
                severity_str = item.get("extra", {}).get("severity", "WARNING")
                severity = SEMGREP_SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

                # 提取 CWE
                metadata = item.get("extra", {}).get("metadata", {})
                cwe = None
                if "cwe" in metadata:
                    cwe_list = metadata["cwe"]
                    if isinstance(cwe_list, list) and cwe_list:
                        cwe = cwe_list[0] if isinstance(cwe_list[0], str) else cwe_list[0].get("id")
                    elif isinstance(cwe_list, str):
                        cwe = cwe_list

                # 提取 OWASP
                owasp = None
                if "owasp" in metadata:
                    owasp_list = metadata["owasp"]
                    if isinstance(owasp_list, list) and owasp_list:
                        owasp = owasp_list[0]

                result = ScanResult(
                    id=self._generate_id(
                        "semgrep",
                        item.get("check_id", "unknown"),
                        item.get("path", ""),
                        item.get("start", {}).get("line", 0),
                    ),
                    tool=ScanTool.SEMGREP,
                    rule_id=item.get("check_id", "unknown"),
                    file=item.get("path", ""),
                    line=item.get("start", {}).get("line", 0),
                    column=item.get("start", {}).get("col"),
                    end_line=item.get("end", {}).get("line"),
                    code=item.get("extra", {}).get("lines", ""),
                    severity=severity,
                    message=item.get("extra", {}).get("message", ""),
                    cwe=cwe,
                    owasp=owasp,
                    metadata=metadata,
                )
                results.append(result)
            except Exception as e:
                logger.warning(f"Failed to parse Semgrep result: {e}")

        return results
