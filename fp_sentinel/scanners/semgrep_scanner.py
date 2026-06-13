"""
Semgrep 扫描器

支持 Java 和 Python 的 Semgrep 扫描集成
"""

import asyncio
import json
import logging
import subprocess
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


class SemgrepScanner(BaseScanner):
    """Semgrep 扫描器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.timeout = self.config.get("timeout", 300)
        self.max_memory = self.config.get("max_memory", 512)
        self.jobs = self.config.get("jobs", 2)

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
            logger.error("Semgrep not found. Please install: pip install semgrep")
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
        """构建 Semgrep 命令"""
        cmd = ["semgrep", "scan", "--json", "--quiet"]

        # 设置并行数
        cmd.extend(["--jobs", str(self.jobs)])

        # 设置规则
        if config_files:
            for f in config_files:
                cmd.extend(["--config", f])
        elif rulesets:
            for r in rulesets:
                cmd.extend(["--config", r])
        else:
            # 使用默认规则集
            default_rulesets = (
                JAVA_SECURITY_RULESETS
                if language == "java"
                else PYTHON_SECURITY_RULESETS
            )
            for r in default_rulesets:
                cmd.extend(["--config", r])

        # 语言过滤
        if language and language != "auto":
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
