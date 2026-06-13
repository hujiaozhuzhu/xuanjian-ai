"""
Bandit 扫描器

Python 专用安全扫描
"""

import asyncio
import json
import logging
from typing import List, Dict, Any, Optional
from . import BaseScanner
from ..models import ScanResult, ScanTool, Severity


logger = logging.getLogger(__name__)

BANDIT_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNDEFINED": Severity.INFO,
}


class BanditScanner(BaseScanner):
    """Bandit 扫描器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.timeout = self.config.get("timeout", 300)

    def get_tool_type(self) -> ScanTool:
        return ScanTool.BANDIT

    async def scan(
        self,
        target_path: str,
        config_file: Optional[str] = None,
        **kwargs
    ) -> List[ScanResult]:
        """使用 Bandit 扫描 Python 代码"""
        cmd = ["bandit", "-f", "json", "-r"]

        if config_file:
            cmd.extend(["-c", config_file])

        # 忽略路径
        for p in self.config.get("ignore_paths", []):
            cmd.extend(["--exclude", p])

        cmd.append(target_path)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )

            return self._parse_output(stdout.decode())
        except FileNotFoundError:
            logger.error("Bandit not found. Please install: pip install bandit")
            return []
        except asyncio.TimeoutError:
            logger.error(f"Bandit scan timed out after {self.timeout}s")
            return []
        except Exception as e:
            logger.error(f"Bandit scan failed: {e}")
            return []

    def _parse_output(self, output: str) -> List[ScanResult]:
        """解析 Bandit JSON 输出"""
        results = []
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            logger.error("Failed to parse Bandit JSON output")
            return []

        for item in data.get("results", []):
            try:
                severity_str = item.get("issue_severity", "MEDIUM")
                severity = BANDIT_SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

                result = ScanResult(
                    id=self._generate_id(
                        "bandit",
                        item.get("test_id", "unknown"),
                        item.get("filename", ""),
                        item.get("line_number", 0),
                    ),
                    tool=ScanTool.BANDIT,
                    rule_id=f"bandit/{item.get('test_id', 'unknown')}/{item.get('test_name', 'unknown')}",
                    file=item.get("filename", ""),
                    line=item.get("line_number", 0),
                    column=item.get("col_offset"),
                    code=item.get("code", ""),
                    severity=severity,
                    message=item.get("issue_text", ""),
                    cwe=f"CWE-{item.get('issue_cwe', {}).get('id', '')}" if item.get("issue_cwe") else None,
                    metadata={
                        "test_id": item.get("test_id"),
                        "test_name": item.get("test_name"),
                        "confidence": item.get("issue_confidence"),
                    },
                )
                results.append(result)
            except Exception as e:
                logger.warning(f"Failed to parse Bandit result: {e}")

        return results
