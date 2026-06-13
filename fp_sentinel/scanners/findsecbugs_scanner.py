"""
FindSecBugs/SpotBugs 扫描器

Java 专用安全扫描，通过 SpotBugs + FindSecBugs 插件进行字节码分析
"""

import asyncio
import json
import logging
import os
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from . import BaseScanner
from ..models import ScanResult, ScanTool, Severity


logger = logging.getLogger(__name__)

# FindSecBugs bug pattern -> Severity 映射
FINDSECBUGS_SEVERITY_MAP = {
    "1": Severity.CRITICAL,
    "2": Severity.HIGH,
    "3": Severity.MEDIUM,
    "4": Severity.LOW,
    "5": Severity.INFO,
}

# FindSecBugs category -> CWE 映射
FINDSECBUGS_CWE_MAP = {
    "SQL_INJECTION": "CWE-89",
    "XSS": "CWE-79",
    "COMMAND_INJECTION": "CWE-78",
    "PATH_TRAVERSAL": "CWE-22",
    "XXE": "CWE-611",
    "SSRF": "CWE-918",
    "DESERIALIZATION": "CWE-502",
    "CRYPTO": "CWE-327",
    "HARDCODED_PASSWORD": "CWE-798",
    "HARDCODED_KEY": "CWE-321",
    "WEAK_CRYPTO": "CWE-327",
    "INSECURE_RANDOM": "CWE-330",
    "REDOS": "CWE-1333",
    "LDAP_INJECTION": "CWE-90",
    "XPATH_INJECTION": "CWE-643",
    "LOG_INJECTION": "CWE-117",
    "UNVALIDATED_REDIRECT": "CWE-601",
    "SPRING_CSRF": "CWE-352",
}


class FindSecBugsScanner(BaseScanner):
    """FindSecBugs/SpotBugs 扫描器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.spotbugs_path = self.config.get("spotbugs_path", "spotbugs")
        self.findsecbugs_jar = self.config.get("findsecbugs_jar", "")
        self.timeout = self.config.get("timeout", 600)
        self.effort = self.config.get("effort", "max")
        self.report_format = self.config.get("report_format", "xml")

    def get_tool_type(self) -> ScanTool:
        return ScanTool.FINDSECBUGS

    async def scan(
        self,
        target_path: str,
        classpath: Optional[str] = None,
        source_path: Optional[str] = None,
        **kwargs
    ) -> List[ScanResult]:
        """
        使用 SpotBugs + FindSecBugs 扫描 Java 字节码

        Args:
            target_path: 编译后的 class 文件或 JAR 路径
            classpath: 额外 classpath
            source_path: 源代码路径（用于定位源文件）

        Returns:
            List[ScanResult]: 扫描结果
        """
        # 先编译（如果需要）
        if target_path.endswith(".java") or os.path.isdir(target_path):
            compiled_path = await self._compile_java(target_path, classpath)
            if not compiled_path:
                logger.error("Java compilation failed")
                return []
            target_path = compiled_path

        cmd = self._build_command(target_path, classpath)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )

            # FindSecBugs 输出 XML 到临时文件
            report_path = self._get_report_path(target_path)
            if os.path.exists(report_path):
                results = self._parse_xml_report(report_path, source_path)
                os.remove(report_path)
                return results
            else:
                logger.warning(f"FindSecBugs report not found: {report_path}")
                return []

        except FileNotFoundError:
            logger.error("SpotBugs not found. Please install SpotBugs with FindSecBugs plugin")
            return []
        except asyncio.TimeoutError:
            logger.error(f"FindSecBugs scan timed out after {self.timeout}s")
            return []
        except Exception as e:
            logger.error(f"FindSecBugs scan failed: {e}")
            return []

    async def _compile_java(
        self, source_path: str, classpath: Optional[str]
    ) -> Optional[str]:
        """编译 Java 源码"""
        output_dir = "/tmp/fp_sentinel_classes"
        os.makedirs(output_dir, exist_ok=True)

        cmd = ["javac", "-d", output_dir]
        if classpath:
            cmd.extend(["-cp", classpath])

        # 收集所有 .java 文件
        java_files = []
        if os.path.isfile(source_path) and source_path.endswith(".java"):
            java_files.append(source_path)
        elif os.path.isdir(source_path):
            for root, _, files in os.walk(source_path):
                for f in files:
                    if f.endswith(".java"):
                        java_files.append(os.path.join(root, f))

        if not java_files:
            logger.error("No Java source files found")
            return None

        cmd.extend(java_files)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                logger.error(f"Java compilation failed: {stderr.decode()}")
                return None

            return output_dir
        except Exception as e:
            logger.error(f"Java compilation error: {e}")
            return None

    def _build_command(
        self, target_path: str, classpath: Optional[str]
    ) -> List[str]:
        """构建 SpotBugs 命令"""
        cmd = [self.spotbugs_path]

        # 设置报告格式
        report_path = self._get_report_path(target_path)
        cmd.extend(["-xml:withMessages", "-output", report_path])

        # 设置 effort
        cmd.extend(["-effort", self.effort])

        # 添加 FindSecBugs 插件
        if self.findsecbugs_jar and os.path.exists(self.findsecbugs_jar):
            cmd.extend(["-pluginList", self.findsecbugs_jar])

        # 设置 classpath
        if classpath:
            cmd.extend(["-classpath", classpath])

        # 只启用安全相关 bug category
        cmd.extend(["-onlyAnalyze", "com.h3xstream.findsecbugs.*"])

        cmd.append(target_path)
        return cmd

    def _get_report_path(self, target_path: str) -> str:
        """获取报告输出路径"""
        return f"/tmp/fp_sentinel_findsecbugs_report.xml"

    def _parse_xml_report(
        self, report_path: str, source_path: Optional[str]
    ) -> List[ScanResult]:
        """解析 SpotBugs XML 报告"""
        results = []

        try:
            tree = ET.parse(report_path)
            root = tree.getroot()

            for bug_instance in root.findall(".//BugInstance"):
                try:
                    # 提取 bug 信息
                    bug_type = bug_instance.get("type", "UNKNOWN")
                    category = bug_instance.get("category", "SECURITY")
                    priority = bug_instance.get("priority", "3")

                    # 提取位置信息
                    source_line = bug_instance.find(".//SourceLine")
                    if source_line is None:
                        continue

                    file_path = source_line.get("sourcepath", "")
                    start_line = int(source_line.get("start", "0"))
                    end_line = int(source_line.get("end", "0"))

                    # 如果有源代码路径，尝试定位源文件
                    if source_path and file_path:
                        full_path = os.path.join(source_path, file_path)
                        if os.path.exists(full_path):
                            file_path = full_path

                    # 提取消息
                    message_elem = bug_instance.find(".//LongMessage")
                    message = message_elem.text if message_elem is not None else bug_type

                    short_msg = bug_instance.find(".//ShortMessage")
                    short_message = short_msg.text if short_msg is not None else ""

                    # 映射严重程度
                    severity = FINDSECBUGS_SEVERITY_MAP.get(priority, Severity.MEDIUM)

                    # 映射 CWE
                    cwe = FINDSECBUGS_CWE_MAP.get(category, None)

                    # 提取方法和类信息
                    method = bug_instance.find(".//Method")
                    class_elem = bug_instance.find(".//Class")
                    method_name = method.get("name", "") if method is not None else ""
                    class_name = class_elem.get("name", "") if class_elem is not None else ""

                    result = ScanResult(
                        id=self._generate_id(
                            "findsecbugs", bug_type, file_path, start_line
                        ),
                        tool=ScanTool.FINDSECBUGS,
                        rule_id=f"findsecbugs/{category}/{bug_type}",
                        file=file_path,
                        line=start_line,
                        end_line=end_line,
                        code="",  # FindSecBugs 不直接提供代码片段
                        severity=severity,
                        message=f"[{short_message}] {message}",
                        cwe=cwe,
                        metadata={
                            "bug_type": bug_type,
                            "category": category,
                            "class": class_name,
                            "method": method_name,
                            "priority": priority,
                        },
                    )
                    results.append(result)
                except Exception as e:
                    logger.warning(f"Failed to parse FindSecBugs bug instance: {e}")

        except ET.ParseError as e:
            logger.error(f"Failed to parse FindSecBugs XML report: {e}")
        except Exception as e:
            logger.error(f"Error reading FindSecBugs report: {e}")

        return results
