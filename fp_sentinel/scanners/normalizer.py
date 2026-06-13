"""
扫描结果归一化器

将不同扫描器的输出统一为 Finding 模型
"""

import hashlib
import logging
import re
from typing import List, Optional

from ..models import Finding, ScanResult, scan_result_to_finding

logger = logging.getLogger(__name__)


class ResultNormalizer:
    """
    扫描结果归一化器

    职责:
    1. 将 ScanResult（扫描器原始输出）转换为统一的 Finding 模型
    2. 生成结果指纹（fingerprint），用于去重和历史匹配
    3. 规范化 severity / category / language 等字段
    """

    # Java 漏洞类别 -> CWE 映射
    JAVA_CWE_CATEGORY_MAP = {
        "CWE-89": "SQL_INJECTION",
        "CWE-79": "XSS",
        "CWE-78": "COMMAND_INJECTION",
        "CWE-22": "PATH_TRAVERSAL",
        "CWE-611": "XXE",
        "CWE-918": "SSRF",
        "CWE-502": "DESERIALIZATION",
        "CWE-327": "CRYPTO",
        "CWE-798": "HARDCODED_CREDENTIALS",
        "CWE-321": "HARDCODED_KEY",
        "CWE-330": "INSECURE_RANDOM",
        "CWE-1333": "REDOS",
        "CWE-90": "LDAP_INJECTION",
        "CWE-643": "XPATH_INJECTION",
        "CWE-117": "LOG_INJECTION",
        "CWE-601": "UNVALIDATED_REDIRECT",
        "CWE-352": "CSRF",
        "CWE-200": "INFORMATION_EXPOSURE",
        "CWE-287": "AUTHENTICATION",
        "CWE-862": "AUTHORIZATION",
    }

    # 语言扩展名映射
    EXTENSION_LANGUAGE_MAP = {
        ".java": "java",
        ".py": "python",
        ".go": "go",
        ".js": "javascript",
        ".ts": "typescript",
        ".kt": "kotlin",
        ".scala": "scala",
        ".xml": "xml",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
    }

    def normalize_scan_result(self, result: ScanResult) -> Finding:
        """
        将单条 ScanResult 归一化为 Finding

        Args:
            result: 扫描器原始结果

        Returns:
            Finding: 归一化后的 Finding
        """
        finding = scan_result_to_finding(result)

        # 补充 category
        if not finding.category and finding.cwe:
            finding.category = self.JAVA_CWE_CATEGORY_MAP.get(finding.cwe)

        # 推断语言
        if not finding.language:
            finding.language = self._infer_language(finding.file_path)

        # 生成指纹
        finding.fingerprint = self.compute_fingerprint(finding)

        # 从 metadata 中提取 confidence
        if finding.confidence == 0.0 and finding.metadata:
            finding.confidence = finding.metadata.get("confidence", 0.0)

        return finding

    def normalize_many(self, results: List[ScanResult]) -> List[Finding]:
        """
        批量归一化

        Args:
            results: 扫描器原始结果列表

        Returns:
            List[Finding]: 归一化后的 Finding 列表
        """
        findings = []
        for r in results:
            try:
                findings.append(self.normalize_scan_result(r))
            except Exception as e:
                logger.warning(f"Failed to normalize result: {e}")
        return findings

    def compute_fingerprint(self, finding: Finding) -> str:
        """
        计算 Finding 的指纹

        指纹用于：
        - 同一项目不同次扫描之间的去重
        - 跨扫描器的结果关联
        - 历史误报匹配

        算法:
        1. 标准化代码片段（去除空白、截取前 200 字符）
        2. 使用 tool:rule_id:file_path:normalized_code 生成 MD5

        Args:
            finding: Finding 对象

        Returns:
            str: 32位 MD5 指纹
        """
        code = finding.code_snippet or ""
        # 去除多余空白
        normalized_code = re.sub(r'\s+', ' ', code.strip())
        # 截取前 200 字符，避免长代码影响
        normalized_code = normalized_code[:200]

        raw = f"{finding.scanner}:{finding.rule_id}:{finding.file_path}:{normalized_code}"
        return hashlib.md5(raw.encode('utf-8')).hexdigest()

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """
        按指纹去重

        保留第一次出现的结果

        Args:
            findings: Finding 列表

        Returns:
            List[Finding]: 去重后的列表
        """
        seen = set()
        unique = []
        for f in findings:
            fp = f.fingerprint or self.compute_fingerprint(f)
            if fp not in seen:
                seen.add(fp)
                unique.append(f)
        return unique

    @staticmethod
    def _infer_language(file_path: str) -> Optional[str]:
        """
        从文件扩展名推断语言

        Args:
            file_path: 文件路径

        Returns:
            str: 语言名称，无法推断则返回 None
        """
        for ext, lang in ResultNormalizer.EXTENSION_LANGUAGE_MAP.items():
            if file_path.endswith(ext):
                return lang
        return None

    @staticmethod
    def resolve_source_path(
        class_path: str,
        source_roots: Optional[List[str]] = None,
    ) -> str:
        """
        将 class 文件路径映射回 Java 源文件路径

        例如:
            com/example/service/UserService.class
            -> src/main/java/com/example/service/UserService.java

        Args:
            class_path: class 文件路径
            source_roots: 源码根目录列表

        Returns:
            str: 可能的源文件路径
        """
        if not class_path.endswith(".class"):
            return class_path

        # com/example/Foo.class -> com/example/Foo.java
        java_path = class_path[:-6] + ".java"

        if source_roots:
            for root in source_roots:
                candidate = f"{root}/{java_path}"
                import os
                if os.path.exists(candidate):
                    return candidate

        return java_path
