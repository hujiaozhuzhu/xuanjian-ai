"""Web API 端点数据模型。

定义 :class:`ApiEndpoint` dataclass 及其与 :class:`FindingReport` 的转换方法，
作为端点发现、分类、越权探测的统一中间数据结构。
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = ["ApiEndpoint", "FindingReport", "Evidence"]


# ---------------------------------------------------------------------------
# 尝试导入共享报告模型；失败时使用回退存根保证模块可用
# ---------------------------------------------------------------------------
try:  # pragma: no cover - 取决于并行开发进度
    from fp_sentinel.mobile_reporting.models.report_models import (  # type: ignore
        FindingReport,
        Evidence,
    )
except ImportError:
    try:
        from fp_sentinel.mobile_reporting.formats._fallback_models import (  # type: ignore
            FindingReport,
            Evidence,
        )
    except ImportError:
        logger.warning(
            "无法导入 FindingReport / Evidence，使用内嵌存根。"
        )

        @dataclass
        class Evidence:
            """漏洞证据存根。"""

            id: str = ""
            location: str = ""
            content: str = ""
            description: str = ""
            source: str = "静态"

            def to_dict(self) -> Dict[str, Any]:
                """序列化为可 JSON 化的 dict。"""
                return asdict(self)

        @dataclass
        class FindingReport:
            """单条漏洞/发现存根。"""

            id: str = ""
            title: str = ""
            severity: str = "MEDIUM"
            cwe_id: str = ""
            owasp_masvs: str = ""
            category: str = ""
            description: str = ""
            evidence: List[Evidence] = field(default_factory=list)
            remediation: str = ""
            references: List[str] = field(default_factory=list)
            tool_version: str = ""
            confidence: float = 0.5

            def to_dict(self) -> Dict[str, Any]:
                """序列化为可 JSON 化的 dict。"""
                return asdict(self)


@dataclass
class ApiEndpoint:
    """统一 API 端点数据模型。

    作为 HAR / Burp / Nuclei / JS / 文本等多种发现源的统一中间表示，
    便于下游分类器、越权探测器和报告生成器使用。
    """

    method: str = "GET"
    url: str = ""
    path: str = ""
    host: str = ""
    port: int = 443
    protocol: str = "https"
    status_code: Optional[int] = None
    content_type: str = ""
    response_size: int = 0
    source: str = ""  # har / burp / nuclei / js / text
    matched_template: str = ""  # nuclei 用
    severity_hint: str = ""  # info / low / medium / high / critical

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict。"""
        return asdict(self)

    def to_finding(self, category: str = "api-discovery") -> FindingReport:
        """转换为标准 :class:`FindingReport`。

        将端点发现结果包装为报告模块可直接渲染的标准 Finding。

        Args:
            category: 发现分类标签（默认 ``"api-discovery"``）。

        Returns:
            FindingReport: 标准化漏洞发现记录。
        """
        return FindingReport(
            id=f"WAF-{hash(self.url) & 0xFFFFFF:06X}",
            title=f"发现 API 端点: {self.method} {self.path or self.url}",
            severity="INFO",
            cwe_id="",
            owasp_masvs="",
            category=category,
            description=(
                f"来源 {self.source} 发现 API 端点 ``{self.method} {self.url}``"
                + (f"，响应状态 {self.status_code}" if self.status_code else "")
                + (f"，MIME 类型 {self.content_type}" if self.content_type else "")
                + (
                    f"，Nuclei 模板 {self.matched_template}"
                    if self.matched_template
                    else ""
                )
                + (
                    f"，严重度提示 {self.severity_hint}"
                    if self.severity_hint
                    else ""
                )
                + "。"
            ),
            evidence=[
                Evidence(
                    id="api-endpoint-evidence",
                    location=self.url,
                    content=(
                        f"method={self.method}\n"
                        f"host={self.host}\n"
                        f"path={self.path}\n"
                        f"port={self.port}\n"
                        f"protocol={self.protocol}\n"
                        f"source={self.source}"
                    ),
                    description=f"API 端点来源: {self.source}",
                    source="静态",
                )
            ],
            remediation="将该端点纳入 API 准入清单并评估其暴露面的必要性。",
            references=[],
            tool_version="fp_sentinel-web-api",
            confidence=0.8 if self.source != "text" else 0.6,
        )
