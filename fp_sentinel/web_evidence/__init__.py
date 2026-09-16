"""玄鉴AI Web 证据 → 报告适配器。

将 Burp / Nuclei / ZAP / 手工录入等 Web 漏洞证据转换为
标准 FindingReport，并借助现有报告模块输出 Excel / Word / HTML。

典型用法::

    from fp_sentinel.web_evidence.report_builder import (
        WebEvidenceReportBuilder,
    )

    builder = WebEvidenceReportBuilder()
    builder.add_from_burp_json("burp_issues.json")
    builder.add_from_nuclei_json("nuclei_results.json")
    builder.generate("reports/out", formats=("html",))
"""

from __future__ import annotations

from .report_builder import WebEvidenceReportBuilder

__all__ = ["WebEvidenceReportBuilder"]
