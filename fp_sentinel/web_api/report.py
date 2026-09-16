"""Web API 安全审计报告汇总。

将端点发现、分类、越权探测结果聚合为
:class:`MobileSecurityReport`，供报告模块直接渲染。
"""

from __future__ import annotations

import logging
import platform
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .endpoints_models import ApiEndpoint, FindingReport
from .classifier import classify
from .privilege_scan import PrivilegeFinding

logger = logging.getLogger(__name__)

__all__ = ["build_report", "MobileSecurityReport"]


# ────────────────────────── 报告聚合模型 ──────────────────────────
# 优先使用共享的 MobileSecurityReport（若存在且支持完整字段集）；
# 否则退回到本模块定义的精简版存根，保证 API 一致性与测试可用。

def _detect_formal_model() -> Any:
    """检测正式共享报告模型是否可用。

    正式模型必须同时包含 metadata / statistics / findings / generate 字段
    才视为可用；否则使用本模块存根。

    Returns:
        Optional[type]: 正式模型类或 None。
    """
    try:
        from fp_sentinel.mobile_reporting.models.report_models import (  # type: ignore
            MobileSecurityReport as _FormalMSR,
        )
        required_fields = {"metadata", "statistics", "findings"}
        if all(hasattr(_FormalMSR, f) for f in required_fields):
            return _FormalMSR
        return None
    except ImportError:
        return None


_FormalModel = _detect_formal_model()


@dataclass
class MobileSecurityReport:
    """Web API 安全评估报告聚合根（精简存根）。

    支持完整 MobileSecurityReport 接口的子集，用于报告模块渲染。
    """

    title: str = "Web API 安全审计报告"
    metadata: Optional[Dict[str, Any]] = None
    statistics: Optional[Dict[str, Any]] = None
    findings: List[FindingReport] = field(default_factory=list)
    generated_at: str = ""
    source_endpoints: List[ApiEndpoint] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict。"""
        return {
            "title": self.title,
            "metadata": self.metadata,
            "statistics": self.statistics,
            "findings": [
                f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings
            ],
            "generated_at": self.generated_at,
            "source_endpoints": [ep.to_dict() for ep in self.source_endpoints],
        }


def build_report(
    endpoints: List[ApiEndpoint],
    classifications: Optional[List[Dict[str, Any]]] = None,
    privilege_findings: Optional[List[PrivilegeFinding]] = None,
    title: str = "Web API 安全审计报告",
) -> MobileSecurityReport:
    """汇总端点、分类、越权发现为 :class:`MobileSecurityReport`。

    自动统计：总端点数、按敏感度分布、按来源分布、确认漏洞数。

    Args:
        endpoints: 已发现的 API 端点列表。
        classifications: 端点分类结果列表（每个元素含 category/sensitivity/reasons）。
            若为 None 则自动对每个端点调用 :func:`classify`。
        privilege_findings: 越权探测结果列表。
        title: 报告标题。

    Returns:
        MobileSecurityReport: 可直接交付给移动报告模块渲染的完整报告。
    """
    classifications = classifications or [classify(ep) for ep in endpoints]
    privilege_findings = privilege_findings or []
    # 合并为 FindingReport 列表
    findings: List[FindingReport] = []
    for ep in endpoints:
        try:
            findings.append(ep.to_finding())
        except Exception as exc:  # noqa: BLE001
            logger.warning("端点转 Finding 失败: %s (%s)", ep.url, exc)
    for pf in privilege_findings:
        try:
            findings.append(pf.to_finding_report())
        except Exception as exc:  # noqa: BLE001
            logger.warning("越权 Finding 转换失败: %s", exc)
    # 统计
    by_severity: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    by_sensitivity: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    confirmed_vulns: int = 0
    for f in findings:
        sev = f.severity.upper()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        cat = f.category or "unknown"
        by_category[cat] = by_category.get(cat, 0) + 1
    for cls in classifications:
        if not isinstance(cls, dict):
            continue
        sens = str(cls.get("sensitivity", "low")).lower()
        by_sensitivity[sens] = by_sensitivity.get(sens, 0) + 1
        cat = str(cls.get("category", "unknown"))
        by_category[cat] = by_category.get(cat, 0) + 1
    for ep in endpoints:
        src = ep.source or "unknown"
        by_source[src] = by_source.get(src, 0) + 1
    for pf in privilege_findings:
        if pf.verdict == "exposed":
            confirmed_vulns += 1
    total_count = len(endpoints)
    now = datetime.now().isoformat(timespec="seconds")
    statistics = {
        "total_count": total_count,
        "by_severity": by_severity,
        "by_category": {
            **by_category,
            "sensitivity": by_sensitivity,
            "source": by_source,
        },
        "vuln_count": confirmed_vulns,
        "high_sensitivity": by_sensitivity.get("high", 0),
        "medium_sensitivity": by_sensitivity.get("medium", 0),
        "low_sensitivity": by_sensitivity.get("low", 0),
    }
    metadata = {
        "title": title,
        "author": "玄鉴AI (fp_sentinel-web-api)",
        "classification": "内部资料",
        "date": now,
        "tool": "fp_sentinel-web-api",
    }
    if _FormalModel is not None:
        # 使用正式报告模型
        from fp_sentinel.mobile_reporting.models.report_models import (  # type: ignore
            ReportMetadata as _RM,
            ReportStatistics as _RS,
        )
        report = _FormalModel(
            metadata=_RM(
                title=title,
                author="玄鉴AI (fp_sentinel-web-api)",
                classification="内部资料",
                date=now,
            ),
            statistics=_RS(
                total_count=total_count,
                by_severity=by_severity,
                by_category={
                    **by_category,
                    "sensitivity": by_sensitivity,
                    "source": by_source,
                },
                coverage_metrics=statistics,
                scan_duration_seconds=0.0,
            ),
            findings=findings,
            generated_at=now,
            report_format="json",
        )
    else:
        report = MobileSecurityReport(
            title=title,
            metadata=metadata,
            statistics=statistics,
            findings=findings,
            generated_at=now,
            source_endpoints=endpoints,
        )
    logger.info(
        "Web API 报告汇总完成: %d 端点, %d Finding, %d 确认漏洞, OS=%s",
        total_count,
        len(findings),
        confirmed_vulns,
        platform.system(),
    )
    return report
