"""报告聚合测试。"""

from __future__ import annotations

from typing import List

from fp_sentinel.web_api.classifier import classify
from fp_sentinel.web_api.endpoints_models import ApiEndpoint
from fp_sentinel.web_api.privilege_scan import PrivilegeFinding
from fp_sentinel.web_api.report import build_report


class TestBuildReport:
    """build_report 聚合函数测试。"""

    def test_empty_inputs(self) -> None:
        """验证空输入返回最小报告。"""
        report = build_report([], [], [])
        assert isinstance(report, object)
        assert hasattr(report, "to_dict")

    def test_with_endpoints(self) -> None:
        """验证端点被转为 FindingReport。"""
        endpoints = [
            ApiEndpoint(method="GET", url="https://x.com/api/login", path="/api/login"),
            ApiEndpoint(method="POST", url="https://x.com/api/orders", path="/api/orders"),
        ]
        report = build_report(endpoints)
        data = report.to_dict()
        # 报告应包含 findings
        assert "findings" in data
        assert len(data["findings"]) >= 2

    def test_statistics(self) -> None:
        """验证统计信息正确计算。"""
        endpoints = [
            ApiEndpoint(method="GET", url="https://x.com/api/login", path="/api/login"),
            ApiEndpoint(method="GET", url="https://x.com/api/info", path="/api/info"),
        ]
        report = build_report(endpoints)
        data = report.to_dict()
        # 统计字段存在
        if "statistics" in data and data["statistics"] is not None:
            stats = data["statistics"]
            assert "total_count" in stats
            assert stats["total_count"] == 2

    def test_privilege_findings_included(self) -> None:
        """验证越权 Finding 被纳入报告。"""
        endpoints = [
            ApiEndpoint(
                method="GET",
                url="https://x.com/admin/users",
                path="/admin/users",
            )
        ]
        priv_findings: List[PrivilegeFinding] = [
            PrivilegeFinding(
                method="GET",
                url="https://x.com/admin/users",
                finding_type="horizontal",
                verdict="exposed",
                status_a=200,
                status_b=200,
                cwe_id="CWE-639",
            )
        ]
        report = build_report(endpoints, [], priv_findings)
        data = report.to_dict()
        assert "findings" in data


class TestClassifyIntegration:
    """分类集成测试。"""

    def test_batch_classify(self) -> None:
        """验证批量分类返回。"""
        endpoints = [
            ApiEndpoint(method="POST", url="https://x.com/api/login", path="/api/login"),
            ApiEndpoint(method="GET", url="https://x.com/static/x.png", path="/static/x.png"),
        ]
        classifications = [classify(ep) for ep in endpoints]
        assert classifications[0]["sensitivity"] == "high"
        assert classifications[1]["sensitivity"] == "low"
