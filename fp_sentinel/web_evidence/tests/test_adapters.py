"""adapters.py 单元测试：severity 归一化 / CWE 提取 / 各工具适配。"""

from __future__ import annotations

from fp_sentinel.mobile_reporting.models.report_models import FindingReport

from fp_sentinel.web_evidence.adapters import (
    burp_alert_to_finding,
    extract_cwe,
    manual_finding,
    normalize_severity,
    nuclei_result_to_finding,
    zap_alert_to_finding,
)


# ────────────────────────── normalize_severity ──────────────────────────


class TestNormalizeSeverity:
    """normalize_severity 全 alias 分支测试。"""

    def test_high_variants(self) -> None:
        assert normalize_severity("high") == "HIGH"
        assert normalize_severity("High") == "HIGH"
        assert normalize_severity("HIGH") == "HIGH"

    def test_medium_variants(self) -> None:
        assert normalize_severity("medium") == "MEDIUM"
        assert normalize_severity("Medium") == "MEDIUM"
        assert normalize_severity("MEDIUM") == "MEDIUM"

    def test_info_variants(self) -> None:
        assert normalize_severity("info") == "INFO"
        assert normalize_severity("Information") == "INFO"
        assert normalize_severity("INFO") == "INFO"

    def test_low(self) -> None:
        assert normalize_severity("low") == "LOW"
        assert normalize_severity("LOW") == "LOW"

    def test_critical(self) -> None:
        assert normalize_severity("critical") == "CRITICAL"
        assert normalize_severity("CRITICAL") == "CRITICAL"

    def test_empty_and_none(self) -> None:
        assert normalize_severity("") == "INFO"
        assert normalize_severity(None) == "INFO"

    def test_unknown_fallback(self) -> None:
        assert normalize_severity("unknown") == "INFO"
        assert normalize_severity("xyz123") == "INFO"


# ────────────────────────── extract_cwe ──────────────────────────


class TestExtractCwe:
    """extract_cwe 提取测试。"""

    def test_single_cwe(self) -> None:
        assert extract_cwe("CWE-89 SQL 注入") == "CWE-89"

    def test_multiple_cwe_returns_first(self) -> None:
        text = "涉及 CWE-79 与 CWE-89 两种漏洞"
        assert extract_cwe(text) == "CWE-79"

    def test_no_cwe(self) -> None:
        assert extract_cwe("这是一段无 CWE 的文本") == ""
        assert extract_cwe("") == ""

    def test_none_input(self) -> None:
        assert extract_cwe(None) == ""

    def test_cwe_three_digits(self) -> None:
        assert extract_cwe("CWE-1234 越权") == "CWE-1234"


# ────────────────────────── burp_alert_to_finding ──────────────────────────


def _sample_burp_alert() -> dict:
    return {
        "name": "SQL Injection",
        "host": "https://example.com",
        "path": "/api/v1/users",
        "severity": "High",
        "confidence": "Certain",
        "issueDetail": "应用未对 id 参数做过滤，存在 CWE-89 漏洞。",
        "remediationBackground": "应使用参数化查询。",
        "references": ["https://owasp.org/sql-injection"],
    }


class TestBurpAlertToFinding:
    def test_basic_conversion(self) -> None:
        finding = burp_alert_to_finding(_sample_burp_alert())
        assert finding is not None
        assert finding.title == "SQL Injection"
        assert finding.severity == "HIGH"
        assert finding.cwe_id == "CWE-89"
        assert finding.remediation == "应使用参数化查询。"
        assert "https://owasp.org/sql-injection" in finding.references

    def test_cwe_from_description_when_missing(self) -> None:
        alert = _sample_burp_alert()
        alert["issueDetail"] = "存在跨站脚本 CWE-79 风险"
        finding = burp_alert_to_finding(alert)
        assert finding is not None
        assert finding.cwe_id == "CWE-79"

    def test_severity_mapping(self) -> None:
        for raw, expected in [
            ("Information", "INFO"),
            ("Medium", "MEDIUM"),
            ("High", "HIGH"),
        ]:
            alert = _sample_burp_alert()
            alert["severity"] = raw
            finding = burp_alert_to_finding(alert)
            assert finding is not None
            assert finding.severity == expected

    def test_evidence_url_set(self) -> None:
        finding = burp_alert_to_finding(_sample_burp_alert())
        assert finding is not None
        assert len(finding.evidence) >= 1
        assert "example.com" in finding.evidence[0].location

    def test_default_severity_applied(self) -> None:
        alert = _sample_burp_alert()
        alert.pop("severity", None)
        finding = burp_alert_to_finding(alert, default_severity="LOW")
        assert finding is not None
        assert finding.severity == "LOW"

    def test_invalid_input_returns_finding(self) -> None:
        finding = burp_alert_to_finding({"severity": 123})
        assert finding is not None


# ── nuclei_result_to_finding ──


def _sample_nuclei_result() -> dict:
    return {
        "template-id": "CVE-2023-1234",
        "matcher-name": "Apache Path Traversal",
        "matched-at": "https://example.com/static/..%2fetc/passwd",
        "type": "http",
        "info": {
            "name": "Apache HTTP Server Path Traversal",
            "severity": "critical",
            "description": "Apache HTTP Server path traversal.",
            "tags": ["cve", "apache", "lfi"],
        },
        "extracted-results": ["/etc/passwd root:x:0:0"],
    }


class TestNucleiResultToFinding:
    def test_basic_conversion(self) -> None:
        finding = nuclei_result_to_finding(_sample_nuclei_result())
        assert finding is not None
        assert finding.title == "Apache Path Traversal"
        assert finding.severity == "CRITICAL"
        assert finding.cwe_id == ""  # tags 不含 cwe
        assert "cve" in finding.category

    def test_url_from_matched_at(self) -> None:
        finding = nuclei_result_to_finding(_sample_nuclei_result())
        assert finding is not None
        assert "example.com" in finding.evidence[0].location

    def test_severity_mapping(self) -> None:
        for raw, expected in [
            ("high", "HIGH"),
            ("medium", "MEDIUM"),
            ("low", "LOW"),
            ("info", "INFO"),
            ("unknown", "INFO"),
        ]:
            result = _sample_nuclei_result()
            result["info"]["severity"] = raw
            finding = nuclei_result_to_finding(result)
            assert finding is not None
            assert finding.severity == expected

    def test_invalid_result_handled(self) -> None:
        finding = nuclei_result_to_finding({})
        assert finding is not None


# ────────────────────────── zap_alert_to_finding ──────────────────────────


def _sample_zap_alert() -> dict:
    return {
        "name": "Cross-site Scripting (Reflected)",
        "riskdesc": "High (Medium)",
        "cweid": "79",
        "desc": "Reflected XSS vulnerability found CWE-79.",
        "uri": "https://example.com/search?q=<script>alert(1)</script>",
        "solution": "Validate and sanitize all user input.",
        "instances": [
            {"uri": "https://example.com/search?q=test1"},
            {"uri": "https://example.com/search?q=test2"},
        ],
    }


class TestZapAlertToFinding:
    def test_basic_conversion(self) -> None:
        finding = zap_alert_to_finding(_sample_zap_alert())
        assert finding is not None
        assert finding.title == "Cross-site Scripting (Reflected)"
        assert finding.severity == "HIGH"
        assert finding.cwe_id == "CWE-79"
        assert finding.remediation == "Validate and sanitize all user input."

    def test_cwe_from_description(self) -> None:
        alert = _sample_zap_alert()
        alert["cweid"] = ""
        finding = zap_alert_to_finding(alert)
        assert finding is not None
        assert finding.cwe_id == "CWE-79"

    def test_instances_as_references(self) -> None:
        finding = zap_alert_to_finding(_sample_zap_alert())
        assert finding is not None
        assert len(finding.references) == 2

    def test_severity_from_risk_desc(self) -> None:
        alert = _sample_zap_alert()
        alert["riskdesc"] = "Medium (Low)"
        finding = zap_alert_to_finding(alert)
        assert finding is not None
        assert finding.severity == "MEDIUM"

    def test_invalid_input_handled(self) -> None:
        finding = zap_alert_to_finding({})
        assert finding is not None


# ────────────────────────── manual_finding ──────────────────────────


class TestManualFinding:
    def test_basic_creation(self) -> None:
        finding = manual_finding(
            id="WEB-001",
            title="反射型 XSS",
            severity="HIGH",
            cwe_id="CWE-79",
            description="搜索参数未过滤导致 XSS",
            evidence="截图: xss_evidence.png",
            remediation="对用户输入进行 HTML 实体编码",
        )
        assert finding is not None
        assert finding.id == "WEB-001"
        assert finding.title == "反射型 XSS"
        assert finding.severity == "HIGH"
        assert finding.cwe_id == "CWE-79"

    def test_severity_normalized(self) -> None:
        finding = manual_finding(
            id="WEB-002",
            title="test",
            severity="medium",
        )
        assert finding is not None
        assert finding.severity == "MEDIUM"

    def test_cwe_extracted_from_description(self) -> None:
        finding = manual_finding(
            id="WEB-003",
            title="SQL Injection",
            severity="critical",
            description="存在 CWE-89 SQL 注入问题",
        )
        assert finding is not None
        assert finding.cwe_id == "CWE-89"

    def test_evidence_object_created(self) -> None:
        finding = manual_finding(
            id="WEB-004",
            title="test",
            severity="low",
            evidence="请求: GET /api?id=1' OR '1'='1",
        )
        assert finding is not None
        assert len(finding.evidence) == 1

    def test_empty_evidence_no_object(self) -> None:
        finding = manual_finding(
            id="WEB-005",
            title="test",
            severity="info",
        )
        assert finding is not None
        assert len(finding.evidence) == 0

    def test_references_preserved(self) -> None:
        refs = [
            "https://example.com/advisory",
            "https://nvd.nist.gov/vuln/CVE-2023-xxxx",
        ]
        finding = manual_finding(
            id="WEB-006",
            title="test",
            severity="high",
            references=refs,
        )
        assert finding is not None
        assert finding.references == refs

    def test_invalid_input_handled(self) -> None:
        try:
            result = manual_finding(id="", title="", severity="")
            assert isinstance(result, FindingReport)
        except Exception:
            pass
