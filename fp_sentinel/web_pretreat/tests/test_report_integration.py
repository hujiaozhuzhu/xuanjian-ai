"""report_integration 模块的单元测试。

验证 :func:`js_audit_to_findings` 输出的 :class:`FindingReport` 的字段正确性，
特别是 cwe、severity、evidence 数量；以及硬编码密钥的脱敏处理。
"""

from __future__ import annotations

import pytest

from fp_sentinel.web_pretreat.report_integration import js_audit_to_findings


# ──────────────────────────────────────────────────────
# Fixtures —— 准备最小预处理结果
# ──────────────────────────────────────────────────────


@pytest.fixture
def eval_suspicious() -> list[dict[str, str]]:
    """模拟 eval 命中项。"""
    return [
        {
            "pattern_type": "eval_function",
            "match_text": "eval(",
            "line": "3",
            "snippet": "...eval(\"xss\")...",
        },
    ]


@pytest.fixture
def xss_suspicious() -> list[dict[str, str]]:
    """模拟 document.write / innerHTML 命中项。"""
    return [
        {
            "pattern_type": "document_write",
            "match_text": "document.write(",
            "line": "5",
            "snippet": "...document.write(...)",
        },
        {
            "pattern_type": "inner_html_assign",
            "match_text": ".innerHTML=",
            "line": "6",
            "snippet": "...el.innerHTML=x",
        },
    ]


@pytest.fixture
def packer_suspicious() -> list[dict[str, str]]:
    """模拟 atob / unescape 命中项。"""
    return [
        {
            "pattern_type": "atob_decode",
            "match_text": "atob(",
            "line": "10",
            "snippet": "...atob('...')",
        },
    ]


@pytest.fixture
def api_list() -> list[dict[str, str]]:
    return [
        {
            "pattern_type": "url_http",
            "match": "https://example.com/api/v1/data",
            "line": "1",
            "snippet": "'...https://example.com...'",
        },
        {
            "pattern_type": "fetch_api",
            "match": "fetch('/users')",
            "line": "7",
            "snippet": "...fetch('/users')",
        },
    ]


@pytest.fixture
def secret_strings() -> list[dict[str, str]]:
    return [
        {
            "value": "sk-abc123def456secret789",
            "tag": "secret_like",
            "line": "2",
            "snippet": '...sk-abc...',
        },
    ]


# ──────────────────────────────────────────────────────
# 测试集
# ──────────────────────────────────────────────────────


class TestJsAuditToFindings:
    """js_audit_to_findings 的核心行为。"""

    def test_eval_produces_cwe95(self, eval_suspicious: list[dict[str, str]]) -> None:
        """eval 类型应为 CWE-95。"""
        findings = js_audit_to_findings(
            file_path="/src/app.js",
            prettify_result="prettified",
            extract_result=[],
            suspicious=eval_suspicious,
            apis=[],
        )
        assert findings, "应产出至少一条 finding"
        eval_finding = next(f for f in findings if "eval" in f.title.lower())
        assert eval_finding.cwe_id == "CWE-95"

    def test_eval_severity_is_high(self, eval_suspicious: list[dict[str, str]]) -> None:
        findings = js_audit_to_findings(
            file_path="/src/app.js",
            prettify_result="",
            extract_result=[],
            suspicious=eval_suspicious,
            apis=[],
        )
        eval_finding = next(f for f in findings if "eval" in f.title.lower())
        assert eval_finding.severity == "HIGH"

    def test_xss_produces_cwe79(self, xss_suspicious: list[dict[str, str]]) -> None:
        findings = js_audit_to_findings(
            file_path="/src/app.js",
            prettify_result="",
            extract_result=[],
            suspicious=xss_suspicious,
            apis=[],
        )
        xss_finding = next(f for f in findings if "xss" in f.title.lower())
        assert xss_finding.cwe_id == "CWE-79"

    def test_xss_groups_multiple_suspicious(
        self, xss_suspicious: list[dict[str, str]]
    ) -> None:
        """document.write + innerHTML 应合并在同一条 finding。"""
        findings = js_audit_to_findings(
            file_path="/src/app.js",
            prettify_result="",
            extract_result=[],
            suspicious=xss_suspicious,
            apis=[],
        )
        xss_findings = [f for f in findings if "xss" in f.title.lower()]
        assert len(xss_findings) == 1
        # evidence 数量应等于命中项数 (document.write + innerHTML)
        assert len(xss_findings[0].evidence) == len(xss_suspicious)

    def test_api_patterns_produce_info_finding(
        self, api_list: list[dict[str, str]]
    ) -> None:
        """URL/端点暴露应产出 INFO 级 finding。"""
        findings = js_audit_to_findings(
            file_path="/src/app.js",
            prettify_result="",
            extract_result=[],
            suspicious=[],
            apis=api_list,
        )
        info_findings = [
            f for f in findings
            if "info" in f.title.lower() or "url" in f.title.lower()
        ]
        assert info_findings
        assert info_findings[0].severity == "INFO"
        assert info_findings[0].cwe_id == "CWE-200"

    def test_hardcoded_secret_produces_cwe798(
        self, secret_strings: list[dict[str, str]]
    ) -> None:
        findings = js_audit_to_findings(
            file_path="/src/app.js",
            prettify_result="",
            extract_result=secret_strings,
            suspicious=[],
            apis=[],
        )
        cred_findings = [
            f for f in findings
            if "key" in f.title.lower() or "token" in f.title.lower()
        ]
        assert cred_findings
        cred = cred_findings[0]
        assert cred.cwe_id == "CWE-798"
        assert cred.severity in {"MEDIUM", "HIGH"}
        # 证据中的描述应对真实值做脱敏
        for ev in cred.evidence:
            assert "sk-abc123def456secret789" not in ev.content
            assert "sk-" in ev.description or "****" in ev.description

    def test_packer_suspicious_produces_cwe94(
        self, packer_suspicious: list[dict[str, str]]
    ) -> None:
        findings = js_audit_to_findings(
            file_path="/src/app.js",
            prettify_result="",
            extract_result=[],
            suspicious=packer_suspicious,
            apis=[],
        )
        packer_findings = [
            f for f in findings
            if "atob" in f.title.lower() or "pack" in f.title.lower()
        ]
        assert packer_findings
        assert packer_findings[0].cwe_id == "CWE-94"

    def test_no_risk_items_returns_empty(self) -> None:
        """全部空输入 -> 空列表。"""
        findings = js_audit_to_findings(
            file_path="/src/app.js",
            prettify_result="",
            extract_result=[],
            suspicious=[],
            apis=[],
        )
        assert findings == []

    def test_comprehensive_produces_multiple_findings(
        self,
        eval_suspicious: list[dict[str, str]],
        xss_suspicious: list[dict[str, str]],
        api_list: list[dict[str, str]],
        secret_strings: list[dict[str, str]],
        packer_suspicious: list[dict[str, str]],
    ) -> None:
        """综合场景：应合并为多条 finding。"""
        all_suspicious = eval_suspicious + xss_suspicious + packer_suspicious
        findings = js_audit_to_findings(
            file_path="/src/app/main.js",
            prettify_result="prettified",
            extract_result=secret_strings,
            suspicious=all_suspicious,
            apis=api_list,
        )
        # 评判: INFO(url) + HIGH(eval) + HIGH(xss) + MEDIUM(cred) + MEDIUM(packer)
        assert len(findings) >= 3

        cwes = {f.cwe_id for f in findings}
        assert "CWE-95" in cwes
        assert "CWE-79" in cwes
        assert "CWE-200" in cwes
        assert "CWE-798" in cwes

        # 各 finding 都不应有空 id
        for f in findings:
            assert f.id
            assert f.title

    def test_findings_have_unique_ids(
        self,
        eval_suspicious: list[dict[str, str]],
        xss_suspicious: list[dict[str, str]],
    ) -> None:
        findings = js_audit_to_findings(
            file_path="a.js",
            prettify_result="",
            extract_result=[],
            suspicious=eval_suspicious + xss_suspicious,
            apis=[],
        )
        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids)), "Finding IDs 应唯一"

    def test_tool_version_set(self, eval_suspicious: list[dict[str, str]]) -> None:
        findings = js_audit_to_findings(
            file_path="a.js",
            prettify_result="",
            extract_result=[],
            suspicious=eval_suspicious,
            apis=[],
        )
        for f in findings:
            assert "web_pretreat" in f.tool_version
