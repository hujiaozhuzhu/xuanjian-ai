"""
玄鉴 v3.0 - Industry Benchmark :: Repair Advisor

Generates industry-specific repair suggestions based on findings and
the benchmark dataset for the enterprise's industry.
"""
from __future__ import annotations

import uuid
from typing import Dict, List, Optional, Tuple

from .models import (
    BenchmarkDataset,
    ComplianceRequirement,
    Industry,
    IndustryScenario,
    RepairSuggestion,
    TopVulnerability,
)
from .builtin_data import build_benchmark_dataset


# --- Built-in remediation templates ---

_REMEDIATION_TEMPLATES: Dict[str, RepairSuggestion] = {
    "SQL_INJECTION": RepairSuggestion(
        suggestion_id="TMPL-SQL-001",
        title="Use parameterized queries to prevent SQL injection",
        description="Replace all string-concatenated SQL statements with parameterized queries using prepared statements.",
        target_categories=["INJECTION"],
        target_severities=["CRITICAL", "HIGH"],
        effort="medium",
        priority=1,
        code_example="cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        reference_links=["https://owasp.org/www-community/controls/SQL_Prevention_Cheat_Sheet"],
    ),
    "XSS": RepairSuggestion(
        suggestion_id="TMPL-XSS-001",
        title="Apply context-aware output encoding for XSS prevention",
        description="Use proper output encoding (HTML entity, JavaScript, URL, CSS) depending on the output context.",
        target_categories=["XSS"],
        target_severities=["HIGH", "MEDIUM"],
        effort="medium",
        priority=2,
        code_example="from markupsafe import escape; output = escape(user_input)",
        reference_links=["https://owasp.org/www-community/attacks/xss/"],
    ),
    "BROKEN_ACCESS_CONTROL": RepairSuggestion(
        suggestion_id="TMPL-ACCESS-001",
        title="Implement resource-level access control",
        description="Verify the authenticated user has permission to access the specific resource at the server side.",
        target_categories=["BROKEN_ACCESS_CONTROL"],
        target_severities=["CRITICAL", "HIGH"],
        effort="high",
        priority=1,
        code_example="if not current_user.can_access(resource_id): raise Forbidden()",
        reference_links=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
    ),
    "CRYPTO_FAILURE": RepairSuggestion(
        suggestion_id="TMPL-CRYPTO-001",
        title="Use strong encryption algorithms (AES-256, SHA-256+)",
        description="Replace legacy hashing (MD5, SHA1) and weak encryption (DES, RC4) with modern standards.",
        target_categories=["CRYPTO_FAILURE"],
        target_severities=["HIGH", "CRITICAL"],
        effort="medium",
        priority=2,
        code_example="import hashlib; hashlib.sha256(data).hexdigest()",
        reference_links=["https://owasp.org/www-project-cheat-sheets/"],
    ),
    "INSECURE_DESIGN": RepairSuggestion(
        suggestion_id="TMPL-DESIGN-001",
        title="Adopt secure design patterns (defense in depth)",
        description="Implement layered security controls including input validation, authentication, audit logging, and rate limiting.",
        target_categories=["INSECURE_DESIGN"],
        target_severities=["MEDIUM", "HIGH"],
        effort="high",
        priority=3,
        reference_links=["https://owasp.org/www-project-application-security-verification-standard/"],
    ),
    "VULNERABLE_COMPONENTS": RepairSuggestion(
        suggestion_id="TMPL-COMP-001",
        title="Upgrade vulnerable dependencies and enable SCA scanning",
        description="Identify and upgrade all components with known CVEs. SCA scanning should be integrated into CI/CD pipeline.",
        target_categories=["VULNERABLE_COMPONENTS"],
        target_severities=["HIGH", "CRITICAL"],
        effort="medium",
        priority=1,
        code_example="pip install --upgrade <package> && pip-audit",
        reference_links=["https://owasp.org/www-project-dependency-check/"],
    ),
    "DATA_LEAKAGE": RepairSuggestion(
        suggestion_id="TMPL-DATA-001",
        title="Encrypt sensitive data at rest and in transit",
        description="Apply AES-256 or SM4 encryption to PII/phi data at rest. Enforce TLS 1.3 for all data in transit.",
        target_categories=["DATA_LEAKAGE"],
        target_severities=["CRITICAL", "HIGH"],
        effort="high",
        priority=1,
        reference_links=["https://owasp.org/www-project-top-ten/"],
    ),
    "AUTH_FAILURE": RepairSuggestion(
        suggestion_id="TMPL-AUTH-001",
        title="Implement multi-factor authentication and secure session management",
        description="Enforce MFA for all privileged accounts. Use secure session tokens with rotation.",
        target_categories=["AUTH_FAILURE"],
        target_severities=["HIGH", "CRITICAL"],
        effort="high",
        priority=1,
        reference_links=["https://owasp.org/www-project-cheat_sheets/"],
    ),
    "MISCONFIGURATION": RepairSuggestion(
        suggestion_id="TMPL-MISCONFIG-001",
        title="Harden security configurations and remove defaults",
        description="Change default passwords, disable debug modes, restrict directory listings, enforce CSP headers.",
        target_categories=["MISCONFIGURATION"],
        target_severities=["MEDIUM", "HIGH"],
        effort="low",
        priority=2,
        code_example="DEBUG = False; SESSION_COOKIE_SECURE = True",
        reference_links=["https://owasp.org/www-project-web-security-testing-guide/"],
    ),
    "BUSINESS_LOGIC": RepairSuggestion(
        suggestion_id="TMPL-LOGIC-001",
        title="Add business logic validation and integrity checks",
        description="Server-side validation of all business parameters. Implement digital signatures for transaction integrity.",
        target_categories=["BUSINESS_LOGIC"],
        target_severities=["CRITICAL"],
        effort="high",
        priority=1,
        reference_links=["https://owasp.org/www-project-web-security-testing-guide/latest/"],
    ),
    "DOS": RepairSuggestion(
        suggestion_id="TMPL-DOS-001",
        title="Implement rate limiting and DDoS protection",
        description="Deploy request rate limiting, circuit breakers, and CDN-based DDoS mitigation.",
        target_categories=["DOS", "AVAILABILITY"],
        target_severities=["HIGH", "CRITICAL"],
        effort="medium",
        priority=1,
        reference_links=["https://owasp.org/www-project-denial-of-service/"],
    ),
}


# --- Industry-specific extra templates ---

_INDUSTRY_TEMPLATES: Dict[str, List[RepairSuggestion]] = {
    "ICS_RCE": [
        RepairSuggestion(
            suggestion_id="ICS-RCE-001",
            title="Segment OT/IT networks with industrial firewalls",
            description="Isolate industrial control networks from corporate IT using demilitarized zones.",
            target_categories=["INJECTION", "AUTH_BYPASS"],
            target_severities=["CRITICAL"],
            effort="high",
            priority=1,
            industry_specific=True,
        ),
    ],
    "NRG_SCADA_HACK": [
        RepairSuggestion(
            suggestion_id="NRG-SCADA-001",
            title="Deploy SCADA-specific IDS for power systems",
            description="Implement industrial intrusion detection for IEC 61850 and DNP3 protocols.",
            target_categories=["INSECURE_PROTOCOL"],
            target_severities=["CRITICAL"],
            effort="high",
            priority=1,
            industry_specific=True,
        ),
    ],
    "SEC_FLASH_CRASH": [
        RepairSuggestion(
            suggestion_id="SEC-FLASH-001",
            title="Deploy circuit breakers and latency equalization",
            description="Implement trading circuit breakers and latency floor mechanisms to prevent flash crashes.",
            target_categories=["LATENCY_EXPLOIT"],
            target_severities=["CRITICAL"],
            effort="high",
            priority=1,
            industry_specific=True,
        ),
    ],
}


def _build_compliance_map(
    requirements: List[ComplianceRequirement],
) -> Dict[str, List[str]]:
    """Build CWE -> compliance ref mapping"""
    cwe_to_compliance: Dict[str, List[str]] = {}
    for req in requirements:
        for cwe in req.related_cwes:
            if cwe not in cwe_to_compliance:
                cwe_to_compliance[cwe] = []
            cwe_to_compliance[cwe].append(req.ref_id)
    return cwe_to_compliance


class RepairAdvisor:
    """
    Industry-specific repair suggestion engine.
    """

    def __init__(self, benchmark: Optional[BenchmarkDataset] = None) -> None:
        self._benchmark = benchmark

    def set_benchmark(self, benchmark: BenchmarkDataset) -> None:
        """Set benchmark for context-aware suggestions"""
        self._benchmark = benchmark

    def suggest_for_finding(
        self,
        category: str,
        severity: str,
        cwe: Optional[str] = None,
        industry: Optional[Industry] = None,
    ) -> List[RepairSuggestion]:
        """
        Get repair suggestions for a single finding.

        Args:
            category: Vulnerability category
            severity: Finding severity
            cwe: Optional CWE identifier
            industry: Optional industry for context

        Returns:
            List of repair suggestions (sorted by priority)
        """
        suggestions: List[RepairSuggestion] = []

        # Match built-in templates
        for key, template in _REMEDIATION_TEMPLATES.items():
            if (not template.target_categories or category in template.target_categories):
                if (not template.target_severities or severity in template.target_severities):
                    sug = template.model_copy()
                    sug.suggestion_id = f"sug-{uuid.uuid4().hex[:8]}"

                    # Enrich with compliance refs if available
                    if cwe and self._benchmark:
                        compliance_map = _build_compliance_map(
                            self._benchmark.compliance_requirements
                        )
                        sug.compliance_refs = compliance_map.get(cwe, [])

                    suggestions.append(sug)

        return sorted(suggestions, key=lambda s: s.priority)

    def suggest_for_industry(
        self,
        industry: Industry,
    ) -> List[RepairSuggestion]:
        """
        Get top industry-specific suggestions based on benchmark data.

        Args:
            industry: Target industry

        Returns:
            List of prioritized repair suggestions
        """
        bench = self._benchmark or build_benchmark_dataset(industry)
        suggestions: List[RepairSuggestion] = []
        seen_ids: set = set()

        # Generate suggestions from top vulnerabilities
        for top_vuln in bench.top_vulnerabilities[:5]:
            for sug in self.suggest_for_finding(
                category=top_vuln.category,
                severity=top_vuln.severity,
                cwe=top_vuln.cwe,
                industry=industry,
            ):
                if sug.suggestion_id not in seen_ids:
                    suggestions.append(sug)
                    seen_ids.add(sug.suggestion_id)

        # Add industry-specific templates
        for scenario in bench.industry_scenarios:
            for key, templates in _INDUSTRY_TEMPLATES.items():
                if key == scenario.scenario_id:
                    for tmpl in templates:
                        sug = tmpl.model_copy()
                        sug.suggestion_id = f"sug-{uuid.uuid4().hex[:8]}"
                        sug.compliance_refs = [
                            c.ref_id for c in bench.compliance_requirements
                            if any(t in c.related_cwes for t in (scenario.related_categories or []))
                        ][:3]
                        if sug.suggestion_id not in seen_ids:
                            suggestions.append(sug)
                            seen_ids.add(sug.suggestion_id)

        return sorted(suggestions, key=lambda s: s.priority)

    def suggest_for_scenarios(
        self,
        industry: Industry,
    ) -> Dict[str, List[RepairSuggestion]]:
        """
        Get mapped suggestions for each industry scenario.

        Returns:
            Dictionary mapping scenario_id to suggestions
        """
        bench = self._benchmark or build_benchmark_dataset(industry)
        result: Dict[str, List[RepairSuggestion]] = {}

        for scenario in bench.industry_scenarios:
            scenario_sugs: List[RepairSuggestion] = []
            for tmpl_key, templates in _INDUSTRY_TEMPLATES.items():
                if tmpl_key == scenario.scenario_id:
                    for tmpl in templates:
                        sug = tmpl.model_copy()
                        sug.suggestion_id = f"sug-{uuid.uuid4().hex[:8]}"
                        scenario_sugs.append(sug)
            if scenario_sugs:
                result[scenario.scenario_id] = sorted(scenario_sugs, key=lambda s: s.priority)

        return result


def suggest_repairs_for_findings(
    findings: List[Tuple[str, str, Optional[str]]],
    industry: Industry,
    benchmark: Optional[BenchmarkDataset] = None,
) -> List[RepairSuggestion]:
    """
    Convenience function: generate repair suggestions for a list of findings.

    Args:
        findings: List of (category, severity, optional_cwe) tuples
        industry: Industry for context
        benchmark: Optional benchmark dataset

    Returns:
        Prioritized list of repair suggestions
    """
    advisor = RepairAdvisor(benchmark=benchmark)
    all_sugs: List[RepairSuggestion] = []
    seen: set = set()

    for category, severity, cwe in findings:
        for sug in advisor.suggest_for_finding(category, severity, cwe, industry):
            if sug.suggestion_id not in seen:
                all_sugs.append(sug)
                seen.add(sug.suggestion_id)

    return sorted(all_sugs, key=lambda s: s.priority)
