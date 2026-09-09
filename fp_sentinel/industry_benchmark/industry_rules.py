"""
玄鉴 v3.0 - Industry Benchmark :: Industry Rules Engine

Provides industry-specific scan rules tailored to each industry's
technology stack and risk profile.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from .models import (
    Industry,
    IndustryRule,
    IndustryRuleSet,
)


# --- Built-in industry rules ---

_DEFENSE_IN_DEPTH_RULE = IndustryRule(
    rule_id="COMMON-DEFENSE-001",
    industry=Industry.INTERNET,
    name="Defense in Depth Verification",
    category="INSECURE_DESIGN",
    cwe="CWE-209",
    severity="MEDIUM",
    pattern="Check for missing layered security controls",
    description="Verify defense-in-depth is implemented across all layers",
    tech_targets=["*"],
    compliance_refs=[],
)

_INDUSTRY_RULES: Dict[Industry, List[IndustryRule]] = {
    Industry.INTERNET: [
        _DEFENSE_IN_DEPTH_RULE.model_copy(update={"industry": Industry.INTERNET}),
        IndustryRule(
            rule_id="INET-API-AUTH-001",
            industry=Industry.INTERNET,
            name="API Horizontal Privilege Escalation Check",
            category="BROKEN_ACCESS_CONTROL",
            cwe="CWE-284",
            severity="HIGH",
            pattern="id_or_resource_id in request params without ownership check",
            description="Verify APIs enforce resource-level authorization",
            tech_targets=["REST", "GraphQL", "gRPC"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.4"],
        ),
        IndustryRule(
            rule_id="INET-SSRF-001",
            industry=Industry.INTERNET,
            name="SSRF via user-supplied URLs",
            category="SSRF",
            cwe="CWE-918",
            severity="HIGH",
            pattern="url.open|requests.get|urllib with user input",
            description="Check for unfiltered URL requests",
            tech_targets=["Python", "Java", "Go", "Node.js"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.3"],
        ),
        IndustryRule(
            rule_id="INET-XSS-DOM-001",
            industry=Industry.INTERNET,
            name="DOM-based XSS",
            category="XSS",
            cwe="CWE-79",
            severity="MEDIUM",
            pattern="innerHTML|document.write|eval with user input",
            description="Detect client-side XSS vectors",
            tech_targets=["JavaScript", "TypeScript", "React", "Vue.js"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.3"],
        ),
        IndustryRule(
            rule_id="INET-CRYPTO-001",
            industry=Industry.INTERNET,
            name="Weak hash/encryption algorithm",
            category="CRYPTO_FAILURE",
            cwe="CWE-327",
            severity="HIGH",
            pattern="MD5|SHA1|DES|RC4",
            description="Detect usage of weak cryptographic algorithms",
            tech_targets=["*"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.4"],
        ),
    ],
    Industry.FINANCE: [
        IndustryRule(
            rule_id="FIN-LOGIC-001",
            industry=Industry.FINANCE,
            name="Transaction amount tampering check",
            category="BUSINESS_LOGIC",
            cwe="CWE-840",
            severity="CRITICAL",
            pattern="amount|price|fee in request without server-side re-validation",
            description="Verify transaction amounts are re-validated server-side",
            tech_targets=["Java", ".NET", "Spring"],
            compliance_refs=["JR/T 0071-2020 三级-8.1.3"],
        ),
        IndustryRule(
            rule_id="FIN-MFA-001",
            industry=Industry.FINANCE,
            name="Multi-factor authentication check",
            category="AUTH_FAILURE",
            cwe="CWE-287",
            severity="HIGH",
            pattern="login|password without mfa|otp verification",
            description="Sensitive operations must require MFA",
            tech_targets=["Java", "Spring", ".NET"],
            compliance_refs=["JR/T 0071-2020 三级-8.1.4"],
        ),
        IndustryRule(
            rule_id="FIN-CRYPTO-SM-001",
            industry=Industry.FINANCE,
            name="GuoMi (SM series) algorithm compliance",
            category="CRYPTO_FAILURE",
            cwe="CWE-327",
            severity="CRITICAL",
            pattern="encryption without SM2|SM3|SM4",
            description="Financial systems must support Chinese national crypto standards",
            tech_targets=["Java", "C++"],
            compliance_refs=["JR/T 0071-2020 三级-8.1.4"],
        ),
        IndustryRule(
            rule_id="FIN-IDOR-001",
            industry=Industry.FINANCE,
            name="IDOR in financial records",
            category="BROKEN_ACCESS_CONTROL",
            cwe="CWE-639",
            severity="HIGH",
            pattern="account_id|loan_id|policy_id without ownership check",
            description="Financial object access must verify ownership",
            tech_targets=["Java", "Spring", ".NET"],
            compliance_refs=["JR/T 0071-2020 三级-8.1.4"],
        ),
    ],
    Industry.GOVERNMENT: [
        IndustryRule(
            rule_id="GOV-SQL-001",
            industry=Industry.GOVERNMENT,
            name="SQL injection in government portal",
            category="INJECTION",
            cwe="CWE-89",
            severity="CRITICAL",
            pattern="statement.execute|createStatement with user input",
            description="Government portals must use parameterized queries exclusively",
            tech_targets=["Java", ".NET", "PHP"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.3"],
        ),
        IndustryRule(
            rule_id="GOV-PII-001",
            industry=Industry.GOVERNMENT,
            name="Citizen PII data protection",
            category="DATA_LEAKAGE",
            cwe="CWE-200",
            severity="CRITICAL",
            pattern="idcard|mobile|address without encryption/masking",
            description="Citizen PII must be encrypted or masked",
            tech_targets=["*"],
            compliance_refs=["个人信息保护法-第51条", "数据安全法-第27条"],
        ),
        IndustryRule(
            rule_id="GOV-SUPPLY-001",
            industry=Industry.GOVERNMENT,
            name="Third-party component audit (supply chain)",
            category="VULNERABLE_COMPONENTS",
            cwe="CWE-1035",
            severity="HIGH",
            pattern="import third party library without version lock",
            description="Government systems must track and audit all third-party components",
            tech_targets=["Java", "JavaScript", "Python"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.5"],
        ),
    ],
    Industry.INDUSTRIAL_CTRL: [
        IndustryRule(
            rule_id="ICS-PROTO-001",
            industry=Industry.INDUSTRIAL_CTRL,
            name="Unencrypted ICS protocol detection",
            category="INSECURE_PROTOCOL",
            cwe="CWE-299",
            severity="CRITICAL",
            pattern="Modbus|OPC|DNP3|IEC 61850 without TLS/VPN",
            description="Industrial control protocols must use encrypted tunnels",
            tech_targets=["C/C++", "Modbus", "OPC UA"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.3", "GB/T 39204-2022"],
        ),
        IndustryRule(
            rule_id="ICS-AUTH-001",
            industry=Industry.INDUSTRIAL_CTRL,
            name="Default/weak PLC credentials",
            category="AUTH_BYPASS",
            cwe="CWE-287",
            severity="CRITICAL",
            pattern="default password|hardcoded credential|no authentication",
            description="ICS devices must not use default credentials",
            tech_targets=["PLC", "HMI", "RTU"],
            compliance_refs=["GB/T 39204-2022"],
        ),
        IndustryRule(
            rule_id="ICS-BUF-001",
            industry=Industry.INDUSTRIAL_CTRL,
            name="Buffer overflow in firmware code",
            category="BUFFER_OVERFLOW",
            cwe="CWE-122",
            severity="CRITICAL",
            pattern="strcpy|sprintf|gets without bounds check",
            description="Firmware must avoid unsafe C/C++ memory operations",
            tech_targets=["C", "C++"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.3"],
        ),
    ],
    Industry.HEALTHCARE: [
        IndustryRule(
            rule_id="HC-PHI-001",
            industry=Industry.HEALTHCARE,
            name="Patient health information (PHI) exposure",
            category="DATA_LEAKAGE",
            cwe="CWE-200",
            severity="CRITICAL",
            pattern="patient_record|diagnosis|prescription without encryption",
            description="PHI must be encrypted at rest and in transit",
            tech_targets=["*"],
            compliance_refs=["健康医疗数据安全指南", "个人信息保护法-第51条"],
        ),
        IndustryRule(
            rule_id="HC-MFA-001",
            industry=Industry.HEALTHCARE,
            name="Healthcare system MFA requirement",
            category="AUTH_FAILURE",
            cwe="CWE-287",
            severity="HIGH",
            pattern="ehr|emr|his login without mfa",
            description="EHR/HIS systems must enforce MFA",
            tech_targets=["Java", ".NET"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.4"],
        ),
        IndustryRule(
            rule_id="HC-AVAIL-001",
            industry=Industry.HEALTHCARE,
            name="Healthcare system availability check",
            category="AVAILABILITY",
            cwe="CWE-400",
            severity="HIGH",
            pattern="no failover|no backup for medical systems",
            description="Critical medical systems must have high availability",
            tech_targets=["*"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.3"],
        ),
    ],
    Industry.EDUCATION: [
        IndustryRule(
            rule_id="EDU-SQL-001",
            industry=Industry.EDUCATION,
            name="Student info SQL injection",
            category="INJECTION",
            cwe="CWE-89",
            severity="CRITICAL",
            pattern="student_id|grade|course in SQL concatenation",
            description="Education platforms must use parameterized queries",
            tech_targets=["PHP", "Java", "Python"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.3"],
        ),
        IndustryRule(
            rule_id="EDU-CHILD-001",
            industry=Industry.EDUCATION,
            name="Child privacy protection (under 14)",
            category="DATA_LEAKAGE",
            cwe="CWE-200",
            severity="HIGH",
            pattern="child|minor|student_age < 14 data collected without parental consent",
            description="Children data requires parental consent mechanisms",
            tech_targets=["*"],
            compliance_refs=["儿童个人信息网络保护规定"],
        ),
    ],
    Industry.TELECOM: [
        IndustryRule(
            rule_id="TEL-PROTO-001",
            industry=Industry.TELECOM,
            name="SIP/Diameter protocol vulnerability",
            category="PROTOCOL_VULN",
            cwe="CWE-299",
            severity="CRITICAL",
            pattern="SIP|Diameter signaling without IPsec/TLS",
            description="Telecom signaling protocols must be encrypted",
            tech_targets=["C/C++", "SIP", "Diameter"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.3"],
        ),
        IndustryRule(
            rule_id="TEL-BILL-001",
            industry=Industry.TELECOM,
            name="Billing system integrity check",
            category="BUSINESS_LOGIC",
            cwe="CWE-840",
            severity="CRITICAL",
            pattern="billing|charging without integrity check",
            description="Billing data must have integrity protection",
            tech_targets=["Java", "C++"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.3"],
        ),
    ],
    Industry.ENERGY: [
        IndustryRule(
            rule_id="NRG-SCADA-001",
            industry=Industry.ENERGY,
            name="SCADA unencrypted protocol (IEC 61850/Modbus)",
            category="INSECURE_PROTOCOL",
            cwe="CWE-299",
            severity="CRITICAL",
            pattern="IEC 61850|Modbus|DNP3 without TLS/VPN/tunnel",
            description="SCADA comms must be encrypted via VPN or protocol-level TLS",
            tech_targets=["C/C++", "IEC 61850", "Modbus"],
            compliance_refs=["电力监控系统安全防护规定", "GB/T 22239-2019 三级-8.1.3"],
        ),
        IndustryRule(
            rule_id="NRG-AUTH-001",
            industry=Industry.ENERGY,
            name="Energy system credential default check",
            category="AUTH_BYPASS",
            cwe="CWE-287",
            severity="CRITICAL",
            pattern="default password|hardcoded token in SCADA/HMI",
            description="Energy systems must not ship with default credentials",
            tech_targets=["PLC", "HMI", "RTU", "SCADA"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.4"],
        ),
    ],
    Industry.TRANSPORTATION: [
        IndustryRule(
            rule_id="TRA-SIG-001",
            industry=Industry.TRANSPORTATION,
            name="Signal system access control check",
            category="SIG_SYS_VULN",
            cwe="CWE-284",
            severity="CRITICAL",
            pattern="signal|track|switch control without authorization",
            description="Signal system controls must verify strict authorization",
            tech_targets=["C/C++", "CBTC", "ATC"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.4"],
        ),
        IndustryRule(
            rule_id="TRA-GPS-001",
            industry=Industry.TRANSPORTATION,
            name="GPS/BeiDou spoofing protection",
            category="GPS_SPOOFING",
            cwe="CWE-290",
            severity="CRITICAL",
            pattern="GPS location used without validation/consistency check",
            description="Location data must be validated for spoof protection",
            tech_targets=["C/C++", "Python"],
            compliance_refs=["GB/T 22239-2019 三级-8.1.3"],
        ),
    ],
    Industry.INSURANCE: [
        IndustryRule(
            rule_id="INS-LOGIC-001",
            industry=Industry.INSURANCE,
            name="Insurance claim logic bypass check",
            category="BUSINESS_LOGIC",
            cwe="CWE-840",
            severity="CRITICAL",
            pattern="claim_amount|coverage|premium without server-side validation",
            description="Claims must be server-side validated",
            tech_targets=["Java", ".NET"],
            compliance_refs=["JR/T 0071-2020 三级-8.1.3"],
        ),
        IndustryRule(
            rule_id="INS-PII-001",
            industry=Industry.INSURANCE,
            name="Insurance client data protection",
            category="DATA_LEAKAGE",
            cwe="CWE-200",
            severity="CRITICAL",
            pattern="policy_holder|beneficiary|health_record without encryption",
            description="Insurance client data must be encrypted",
            tech_targets=["*"],
            compliance_refs=["个人信息保护法-第51条", "个人金融信息保护技术规范"],
        ),
    ],
    Industry.SECURITIES: [
        IndustryRule(
            rule_id="SEC-LOGIC-001",
            industry=Industry.SECURITIES,
            name="Trading logic manipulation prevention",
            category="BUSINESS_LOGIC",
            cwe="CWE-840",
            severity="CRITICAL",
            pattern="order_price|quantity|execution_time without integrity check",
            description="Trading orders must have integrity verification",
            tech_targets=["Java", "C++", "Rust", "FPGA"],
            compliance_refs=["JR/T 0071-2020 三级-8.1.3"],
        ),
        IndustryRule(
            rule_id="SEC-LATENCY-001",
            industry=Industry.SECURITIES,
            name="Latency equalization (HFT fairness)",
            category="LATENCY_EXPLOIT",
            cwe=None,
            severity="CRITICAL",
            pattern="co-location|direct exchange feed without latency floor",
            description="High-frequency trading must implement latency floors",
            tech_targets=["C++", "FPGA"],
            compliance_refs=["JR/T 0071-2020 三级-8.1.3"],
        ),
        IndustryRule(
            rule_id="SEC-MARKET-001",
            industry=Industry.SECURITIES,
            name="Market manipulation detection",
            category="MARKET_MANIPULATION",
            cwe=None,
            severity="CRITICAL",
            pattern="spoofing|layering|quote stuffing patterns detected",
            description="Detect potential market manipulation patterns",
            tech_targets=["Java", "C++"],
            compliance_refs=["证券法-第77条"],
        ),
    ],
}


class IndustryRuleEngine:
    """
    Industry-specific rule set management engine.
    """

    def __init__(self) -> None:
        self._rule_sets: Dict[Industry, IndustryRuleSet] = {}
        self._load_builtin_rules()

    def _load_builtin_rules(self) -> None:
        """Load all built-in industry rules"""
        for industry, rules in _INDUSTRY_RULES.items():
            self._rule_sets[industry] = IndustryRuleSet(
                industry=industry,
                rules=rules,
                version="3.0.0",
            )

    def get_rule_set(self, industry: Industry) -> IndustryRuleSet:
        """Get the rule set for an industry"""
        if industry not in self._rule_sets:
            self._rule_sets[industry] = IndustryRuleSet(
                industry=industry,
                rules=[_DEFENSE_IN_DEPTH_RULE.model_copy(update={"industry": industry})],
                version="3.0.0",
            )
        return self._rule_sets[industry]

    def add_rule(self, industry: Industry, rule: IndustryRule) -> None:
        """Add a custom rule to an industry"""
        rs = self.get_rule_set(industry)
        rs.rules.append(rule)

    def get_rules_for_tech(self, industry: Industry, tech: str) -> List[IndustryRule]:
        """Get rules targeting a specific technology stack"""
        rs = self.get_rule_set(industry)
        return [
            r for r in rs.enabled_rules
            if "*" in r.tech_targets or tech in r.tech_targets
        ]

    def enable_rule(self, industry: Industry, rule_id: str, enabled: bool = True) -> bool:
        """Enable or disable a specific rule"""
        rs = self.get_rule_set(industry)
        for rule in rs.rules:
            if rule.rule_id == rule_id:
                rule.enabled = enabled
                return True
        return False

    def get_all_industries_with_rules(self) -> List[Industry]:
        """List all industries that have rules"""
        return list(self._rule_sets.keys())

    def count_rules(self, industry: Optional[Industry] = None) -> int:
        """Count rules, optionally filtered by industry"""
        if industry:
            return len(self.get_rule_set(industry).rules)
        return sum(len(rs.rules) for rs in self._rule_sets.values())


def get_industry_rule_set(industry: Industry) -> IndustryRuleSet:
    """Convenience function: get rule set for an industry"""
    engine = IndustryRuleEngine()
    return engine.get_rule_set(industry)


def list_industry_rules(industry: Industry, enabled_only: bool = True) -> List[IndustryRule]:
    """
    Convenience function: list all rules for an industry.

    Args:
        industry: Target industry
        enabled_only: If True, return only enabled rules

    Returns:
        List of rules
    """
    rs = get_industry_rule_set(industry)
    if enabled_only:
        return rs.enabled_rules
    return rs.rules
