"""attack/harmless_verifier 测试 — 基于源码的静态用例，不依赖外网。"""

import unittest
from unittest.mock import MagicMock

from fp_sentinel.attack.harmless_verifier.verifier import (
    HarmlessVerifier,
    HarmlessVerifyResult,
    HarmlessVerifyStep,
    VerificationReport,
    VerifyConfidence,
)


class TestVerifyConfidence(unittest.TestCase):
    """Test VerifyConfidence enum values."""

    def test_enum_values(self):
        """Verify enum has all expected values."""
        expected = {"high", "medium", "low", "uncertain"}
        actual = {c.value for c in VerifyConfidence}
        self.assertEqual(expected, actual)

    def test_enum_members(self):
        """Verify individual members exist."""
        self.assertEqual(VerifyConfidence.HIGH.value, "high")
        self.assertEqual(VerifyConfidence.MEDIUM.value, "medium")
        self.assertEqual(VerifyConfidence.LOW.value, "low")
        self.assertEqual(VerifyConfidence.UNCERTAIN.value, "uncertain")


class TestRuleIdToVulnType(unittest.TestCase):
    """Test _rule_id_to_vuln_type mapping logic."""

    def setUp(self):
        self.verifier = HarmlessVerifier()

    def test_sqli_injection_prefix(self):
        """Verify 'python.lang.injection.sql.execution' maps to 'sqli'."""
        result = self.verifier._rule_id_to_vuln_type("python.lang.injection.sql.execution")
        self.assertEqual(result, "sqli")

    def test_xss_dom_prefix(self):
        """Verify 'xss.dom' maps to 'xss'."""
        result = self.verifier._rule_id_to_vuln_type("xss.dom")
        self.assertEqual(result, "xss")

    def test_random_rule_id_returns_empty(self):
        """Verify unrecognized rule_id returns empty string."""
        result = self.verifier._rule_id_to_vuln_type("random")
        self.assertEqual(result, "")

    def test_empty_rule_id(self):
        """Verify empty rule_id returns empty string."""
        result = self.verifier._rule_id_to_vuln_type("")
        self.assertEqual(result, "")

    def test_ssrf_rule(self):
        """Verify ssrf rule maps correctly."""
        result = self.verifier._rule_id_to_vuln_type("ssrf.url-open")
        self.assertEqual(result, "ssrf")

    def test_deserialization_rule(self):
        """Verify deserialization rule maps correctly."""
        result = self.verifier._rule_id_to_vuln_type("deserialization.object-stream")
        self.assertEqual(result, "deserialization")

    def test_path_traversal_rule(self):
        """Verify path traversal rule maps correctly."""
        result = self.verifier._rule_id_to_vuln_type("path.traversal.read")
        self.assertEqual(result, "path_traversal")

    def test_crypto_weak_rule(self):
        """Verify crypto weak hash rule maps correctly."""
        result = self.verifier._rule_id_to_vuln_type("crypto.weak.hash.md5")
        self.assertEqual(result, "crypto_weak")

    def test_hardcoded_secret_rule(self):
        """Verify hardcoded secret rule maps correctly."""
        result = self.verifier._rule_id_to_vuln_type("hardcoded.secret.password")
        self.assertEqual(result, "hardcoded_secret")


class TestDetectSink(unittest.TestCase):
    """Test _detect_sink regex patterns for 10 categories."""

    def setUp(self):
        self.verifier = HarmlessVerifier()

    def _detect(self, source, rule_id):
        return self.verifier._detect_sink(source, rule_id)

    def test_sqli_pattern(self):
        """Verify SQL injection sink is detected."""
        source = "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)"
        match, pattern = self._detect(source, "python.lang.injection.sql.execution")
        self.assertTrue(match)

    def test_xss_pattern(self):
        """Verify XSS sink is detected."""
        source = 'element.innerHTML = userInput'
        match, pattern = self._detect(source, "xss.dom")
        self.assertTrue(match)

    def test_cmd_injection_pattern(self):
        """Verify command injection sink is detected."""
        source = 'os.system("ls " + user_input)'
        match, pattern = self._detect(source, "injection.command.exec")
        self.assertTrue(match)

    def test_path_traversal_pattern(self):
        """Verify path traversal sink is detected."""
        source = 'open("/data/" + filename, "r")'
        match, pattern = self._detect(source, "path.traversal.read")
        self.assertTrue(match)

    def test_ssrf_pattern(self):
        """Verify SSRF sink is detected."""
        source = 'requests.get("http://" + user_url)'
        match, pattern = self._detect(source, "ssrf.url-open")
        self.assertTrue(match)

    def test_deserialization_pattern(self):
        """Verify deserialization sink is detected."""
        source = "pickle.loads(data)"
        match, pattern = self._detect(source, "deserialization.object-stream")
        self.assertTrue(match)

    def test_ssti_pattern(self):
        """Verify SSTI sink is detected."""
        source = "Template(user_input).render()"
        match, pattern = self._detect(source, "injection.template.render")
        self.assertTrue(match)

    def test_xxe_pattern(self):
        """Verify XXE sink is detected."""
        source = "from lxml import etree"
        match, pattern = self._detect(source, "injection.xml.parse")
        self.assertTrue(match)

    def test_crypto_weak_pattern(self):
        """Verify weak crypto sink is detected."""
        source = "hash = md5(password.encode())"
        match, pattern = self._detect(source, "crypto.weak.hash.md5")
        self.assertTrue(match)

    def test_hardcoded_secret_pattern(self):
        """Verify hardcoded secret sink is detected."""
        source = "password = 'super_secret_123'"
        match, pattern = self._detect(source, "hardcoded.secret.password")
        self.assertTrue(match)

    def test_no_match_returns_false(self):
        """Verify non-matching source returns False."""
        source = "print('hello world')"
        match, pattern = self._detect(source, "injection.sql-execution")
        self.assertFalse(match)
        self.assertEqual(pattern, "")

    def test_unrecognized_rule_with_dangerous_source(self):
        """Verify unrecognized rule returns False even with dangerous source."""
        source = "os.system(evil)"
        match, pattern = self._detect(source, "random.rule")
        # random.rule maps to "" vuln_type, no patterns to check
        self.assertFalse(match)


class TestVerifyFinding(unittest.TestCase):
    """Test verify_finding returns complete HarmlessVerifyResult."""

    def _make_finding(self, **kwargs):
        """Create a mock Finding-like object."""
        finding = MagicMock()
        finding.id = kwargs.get("id", "finding-001")
        finding.rule_id = kwargs.get("rule_id", "injection.sql-execution")
        finding.file_path = kwargs.get("file_path", "/app/views.py")
        finding.line_start = kwargs.get("line_start", 42)
        finding.category = kwargs.get("category", "sql_injection")
        return finding

    def test_returns_harmless_verify_result(self):
        """Verify verify_finding returns HarmlessVerifyResult."""
        verifier = HarmlessVerifier()
        finding = self._make_finding()
        result = verifier.verify_finding(finding)
        self.assertIsInstance(result, HarmlessVerifyResult)

    def test_fields_populated(self):
        """Verify result has required fields populated."""
        verifier = HarmlessVerifier()
        finding = self._make_finding()
        result = verifier.verify_finding(finding)
        self.assertEqual(result.finding_id, "finding-001")
        self.assertEqual(result.rule_id, "injection.sql-execution")
        self.assertEqual(result.file_path, "/app/views.py")
        self.assertEqual(result.line, 42)
        self.assertIsInstance(result.confidence, VerifyConfidence)
        self.assertIsInstance(result.steps, list)
        self.assertIsInstance(result.verified, bool)

    def test_result_is_harmless(self):
        """Verify result always has is_harmless=True."""
        verifier = HarmlessVerifier()
        finding = self._make_finding()
        result = verifier.verify_finding(finding)
        self.assertTrue(result.is_harmless)

    def test_result_has_timestamp(self):
        """Verify result has timestamp string."""
        verifier = HarmlessVerifier()
        finding = self._make_finding()
        result = verifier.verify_finding(finding)
        self.assertIsInstance(result.timestamp, str)
        self.assertGreater(len(result.timestamp), 0)

    def test_result_has_duration(self):
        """Verify result has duration_ms."""
        verifier = HarmlessVerifier()
        finding = self._make_finding()
        result = verifier.verify_finding(finding)
        self.assertIsInstance(result.duration_ms, float)
        self.assertGreaterEqual(result.duration_ms, 0)

    def test_confidence_in_valid_set(self):
        """Verify confidence is one of the valid enum values."""
        verifier = HarmlessVerifier()
        finding = self._make_finding()
        result = verifier.verify_finding(finding)
        self.assertIn(result.confidence.value, {"high", "medium", "low", "uncertain"})

    def test_nonexistent_file_path(self):
        """Verify non-existent file path returns UNCERTAIN confidence."""
        verifier = HarmlessVerifier()
        finding = self._make_finding(file_path="/nonexistent/file.py")
        result = verifier.verify_finding(finding)
        self.assertEqual(result.confidence, VerifyConfidence.UNCERTAIN)
        self.assertIn("not readable", result.summary)


class TestVerifyFindings(unittest.TestCase):
    """Test verify_findings aggregation into VerificationReport."""

    def _make_finding(self, **kwargs):
        finding = MagicMock()
        finding.id = kwargs.get("id", "finding-001")
        finding.rule_id = kwargs.get("rule_id", "injection.sql-execution")
        finding.file_path = kwargs.get("file_path", "/app/views.py")
        finding.line_start = kwargs.get("line_start", 42)
        finding.category = kwargs.get("category", "sql_injection")
        return finding

    def test_returns_verification_report(self):
        """Verify verify_findings returns VerificationReport."""
        verifier = HarmlessVerifier()
        findings = [self._make_finding(id="f1"), self._make_finding(id="f2")]
        report = verifier.verify_findings(findings)
        self.assertIsInstance(report, VerificationReport)

    def test_report_summary_fields(self):
        """Verify report.summary() has all expected keys."""
        verifier = HarmlessVerifier()
        findings = [self._make_finding(id="f1")]
        report = verifier.verify_findings(findings)
        summary = report.summary()
        expected_keys = {"report_id", "project", "total", "verified",
                         "simulated", "manual_required", "errors", "coverage_pct"}
        for key in expected_keys:
            self.assertIn(key, summary)

    def test_report_total_findings(self):
        """Verify report total matches number of input findings."""
        verifier = HarmlessVerifier()
        findings = [self._make_finding(id=f"f{i}") for i in range(5)]
        report = verifier.verify_findings(findings)
        self.assertEqual(report.total_findings, 5)

    def test_report_results_count(self):
        """Verify results list length matches input."""
        verifier = HarmlessVerifier()
        findings = [self._make_finding(id="f1"), self._make_finding(id="f2")]
        report = verifier.verify_findings(findings)
        self.assertEqual(len(report.results), 2)


class TestHarmlessVerifyResultModel(unittest.TestCase):
    """Test HarmlessVerifyResult dataclass defaults."""

    def test_default_finding_id(self):
        """Verify default finding_id is empty string."""
        result = HarmlessVerifyResult()
        self.assertEqual(result.finding_id, "")

    def test_default_confidence(self):
        """Verify default confidence is UNCERTAIN."""
        result = HarmlessVerifyResult()
        self.assertEqual(result.confidence, VerifyConfidence.UNCERTAIN)

    def test_default_verified_false(self):
        """Verify default verified is False."""
        result = HarmlessVerifyResult()
        self.assertFalse(result.verified)

    def test_default_steps_empty_list(self):
        """Verify default steps is an empty list."""
        result = HarmlessVerifyResult()
        self.assertEqual(result.steps, [])

    def test_to_dict_includes_fields(self):
        """Verify to_dict() produces expected keys."""
        result = HarmlessVerifyResult(
            finding_id="f1", rule_id="xss.dom",
            confidence=VerifyConfidence.HIGH,
        )
        d = result.to_dict()
        self.assertEqual(d["finding_id"], "f1")
        self.assertEqual(d["rule_id"], "xss.dom")
        self.assertEqual(d["confidence"], "high")
        self.assertIn("is_harmless", d)
        self.assertTrue(d["is_harmless"])


if __name__ == "__main__":
    unittest.main()
