"""
Tests for the Harmless Auto-Verification Engine (v3.1)

Tests: verifier core, step generator, sink detection, full verification flow
Coverage target: >= 95%
"""

import sys
import os
import tempfile
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


class TestHarmlessVerifierModels(unittest.TestCase):
    def test_confidence_enum(self):
        from fp_sentinel.attack.harmless_verifier.verifier import VerifyConfidence
        self.assertEqual(VerifyConfidence.HIGH.value, "high")
        self.assertEqual(VerifyConfidence.MEDIUM.value, "medium")
        self.assertEqual(VerifyConfidence.LOW.value, "low")

    def test_harmless_verify_step(self):
        from fp_sentinel.attack.harmless_verifier.verifier import HarmlessVerifyStep
        step = HarmlessVerifyStep(step_number=1, action="read source", passed=True)
        self.assertEqual(step.step_number, 1)
        self.assertTrue(step.passed)

    def test_harmless_verify_result_defaults(self):
        from fp_sentinel.attack.harmless_verifier.verifier import HarmlessVerifyResult
        r = HarmlessVerifyResult()
        self.assertTrue(r.is_harmless)

    def test_harmless_verify_result_to_dict(self):
        from fp_sentinel.attack.harmless_verifier.verifier import HarmlessVerifyResult
        r = HarmlessVerifyResult(
            finding_id="f1", rule_id="sql_injection",
            file_path="app.py", line=42, vuln_category="sqli",
        )
        d = r.to_dict()
        self.assertEqual(d["finding_id"], "f1")
        self.assertTrue(d["is_harmless"])
        self.assertIn("reproducible_steps", d)

    def test_verification_report_summary(self):
        from fp_sentinel.attack.harmless_verifier.verifier import VerificationReport
        report = VerificationReport(
            report_id="r1", project="test",
            total_findings=10, verified_count=5,
            simulated_count=3, manual_count=2,
        )
        s = report.summary()
        self.assertEqual(s["total"], 10)
        self.assertIn("coverage_pct", s)


class TestHarmlessVerifierCore(unittest.TestCase):
    def test_init(self):
        from fp_sentinel.attack.harmless_verifier.verifier import HarmlessVerifier
        v = HarmlessVerifier(project_root=".", allow_docker=False)
        self.assertEqual(v.project_root, ".")
        self.assertFalse(v.allow_docker)

    def test_sink_patterns_loaded(self):
        from fp_sentinel.attack.harmless_verifier.verifier import HarmlessVerifier
        v = HarmlessVerifier()
        self.assertIn("sqli", v.SINK_PATTERNS)
        self.assertIn("xss", v.SINK_PATTERNS)
        self.assertIn("cmd_injection", v.SINK_PATTERNS)
        self.assertIn("deserialization", v.SINK_PATTERNS)
        self.assertTrue(len(v.SINK_PATTERNS) >= 10)

    def test_rule_id_to_vuln_type(self):
        from fp_sentinel.attack.harmless_verifier.verifier import HarmlessVerifier
        v = HarmlessVerifier()
        self.assertEqual(v._rule_id_to_vuln_type("sqli-injection"), "sqli")
        self.assertEqual(v._rule_id_to_vuln_type("xss-dom"), "xss")
        self.assertEqual(v._rule_id_to_vuln_type("deserialize-object"), "deserialization")
        self.assertEqual(v._rule_id_to_vuln_type("unknown-rule"), "")

    def test_get_safe_payload(self):
        from fp_sentinel.attack.harmless_verifier.verifier import HarmlessVerifier
        v = HarmlessVerifier()
        sqli = v._get_safe_payload("sqli")
        self.assertIn("fp_sentinel_verify", sqli)
        xss = v._get_safe_payload("xss")
        self.assertIn("fp_sentinel_verify", xss)
        unknown = v._get_safe_payload("nonexistent")
        self.assertEqual(unknown, "fp_sentinel_verify")

    def test_get_remediation_hint(self):
        from fp_sentinel.attack.harmless_verifier.verifier import HarmlessVerifier
        v = HarmlessVerifier()
        hint = v._get_remediation_hint("sql-injection")
        self.assertIn("parameterized", hint.lower())
        hint2 = v._get_remediation_hint("xss-dom")
        self.assertIn("textContent", hint2)
        hint3 = v._get_remediation_hint("unknown-rule")
        self.assertIn("security", hint3.lower())


class TestSinkDetection(unittest.TestCase):
    def setUp(self):
        from fp_sentinel.attack.harmless_verifier.verifier import HarmlessVerifier
        self.verifier = HarmlessVerifier()

    def test_detect_sqli_sink(self):
        source = "def get_user(id):\n    db.execute('SELECT * FROM users WHERE id = ' + id)"
        matched, pattern = self.verifier._detect_sink(source, "sqli-injection")
        self.assertTrue(matched)

    def test_no_false_positive_sqli(self):
        source = "def get_user(id):\n    db.execute('SELECT 1')"
        matched, _ = self.verifier._detect_sink(source, "sqli-injection")
        self.assertFalse(matched)

    def test_detect_xss_sink(self):
        source = "element.innerHTML = userInput"
        matched, _ = self.verifier._detect_sink(source, "xss-dom")
        self.assertTrue(matched)

    def test_detect_deserialization_sink(self):
        source = "obj = pickle.loads(data)"
        matched, _ = self.verifier._detect_sink(source, "deserialize-pickle")
        self.assertTrue(matched)

    def test_detect_eval_sink(self):
        source = "result = eval(user_code)"
        matched, _ = self.verifier._detect_sink(source, "cmd-injection")
        self.assertTrue(matched)

    def test_trace_input(self):
        source = "id = request.args['id']\ndb.execute('SELECT * FROM users WHERE id = ' + id)"
        matched, _ = self.verifier._trace_input(source)
        self.assertTrue(matched)

    def test_no_input_trace(self):
        source = "def helper():\n    return 42"
        matched, _ = self.verifier._trace_input(source)
        self.assertFalse(matched)


class TestVerifyFinding(unittest.TestCase):
    def test_verify_finding_with_source_file(self):
        from fp_sentinel.attack.harmless_verifier.verifier import HarmlessVerifier
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("def get_user(id):\n")
            f.write("    import os\n")
            f.write("    os.system('ping ' + id)\n")
            f.flush()
            tmpfile = f.name

        try:
            verifier = HarmlessVerifier(project_root=os.path.dirname(tmpfile))
            finding = MagicMock()
            finding.id = "f1"
            finding.rule_id = "cmd-injection-os-system"
            finding.file_path = tmpfile
            finding.line_start = 3
            finding.category = "cmd_injection"

            result = verifier.verify_finding(finding)
            self.assertTrue(result.is_harmless)
            self.assertGreater(len(result.steps), 0)
            self.assertGreater(len(result.reproducible_steps), 0)
        finally:
            os.unlink(tmpfile)

    def test_verify_finding_no_source(self):
        from fp_sentinel.attack.harmless_verifier.verifier import HarmlessVerifier
        verifier = HarmlessVerifier(project_root="/nonexistent/path")
        finding = MagicMock()
        finding.id = "f2"
        finding.rule_id = "sql-injection"
        finding.file_path = "/nonexistent/file.py"
        finding.line_start = 10
        finding.category = "sqli"

        result = verifier.verify_finding(finding)
        self.assertTrue(result.is_harmless)
        self.assertEqual(result.confidence.__class__.__name__, "VerifyConfidence")

    def test_verify_findings_batch(self):
        from fp_sentinel.attack.harmless_verifier.verifier import HarmlessVerifier
        verifier = HarmlessVerifier(project_root="/nonexistent")
        findings = []
        for i in range(5):
            f = MagicMock()
            f.id = f"f{i}"
            f.rule_id = "rule-" + str(i)
            f.file_path = "/nonexistent/file" + str(i) + ".py"
            f.line_start = 10 + i
            f.category = "test"
            findings.append(f)

        report = verifier.verify_findings(findings)
        self.assertEqual(report.total_findings, 5)
        self.assertEqual(len(report.results), 5)
        self.assertIsNotNone(report.completed_at)


class TestStepGenerator(unittest.TestCase):
    def test_generate_reproducible_steps(self):
        from fp_sentinel.attack.harmless_verifier.step_generator import (
            generate_reproducible_steps,
        )
        from fp_sentinel.attack.harmless_verifier.verifier import (
            HarmlessVerifyResult, VerifyConfidence,
        )
        result = HarmlessVerifyResult(
            finding_id="f1", rule_id="sqli-injection",
            file_path="app.py", line=42,
            confidence=VerifyConfidence.HIGH,
            sink_identified=True, input_traced=True,
            remediation_hint="Use parameterized queries",
        )
        steps = generate_reproducible_steps(result)
        self.assertTrue(len(steps) >= 4)

    def test_build_verification_report(self):
        from fp_sentinel.attack.harmless_verifier.step_generator import (
            build_verification_report,
        )
        from fp_sentinel.attack.harmless_verifier.verifier import (
            HarmlessVerifyResult, VerifyConfidence,
        )
        results = [
            HarmlessVerifyResult(
                finding_id=f"f{i}", confidence=VerifyConfidence.HIGH,
            ) for i in range(3)
        ] + [
            HarmlessVerifyResult(
                finding_id="f_low", confidence=VerifyConfidence.LOW,
            )
        ]
        report = build_verification_report(results, project_name="test-proj")
        self.assertEqual(report["total_findings"], 4)
        self.assertEqual(report["verified"]["high_confidence"], 3)
        self.assertTrue(report["is_harmless"])
        self.assertIn("coverage_pct", report)

    def test_get_remediation_for_rule(self):
        from fp_sentinel.attack.harmless_verifier.step_generator import (
            get_remediation_for_rule,
        )
        self.assertIn("parameterized", get_remediation_for_rule("sql-injection").lower())
        self.assertIn("shell", get_remediation_for_rule("cmd-injection").lower())
        self.assertIn("practice", get_remediation_for_rule("unknown-rule").lower())

    def test_step_generator_with_empty_result(self):
        from fp_sentinel.attack.harmless_verifier.step_generator import (
            generate_reproducible_steps,
        )
        from fp_sentinel.attack.harmless_verifier.verifier import (
            HarmlessVerifyResult, VerifyConfidence,
        )
        result = HarmlessVerifyResult(
            finding_id="empty", confidence=VerifyConfidence.UNCERTAIN,
        )
        steps = generate_reproducible_steps(result)
        self.assertTrue(len(steps) > 0)


class TestVerificationWithSourceContent(unittest.TestCase):
    def test_full_sqli_verification(self):
        from fp_sentinel.attack.harmless_verifier.verifier import (
            HarmlessVerifier, VerifyConfidence,
        )
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("# Vulnerable SQL code\n")
            f.write("from flask import request\n")
            f.write("def search():\n")
            f.write("    q = request.args.get('q')\n")
            f.write("    query = 'SELECT * FROM products WHERE name LIKE %' + q\n")
            f.write("    cursor.execute(query)\n")
            f.flush()
            tmpfile = f.name

        try:
            verifier = HarmlessVerifier(project_root=os.path.dirname(tmpfile))
            finding = MagicMock()
            finding.id = "full-sqli-1"
            finding.rule_id = "sql-injection-string-concat"
            finding.file_path = tmpfile
            finding.line_start = 6
            finding.category = "sqli"

            result = verifier.verify_finding(finding)
            self.assertTrue(result.sink_identified)
            self.assertTrue(result.input_traced)
            self.assertEqual(result.confidence, VerifyConfidence.HIGH)
            self.assertTrue(result.verified)
            self.assertGreater(len(result.steps), 3)
            self.assertTrue(len(result.remediation_hint) > 0)
        finally:
            os.unlink(tmpfile)

    def test_full_xss_verification(self):
        from fp_sentinel.attack.harmless_verifier.verifier import (
            HarmlessVerifier, VerifyConfidence,
        )
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write("// Vulnerable JS code\n")
            f.write("const params = new URLSearchParams(window.location.search);\n")
            f.write("const name = params.get('name');\n")
            f.write("document.getElementById('greeting').innerHTML = name;\n")
            f.flush()
            tmpfile = f.name

        try:
            verifier = HarmlessVerifier(project_root=os.path.dirname(tmpfile))
            finding = MagicMock()
            finding.id = "full-xss-1"
            finding.rule_id = "xss-dom-innerhtml"
            finding.file_path = tmpfile
            finding.line_start = 4
            finding.category = "xss"

            result = verifier.verify_finding(finding)
            self.assertTrue(result.sink_identified)
            self.assertTrue(result.input_traced)
            self.assertEqual(result.confidence, VerifyConfidence.HIGH)
        finally:
            os.unlink(tmpfile)

    def test_hardcoded_secret_verification(self):
        from fp_sentinel.attack.harmless_verifier.verifier import (
            HarmlessVerifier, VerifyConfidence,
        )
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("# Configuration file\n")
            f.write("DATABASE_PASSWORD = 'SuperSecret123!'\n")
            f.write("API_SECRET = 'sk_live_abcdef123456'\n")
            f.flush()
            tmpfile = f.name

        try:
            verifier = HarmlessVerifier(project_root=os.path.dirname(tmpfile))
            finding = MagicMock()
            finding.id = "sec-1"
            finding.rule_id = "hardcoded-secret-password"
            finding.file_path = tmpfile
            finding.line_start = 2
            finding.category = "HARDCODED_SECRET"

            result = verifier.verify_finding(finding)
            self.assertTrue(result.sink_identified)
        finally:
            os.unlink(tmpfile)


if __name__ == "__main__":
    unittest.main()
