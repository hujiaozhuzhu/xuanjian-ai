"""attack 全链路 pipeline 测试 — scan → verify → report 端到端串联验证。"""

import unittest
from unittest.mock import MagicMock

from fp_sentinel.attack.harmless_verifier import HarmlessVerifier
from fp_sentinel.attack.harmless_verifier.step_generator import (
    generate_reproducible_steps,
    build_verification_report,
)
from fp_sentinel.attack.harmless_verifier.verifier import (
    HarmlessVerifyResult,
    VerifyConfidence,
    VerificationReport,
)


def _make_mock_finding(**kwargs):
    """Construct a mock Finding with SQL injection attributes."""
    finding = MagicMock()
    finding.id = kwargs.get("id", "pipeline-finding-001")
    finding.rule_id = kwargs.get("rule_id", "injection.sql-execution")
    finding.file_path = kwargs.get("file_path", "/app/controllers/user.py")
    finding.line_start = kwargs.get("line_start", 55)
    finding.category = kwargs.get("category", "sql_injection")
    return finding


class TestFullPipeline(unittest.TestCase):
    """Test scan -> verify -> report end-to-end pipeline."""

    def test_full_pipeline(self):
        """Verify full pipeline: finding -> verify -> steps -> report."""
        # 1. Construct a mock Finding with sqli keyword
        finding = _make_mock_finding()

        # 2. verifier.verify_finding(finding) -> result
        verifier = HarmlessVerifier()
        result = verifier.verify_finding(finding)

        # 3. generate_reproducible_steps(result) -> list of str
        steps = generate_reproducible_steps(result)
        self.assertIsInstance(steps, list)
        self.assertGreater(len(steps), 0)
        for step in steps:
            self.assertIsInstance(step, str)
            self.assertGreater(len(step), 0)

        # 4. build_verification_report([result]) -> report with summary
        report = build_verification_report([result], project_name="test-project")
        self.assertIn("project", report)
        self.assertEqual(report["project"], "test-project")
        self.assertIn("total_findings", report)
        self.assertIn("verified", report)
        self.assertIn("findings", report)
        self.assertTrue(report["is_harmless"])

        # 5. Verify confidence value is in valid set
        self.assertIn(
            result.confidence.value, {"high", "medium", "low", "uncertain"}
        )

    def test_pipeline_multiple_findings(self):
        """Verify pipeline handles multiple findings."""
        sqli_finding = _make_mock_finding(id="f1", rule_id="injection.sql-execution")
        xss_finding = _make_mock_finding(
            id="f2", rule_id="xss.dom",
            file_path="/app/views/template.html",
            category="xss",
        )

        verifier = HarmlessVerifier()
        result1 = verifier.verify_finding(sqli_finding)
        result2 = verifier.verify_finding(xss_finding)

        report = build_verification_report([result1, result2], project_name="multi")
        self.assertEqual(report["total_findings"], 2)
        self.assertEqual(len(report["findings"]), 2)

        # Each finding should be harmless
        for finding_dict in report["findings"]:
            self.assertTrue(finding_dict["is_harmless"])

    def test_pipeline_with_verification_report_object(self):
        """Verify VerificationReport object path via verify_findings."""
        finding = _make_mock_finding()

        verifier = HarmlessVerifier()
        report = verifier.verify_findings([finding])

        self.assertIsInstance(report, VerificationReport)
        self.assertEqual(report.total_findings, 1)
        self.assertEqual(len(report.results), 1)

        # Summary should be callable and return dict
        summary = report.summary()
        self.assertIsInstance(summary, dict)
        self.assertIn("coverage_pct", summary)

    def test_steps_format_contains_step_markers(self):
        """Verify generated steps contain [Step N] format markers."""
        finding = _make_mock_finding()
        verifier = HarmlessVerifier()
        result = verifier.verify_finding(finding)
        steps = generate_reproducible_steps(result)

        for step in steps:
            self.assertTrue(
                step.startswith("[Step "),
                f"Step should start with '[Step N]': {step}"
            )

    def test_pipeline_confidence_propagation(self):
        """Verify confidence level propagates through pipeline."""
        finding = _make_mock_finding()
        verifier = HarmlessVerifier()
        result = verifier.verify_finding(finding)

        report = build_verification_report([result])

        # The result's confidence value should appear in the report
        result_dict = report["findings"][0]
        self.assertEqual(result_dict["confidence"], result.confidence.value)

    def test_pipeline_empty_findings(self):
        """Verify pipeline handles empty findings list gracefully."""
        report = build_verification_report([])
        self.assertEqual(report["total_findings"], 0)
        self.assertEqual(report["coverage_pct"], 0.0)

    def test_build_report_verified_counts(self):
        """Verify build_verification_report correctly counts confidence levels."""
        # Create a manual result with HIGH confidence
        high_result = HarmlessVerifyResult(
            finding_id="f1",
            rule_id="injection.sql-execution",
            confidence=VerifyConfidence.HIGH,
        )
        # Create a manual result with UNCERTAIN confidence
        unc_result = HarmlessVerifyResult(
            finding_id="f2",
            rule_id="random.rule",
            confidence=VerifyConfidence.UNCERTAIN,
        )

        report = build_verification_report([high_result, unc_result])
        self.assertEqual(report["verified"]["high_confidence"], 1)
        self.assertEqual(report["needs_review"]["uncertain"], 1)
        self.assertEqual(report["coverage_pct"], 50.0)


if __name__ == "__main__":
    unittest.main()
