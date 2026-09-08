"""DevSecOps Pipeline Gate Tests"""

import pytest

from fp_sentinel.devops.models import (
    DevOpsConfig,
    DevOpsProvider,
    FindingRef,
    FindingViolation,
    PipelineGateRequest,
    PipelineGateResult,
    PipelineGateVerdict,
)
from fp_sentinel.devops.pipeline_gate import (
    _count_by_severity,
    _evaluate_finding,
    evaluate_gate,
    format_gate_output,
    gate_exit_code,
)


class TestEvaluateFinding:
    """_evaluate_finding 单元测试"""

    def test_critical_blocks(self):
        config = DevOpsConfig(provider=DevOpsProvider.GITLAB, base_url="")
        finding = FindingRef(severity="CRITICAL", rule_id="r1")
        assert _evaluate_finding(finding, config) == "block"

    def test_high_blocks(self):
        config = DevOpsConfig(provider=DevOpsProvider.GITLAB, base_url="")
        finding = FindingRef(severity="HIGH", rule_id="r1")
        assert _evaluate_finding(finding, config) == "block"

    def test_medium_warns(self):
        config = DevOpsConfig(provider=DevOpsProvider.GITLAB, base_url="")
        finding = FindingRef(severity="MEDIUM", rule_id="r1")
        assert _evaluate_finding(finding, config) == "warn"

    def test_low_ok(self):
        config = DevOpsConfig(provider=DevOpsProvider.GITLAB, base_url="")
        finding = FindingRef(severity="LOW", rule_id="r1")
        assert _evaluate_finding(finding, config) == "ok"

    def test_info_ok(self):
        config = DevOpsConfig(provider=DevOpsProvider.GITLAB, base_url="")
        finding = FindingRef(severity="INFO", rule_id="r1")
        assert _evaluate_finding(finding, config) == "ok"

    def test_low_warns_when_configured(self):
        config = DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="",
            warn_on_low=True,
        )
        finding = FindingRef(severity="LOW", rule_id="r1")
        assert _evaluate_finding(finding, config) == "warn"

    def test_medium_ok_when_warn_off(self):
        config = DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="",
            warn_on_medium=False,
        )
        finding = FindingRef(severity="MEDIUM", rule_id="r1")
        assert _evaluate_finding(finding, config) == "ok"

    def test_high_ok_when_all_off(self):
        """HIGH finding is ok when both block_on_high and warn_on_medium are disabled"""
        config = DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="",
            block_on_high=False,
            warn_on_medium=False,
        )
        finding = FindingRef(severity="HIGH", rule_id="r1")
        assert _evaluate_finding(finding, config) == "ok"

    def test_high_warns_when_block_off_but_warn_on(self):
        """HIGH finding still triggers warn when block_off but warn_on_medium enabled"""
        config = DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="",
            block_on_high=False,
        )
        finding = FindingRef(severity="HIGH", rule_id="r1")
        # HIGH rank >= MEDIUM rank, so warn_on_medium still fires
        assert _evaluate_finding(finding, config) == "warn"

    def test_empty_config_defaults(self):
        """Test with default config (block_on_critical=True, block_on_high=True)"""
        config = DevOpsConfig(provider=DevOpsProvider.GITLAB, base_url="")
        finding = FindingRef(severity="CRITICAL", rule_id="r1")
        assert _evaluate_finding(finding, config) == "block"


class TestCountBySeverity:
    def test_counts(self):
        findings = [
            FindingRef(severity="CRITICAL"),
            FindingRef(severity="CRITICAL"),
            FindingRef(severity="HIGH"),
            FindingRef(severity="LOW"),
        ]
        counter = _count_by_severity(findings)
        assert counter["CRITICAL"] == 2
        assert counter["HIGH"] == 1
        assert counter["LOW"] == 1

    def test_empty(self):
        assert _count_by_severity([]) == {}

    def test_case_normalize(self):
        findings = [FindingRef(severity="high"), FindingRef(severity="High")]
        counter = _count_by_severity(findings)
        assert counter["HIGH"] == 2


class TestEvaluateGate:
    """evaluate_gate 集成测试"""

    def _make_request(self, findings, config=None, provider=DevOpsProvider.GITLAB):
        return PipelineGateRequest(
            provider=provider,
            project_id="proj1",
            commit_hash="abc123",
            branch="main",
            findings=findings,
            config=config,
        )

    def test_pass_no_findings(self):
        req = self._make_request([])
        result = evaluate_gate(req)
        assert result.verdict == PipelineGateVerdict.PASS
        assert result.total_findings == 0
        assert result.violations == []

    def test_pass_only_info(self):
        req = self._make_request([
            FindingRef(severity="INFO", rule_id="info.rule"),
        ])
        result = evaluate_gate(req)
        assert result.verdict == PipelineGateVerdict.PASS

    def test_block_on_critical(self):
        req = self._make_request([
            FindingRef(severity="CRITICAL", rule_id="sql.inj", file_path="a.js", line_start=1),
        ])
        result = evaluate_gate(req)
        assert result.verdict == PipelineGateVerdict.BLOCK
        assert result.critical_count == 1
        assert len(result.violations) == 1
        assert result.violations[0].violation_level == "block"

    def test_block_on_high(self):
        req = self._make_request([
            FindingRef(severity="HIGH", rule_id="xss", file_path="b.js", line_start=2),
        ])
        result = evaluate_gate(req)
        assert result.verdict == PipelineGateVerdict.BLOCK
        assert result.high_count == 1

    def test_warn_on_medium(self):
        req = self._make_request([
            FindingRef(severity="MEDIUM", rule_id="weak.crypto", file_path="c.js"),
        ])
        result = evaluate_gate(req)
        assert result.verdict == PipelineGateVerdict.WARN
        assert result.medium_count == 1
        assert len(result.warnings) == 1
        assert result.warnings[0].violation_level == "warn"

    def test_block_takes_precedence_over_warn(self):
        req = self._make_request([
            FindingRef(severity="CRITICAL", rule_id="sql.inj"),
            FindingRef(severity="MEDIUM", rule_id="weak.crypto"),
        ])
        result = evaluate_gate(req)
        assert result.verdict == PipelineGateVerdict.BLOCK

    def test_max_findings_threshold(self):
        config = DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="",
            max_findings_threshold=2,
            block_on_critical=False,
            block_on_high=False,
            warn_on_medium=False,
            warn_on_low=False,
        )
        req = self._make_request([
            FindingRef(severity="INFO", rule_id="r1"),
            FindingRef(severity="INFO", rule_id="r2"),
            FindingRef(severity="INFO", rule_id="r3"),
        ], config=config)
        result = evaluate_gate(req)
        assert result.verdict == PipelineGateVerdict.BLOCK

    def test_max_findings_threshold_not_exceeded(self):
        config = DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="",
            max_findings_threshold=5,
            block_on_critical=False,
            block_on_high=False,
            warn_on_medium=False,
            warn_on_low=False,
        )
        req = self._make_request([
            FindingRef(severity="INFO", rule_id="r1"),
            FindingRef(severity="INFO", rule_id="r2"),
        ], config=config)
        result = evaluate_gate(req)
        assert result.verdict == PipelineGateVerdict.PASS

    def test_counts_all_severities(self):
        req = self._make_request([
            FindingRef(severity="CRITICAL"),
            FindingRef(severity="HIGH"),
            FindingRef(severity="HIGH"),
            FindingRef(severity="MEDIUM"),
            FindingRef(severity="LOW"),
            FindingRef(severity="INFO"),
        ])
        result = evaluate_gate(req)
        assert result.critical_count == 1
        assert result.high_count == 2
        assert result.medium_count == 1
        assert result.low_count == 1
        assert result.info_count == 1

    def test_result_has_summary(self):
        req = self._make_request([
            FindingRef(severity="HIGH", rule_id="r1"),
        ])
        result = evaluate_gate(req)
        assert result.summary != ""
        assert "BLOCK" in result.summary

    def test_result_has_suggestions(self):
        req = self._make_request([
            FindingRef(severity="CRITICAL", rule_id="sql.inj"),
        ])
        result = evaluate_gate(req)
        assert len(result.suggested_actions) > 0
        assert any("修复" in a for a in result.suggested_actions)

    def test_violation_details_populated(self):
        req = self._make_request([
            FindingRef(id="f1", severity="HIGH", rule_id="sql.inj", file_path="a.js", line_start=10, message="SQLi"),
        ])
        result = evaluate_gate(req)
        v = result.violations[0]
        assert v.finding_id == "f1"
        assert v.severity == "HIGH"
        assert v.rule_id == "sql.inj"
        assert v.file_path == "a.js"

    def test_custom_config_disable_all(self):
        config = DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="",
            block_on_critical=False,
            block_on_high=False,
            warn_on_medium=False,
            warn_on_low=False,
        )
        req = self._make_request([
            FindingRef(severity="CRITICAL"),
            FindingRef(severity="HIGH"),
            FindingRef(severity="MEDIUM"),
        ], config=config)
        result = evaluate_gate(req)
        assert result.verdict == PipelineGateVerdict.PASS


class TestFormatGateOutput:
    """format_gate_output 格式化测试"""

    def test_text_format_contains_verdict(self):
        result = PipelineGateResult(
            verdict=PipelineGateVerdict.BLOCK,
            provider=DevOpsProvider.GITLAB,
            project_id="proj1",
            summary="test summary",
        )
        output = format_gate_output(result, "text")
        assert "BLOCK" in output

    def test_json_format(self):
        import json
        result = PipelineGateResult(
            verdict=PipelineGateVerdict.PASS,
            provider=DevOpsProvider.GITLAB,
            project_id="proj1",
        )
        output = format_gate_output(result, "json")
        parsed = json.loads(output)
        assert parsed["verdict"] == "pass"

    def test_text_format_with_violations(self):
        result = PipelineGateResult(
            verdict=PipelineGateVerdict.BLOCK,
            provider=DevOpsProvider.GITLAB,
            project_id="p1",
            violations=[
                FindingViolation(severity="CRITICAL", rule_id="sql.inj", file_path="a.js", message="SQLi"),
                FindingViolation(severity="HIGH", rule_id="xss", file_path="b.js", message="XSS"),
            ],
            warnings=[
                FindingViolation(severity="MEDIUM", rule_id="weak", file_path="c.js", message="weak"),
            ],
            suggested_actions=["Fix now"],
        )
        output = format_gate_output(result, "text")
        assert "阻断项" in output or "BLOCK" in output
        assert "sql.inj" in output

    def test_text_format_truncates_many_violations(self):
        violations = [
            FindingViolation(severity="HIGH", rule_id=f"rule-{i}", file_path=f"f{i}.js", message="x")
            for i in range(15)
        ]
        result = PipelineGateResult(
            verdict=PipelineGateVerdict.BLOCK,
            provider=DevOpsProvider.GITLAB,
            project_id="p1",
            violations=violations,
        )
        output = format_gate_output(result, "text")
        assert "15" in output  # total count mentioned


class TestGateExitCode:
    """gate_exit_code 测试"""

    def test_block_returns_1(self):
        result = PipelineGateResult(
            verdict=PipelineGateVerdict.BLOCK,
            provider=DevOpsProvider.GITLAB,
        )
        assert gate_exit_code(result) == 1

    def test_warn_returns_0(self):
        result = PipelineGateResult(
            verdict=PipelineGateVerdict.WARN,
            provider=DevOpsProvider.GITLAB,
        )
        assert gate_exit_code(result) == 0

    def test_pass_returns_0(self):
        result = PipelineGateResult(
            verdict=PipelineGateVerdict.PASS,
            provider=DevOpsProvider.GITLAB,
        )
        assert gate_exit_code(result) == 0
