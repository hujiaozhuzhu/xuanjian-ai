"""
V3.0 AI Pentest - Auto Verifier Tests (Full Coverage)

Covers: AutoVerifier, VerificationRecord, VerificationSession,
        verify_attack_chain (convenience func), VerificationMethod enum,
        _try_lab_verify (all branches including degraded, no-targets, available),
        verify_findings (all status counting paths),
        verify_attack_chain (MANUAL_REQUIRED propagation, empty chain)
"""
import pytest
from unittest.mock import MagicMock, patch

from fp_sentinel.models import Finding, Severity
from fp_sentinel.attack.v3_ai_pentest.auto_verifier import (
    AutoVerifier,
    VerificationRecord,
    VerificationSession,
    VerificationMethod,
    verify_attack_chain,
)
from fp_sentinel.attack.target_validator import VerifyStatus, VerifyResult
from fp_sentinel.attack.v3_ai_pentest.attack_chain_reasoner import (
    AttackChainReasoner, ReasoningChain, EnhancedReasoningNode,
)


def _f(rule_id, line, code, severity=Severity.HIGH, file_path="app.py"):
    return Finding(scanner="test", rule_id=rule_id, severity=severity,
                   file_path=file_path, line_start=line, code_snippet=code)


# ============================================================
# Test VerificationRecord
# ============================================================


class TestVerificationRecord:
    def test_default_construction(self):
        record = VerificationRecord()
        assert record.finding_id == ""
        assert record.rule_id == ""
        assert record.status == VerifyStatus.SIMULATED
        assert record.duration_ms == 0.0
        assert record.logs == []

    def test_full_construction(self):
        record = VerificationRecord(
            finding_id="f1", rule_id="py.xss.dom",
            file_path="app.py", line=10,
            status=VerifyStatus.VERIFIED_LOCAL,
            method="docker_probe", evidence="found signature",
            detail="all good", timestamp="2025-01-01",
            duration_ms=150.0, logs=["step1", "step2"],
        )
        assert record.finding_id == "f1"
        assert record.status == VerifyStatus.VERIFIED_LOCAL
        assert len(record.logs) == 2

    def test_to_dict(self):
        record = VerificationRecord(
            finding_id="test-1", rule_id="py.xss.dom",
            file_path="app.py", line=10,
            status=VerifyStatus.SIMULATED,
            method="feature_match", evidence="test evidence",
        )
        d = record.to_dict()
        assert d["rule_id"] == "py.xss.dom"
        assert d["status"] == "simulated"
        assert d["log_count"] == 0

    def test_to_dict_with_logs(self):
        record = VerificationRecord(logs=["a", "b", "c"])
        d = record.to_dict()
        assert d["log_count"] == 3


# ============================================================
# Test VerificationSession
# ============================================================


class TestVerificationSession:
    def test_default_construction(self):
        session = VerificationSession()
        assert session.session_id == ""
        assert session.total_findings == 0
        assert session.records == []

    def test_summary(self):
        session = VerificationSession(
            session_id="s1", project="test",
            total_findings=3, verified_count=1,
            simulated_count=1, manual_count=1,
        )
        summary = session.summary()
        assert summary["total"] == 3
        assert summary["verified_local"] == 1
        assert summary["simulated"] == 1
        assert summary["manual_required"] == 1
        assert summary["errors"] == 0


# ============================================================
# Test AutoVerifier - Single Finding Verification
# ============================================================


class TestAutoVerifierSingle:
    def test_verify_single_finding(self):
        verifier = AutoVerifier(allow_docker=False)
        finding = _f("py.injection.sql", 10, "q = SELECT || uid")
        record = verifier.verify_finding(finding)
        assert isinstance(record, VerificationRecord)
        assert record.rule_id == "py.injection.sql"
        assert record.status in (VerifyStatus.SIMULATED, VerifyStatus.MANUAL_REQUIRED)

    def test_verify_source_unreadable(self):
        verifier = AutoVerifier(allow_docker=False)
        finding = _f("py.injection.sql", 10, "q = x", file_path="/nonexistent/file.py")
        record = verifier.verify_finding(finding)
        assert record.status == VerifyStatus.MANUAL_REQUIRED

    def test_verify_critical_severity(self):
        verifier = AutoVerifier(allow_docker=False)
        finding = _f("py.injection.os_command", 5, "os.system(cmd)", severity=Severity.CRITICAL)
        record = verifier.verify_finding(finding)
        assert record.rule_id == "py.injection.os_command"

    def test_verify_empty_severity(self):
        """Test verification with empty/minimal finding."""
        verifier = AutoVerifier(allow_docker=False)
        finding = Finding(
            scanner="test", rule_id="test.rule",
            severity=Severity.LOW, file_path="app.py",
            line_start=1, code_snippet="x",
        )
        record = verifier.verify_finding(finding)
        assert isinstance(record, VerificationRecord)

    def test_verify_with_docker_allowed_but_no_lab(self):
        """Test verification with docker allowed but no lab environment."""
        verifier = AutoVerifier(allow_docker=True)
        finding = _f("py.injection.sql", 10, "q = SELECT || uid")
        record = verifier.verify_finding(finding)
        assert isinstance(record, VerificationRecord)

    def test_verify_returns_duration(self):
        """Test that verification records duration."""
        verifier = AutoVerifier(allow_docker=False)
        finding = _f("py.injection.sql", 10, "q = SELECT || uid")
        record = verifier.verify_finding(finding)
        assert record.duration_ms >= 0

    def test_verify_populates_timestamp(self):
        """Test that verification populates timestamp."""
        verifier = AutoVerifier(allow_docker=False)
        finding = _f("py.injection.sql", 10, "q = SELECT || uid")
        record = verifier.verify_finding(finding)
        assert record.timestamp != ""

    def test_verify_handles_exception_in_base_verify(self):
        """Test that verification handles exceptions gracefully."""
        verifier = AutoVerifier(allow_docker=False)
        finding = _f("py.injection.sql", 10, "q = x")
        with patch(
            "fp_sentinel.attack.v3_ai_pentest.auto_verifier.base_verify",
            side_effect=RuntimeError("mock error"),
        ):
            record = verifier.verify_finding(finding)
        assert record.status == VerifyStatus.MANUAL_REQUIRED
        assert "error" in record.method.lower() or "Error" in record.evidence

    def test_verify_sets_finding_id(self):
        """Test that finding_id is correctly extracted."""
        verifier = AutoVerifier(allow_docker=False)
        finding = _f("py.injection.sql", 10, "x")
        finding.id = "custom-finding-id"
        record = verifier.verify_finding(finding)
        assert record.finding_id == "custom-finding-id"

    def test_verify_extracts_line_start(self):
        """Test that line_start is extracted correctly."""
        verifier = AutoVerifier(allow_docker=False)
        finding = _f("py.injection.sql", 42, "x")
        record = verifier.verify_finding(finding)
        assert record.line == 42


# ============================================================
# Test AutoVerifier - Batch Verification
# ============================================================


class TestAutoVerifierBatch:
    def test_verify_findings_batch(self):
        verifier = AutoVerifier(allow_docker=False)
        findings = [
            _f("py.injection.sql", 10, "q = SELECT || uid"),
            _f("py.xss.dom", 20, "el.innerHTML = x"),
        ]
        session = verifier.verify_findings(findings)
        assert isinstance(session, VerificationSession)
        assert session.total_findings == 2
        assert len(session.records) == 2

    def test_verify_findings_empty_list(self):
        verifier = AutoVerifier(allow_docker=False)
        session = verifier.verify_findings([])
        assert session.total_findings == 0
        assert len(session.records) == 0
        assert session.verified_count == 0
        assert session.simulated_count == 0
        assert session.manual_count == 0

    def test_verify_findings_counts_verified(self):
        """Test that verified_count is incremented."""
        verifier = AutoVerifier(allow_docker=False)
        with patch.object(verifier, "verify_finding") as mock_verify:
            mock_verify.return_value = VerificationRecord(
                status=VerifyStatus.VERIFIED_LOCAL,
            )
            session = verifier.verify_findings([_f("r", 1, "x"), _f("r", 2, "y")])
        assert session.verified_count == 2
        assert session.simulated_count == 0
        assert session.total_findings == 2

    def test_verify_findings_counts_simulated(self):
        """Test that simulated_count is incremented."""
        verifier = AutoVerifier(allow_docker=False)
        with patch.object(verifier, "verify_finding") as mock_verify:
            mock_verify.return_value = VerificationRecord(
                status=VerifyStatus.SIMULATED,
            )
            session = verifier.verify_findings([_f("r", 1, "x")])
        assert session.simulated_count == 1
        assert session.verified_count == 0

    def test_verify_findings_counts_manual(self):
        """Test that manual_count is incremented."""
        verifier = AutoVerifier(allow_docker=False)
        with patch.object(verifier, "verify_finding") as mock_verify:
            mock_verify.return_value = VerificationRecord(
                status=VerifyStatus.MANUAL_REQUIRED,
            )
            session = verifier.verify_findings([_f("r", 1, "x")])
        assert session.manual_count == 1

    def test_verify_findings_session_timestamps(self):
        """Test session has start and complete timestamps."""
        verifier = AutoVerifier(allow_docker=False)
        session = verifier.verify_findings([_f("py.injection.sql", 10, "x")])
        assert session.started_at != ""
        assert session.completed_at != ""

    def test_verify_findings_session_id_format(self):
        """Test session ID format."""
        verifier = AutoVerifier(allow_docker=False)
        session = verifier.verify_findings([_f("py.injection.sql", 10, "x")])
        assert session.session_id.startswith("VERIFY-")


# ============================================================
# Test AutoVerifier - Lab Integration
# ============================================================


class TestLabIntegration:
    def test_try_lab_verify_degraded(self):
        """Lab verify returns None when lab is degraded."""
        lab = MagicMock()
        lab.is_degraded = True
        verifier = AutoVerifier(allow_docker=True, lab_environment=lab)
        finding = _f("py.injection.sql", 10, "x")
        result = verifier._try_lab_verify(finding, VerifyResult(
            status=VerifyStatus.SIMULATED, method="test",
        ))
        assert result is None

    def test_try_lab_verify_no_targets(self):
        """Lab verify returns None when no targets available."""
        lab = MagicMock()
        lab.is_degraded = False
        lab.target_count = 0
        verifier = AutoVerifier(allow_docker=True, lab_environment=lab)
        finding = _f("py.injection.sql", 10, "x")
        result = verifier._try_lab_verify(finding, VerifyResult(
            status=VerifyStatus.SIMULATED, method="test",
        ))
        assert result is None

    def test_try_lab_verify_with_targets_returns_none(self):
        """With targets, lab verify returns None (S4 safety maintained)."""
        lab = MagicMock()
        lab.is_degraded = False
        lab.target_count = 2
        verifier = AutoVerifier(allow_docker=True, lab_environment=lab)
        finding = _f("py.injection.sql", 10, "x")
        result = verifier._try_lab_verify(finding, VerifyResult(
            status=VerifyStatus.SIMULATED, method="test",
        ))
        assert result is None

    def test_try_lab_verify_exception(self):
        """Lab verify handles exceptions gracefully."""
        lab = MagicMock()
        lab.is_degraded = False
        lab.target_count = 2
        type(lab).target_count = property(lambda self: (_ for _ in ()).throw(RuntimeError("fail")))
        verifier = AutoVerifier(allow_docker=True, lab_environment=lab)
        finding = _f("py.injection.sql", 10, "x")
        result = verifier._try_lab_verify(finding, VerifyResult(
            status=VerifyStatus.SIMULATED, method="test",
        ))
        assert result is None

    def test_verify_finding_with_lab_upgrades_status(self):
        """Test lab verify can upgrade SIMULATED to VERIFIED_LOCAL."""
        lab = MagicMock()
        lab.is_degraded = False
        lab.target_count = 1

        verifier = AutoVerifier(allow_docker=True, lab_environment=lab)
        # Use a code snippet that triggers SIMULATED status
        finding = _f("py.injection.sql", 10, "q = SELECT || uid")

        # Mock base_verify to return SIMULATED so lab verify branch is hit
        with patch(
            "fp_sentinel.attack.v3_ai_pentest.auto_verifier.base_verify",
            return_value=VerifyResult(
                status=VerifyStatus.SIMULATED,
                method="feature_match",
                evidence="signature found",
                detail="simulated",
            ),
        ):
            with patch.object(verifier, "_try_lab_verify") as mock_lab:
                mock_lab.return_value = VerifyResult(
                    status=VerifyStatus.VERIFIED_LOCAL,
                    method="docker_probe",
                    evidence="reachable",
                    detail="container running",
                )
                record = verifier.verify_finding(finding)

        assert record.status == VerifyStatus.VERIFIED_LOCAL
        assert "lab:" in record.evidence

    def test_lab_verify_only_called_for_simulated(self):
        """Lab verify is only called for SIMULATED results."""
        lab = MagicMock()
        lab.is_degraded = False
        lab.target_count = 1
        verifier = AutoVerifier(allow_docker=True, lab_environment=lab)
        finding = _f("py.injection.sql", 10, "x")

        with patch.object(verifier, "_try_lab_verify") as mock_lab:
            # Even if it returns something, it should NOT be called
            # because base verify returns MANUAL_REQUIRED
            base_result = VerifyResult(
                status=VerifyStatus.MANUAL_REQUIRED, method="test",
            )
            with patch(
                "fp_sentinel.attack.v3_ai_pentest.auto_verifier.base_verify",
                return_value=base_result,
            ):
                record = verifier.verify_finding(finding)

        mock_lab.assert_not_called()


# ============================================================
# Test AutoVerifier - Attack Chain Verification
# ============================================================


class TestAttackChainVerification:
    def test_verify_attack_chain_basic(self):
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            record = verify_attack_chain(report.chains[0], allow_docker=False)
            assert isinstance(record, VerificationRecord)
            assert record.rule_id == "attack_chain"

    def test_verify_attack_chain_convenience(self):
        """Test verify_attack_chain convenience function."""
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            result = verify_attack_chain(report.chains[0], allow_docker=False)
            assert result.status in (VerifyStatus.SIMULATED, VerifyStatus.MANUAL_REQUIRED)

    def test_verify_attack_chain_single_node_chain(self):
        """Test chain verification with a single node chain."""
        chain = ReasoningChain(
            nodes=[
                EnhancedReasoningNode(
                    id="n1", rule_id="py.xss.dom",
                    file_path="app.py", line=10,
                    severity="HIGH", node_role="entry",
                ),
            ],
            edges=[],
        )
        record = verify_attack_chain(chain, allow_docker=False)
        assert record.rule_id == "attack_chain"
        assert "1 steps" in record.detail

    def test_verify_attack_chain_empty_nodes(self):
        """Test chain verification with no nodes."""
        chain = ReasoningChain(nodes=[], edges=[])
        record = verify_attack_chain(chain, allow_docker=False)
        assert record.rule_id == "attack_chain"

    def test_verify_attack_chain_propagates_manual(self):
        """Test that MANUAL_REQUIRED in any step propagates to overall."""
        chain = ReasoningChain(
            nodes=[
                EnhancedReasoningNode(
                    id="n1", rule_id="py.xss.dom",
                    file_path="app.py", line=10,
                    severity="HIGH", node_role="entry",
                ),
                EnhancedReasoningNode(
                    id="n2", rule_id="py.injection.sql",
                    file_path="app.py", line=20,
                    severity="CRITICAL", node_role="sink",
                ),
            ],
            edges=[],
        )

        verifier = AutoVerifier(allow_docker=False)
        with patch.object(verifier, "verify_finding") as mock_verify:
            mock_verify.return_value = VerificationRecord(
                status=VerifyStatus.MANUAL_REQUIRED,
            )
            record = verifier.verify_attack_chain(chain)

        assert record.status == VerifyStatus.MANUAL_REQUIRED

    def test_verify_attack_chain_with_logs(self):
        """Test that chain verification produces step logs."""
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            record = verify_attack_chain(report.chains[0], allow_docker=False)
            assert len(record.logs) >= 2

    def test_verify_attack_chain_evidence_includes_steps(self):
        """Test that chain evidence includes step info."""
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            record = verify_attack_chain(report.chains[0], allow_docker=False)
            assert "Chain steps:" in record.evidence


# ============================================================
# Test VerificationMethod Enum
# ============================================================


class TestVerificationMethod:
    def test_enum(self):
        assert VerificationMethod.DOCKER_PROBE.value == "docker_probe"
        assert VerificationMethod.FEATURE_MATCH.value == "feature_match"
        assert VerificationMethod.SOURCE_ANALYSIS.value == "source_analysis"
        assert VerificationMethod.MANUAL.value == "manual"

    def test_count(self):
        assert len(VerificationMethod) == 4
