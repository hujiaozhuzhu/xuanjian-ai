"""
V3.0 AI Pentest - Auto Verifier Tests
"""
from fp_sentinel.models import Finding, Severity
from fp_sentinel.attack.v3_ai_pentest.auto_verifier import (
    AutoVerifier,
    VerificationRecord,
    VerificationSession,
    VerificationMethod,
    verify_attack_chain,
)
from fp_sentinel.attack.target_validator import VerifyStatus
from fp_sentinel.attack.v3_ai_pentest.attack_chain_reasoner import AttackChainReasoner


def _f(rule_id, line, code, severity=Severity.HIGH, file_path="app.py"):
    return Finding(scanner="test", rule_id=rule_id, severity=severity,
                   file_path=file_path, line_start=line, code_snippet=code)


class TestAutoVerifier:
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

    def test_verify_attack_chain(self):
        from fp_sentinel.attack.v3_ai_pentest.attack_chain_reasoner import ReasoningChain
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            record = verify_attack_chain(report.chains[0], allow_docker=False)
            assert isinstance(record, VerificationRecord)
            assert record.rule_id == "attack_chain"

    def test_verification_record_to_dict(self):
        record = VerificationRecord(
            finding_id="test-1", rule_id="py.xss.dom",
            file_path="app.py", line=10,
            status=VerifyStatus.SIMULATED,
            method="feature_match", evidence="test evidence",
        )
        d = record.to_dict()
        assert d["rule_id"] == "py.xss.dom"
        assert d["status"] == "simulated"

    def test_session_summary(self):
        verifier = AutoVerifier(allow_docker=False)
        findings = [_f("py.injection.sql", 10, "q = SELECT || uid")]
        session = verifier.verify_findings(findings)
        summary = session.summary()
        assert "total" in summary
        assert summary["total"] == 1


class TestVerifyAttackChainConvenience:
    def test_convenience_func_no_docker(self):
        findings = [
            _f("py.xss.dom", 10, "v = request.args"),
            _f("py.injection.sql", 20, "q = SELECT || uid"),
        ]
        report = AttackChainReasoner().reason(findings)
        if report.chains:
            result = verify_attack_chain(report.chains[0], allow_docker=False)
            assert result.status in (VerifyStatus.SIMULATED, VerifyStatus.MANUAL_REQUIRED)


class TestVerificationMethod:
    def test_enum(self):
        assert VerificationMethod.DOCKER_PROBE.value == "docker_probe"
        assert VerificationMethod.FEATURE_MATCH.value == "feature_match"
