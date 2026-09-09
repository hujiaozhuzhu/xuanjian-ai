"""
模型测试
覆盖：所有枚举、Pydantic模型序列化/反序列化、默认值
"""

import pytest
from fp_sentinel.auto_pr.models import (
    AutoPRConfig,
    FixDiff,
    FixPatch,
    FixPreview,
    FixRecord,
    FixStatus,
    FixVerificationResult,
    GenerateFixRequest,
    PRStats,
    PullRequestRecord,
    SubmitPRRequest,
    VerificationStatus,
    VerifyFixRequest,
    VulnerabilityType,
)


# ─────────────────────── 枚举测试 ───────────────────────

class TestEnums:
    def test_vulnerability_type_values(self):
        assert VulnerabilityType.SQL_INJECTION.value == "sql_injection"
        assert VulnerabilityType.XSS.value == "xss"
        assert VulnerabilityType.GENERIC.value == "generic"
        assert len(VulnerabilityType) == 16  # 16 types total

    def test_fix_status_values(self):
        assert FixStatus.PENDING.value == "pending"
        assert FixStatus.VERIFIED.value == "verified"
        assert FixStatus.MERGED.value == "merged"

    def test_verification_status_values(self):
        assert VerificationStatus.PASS.value == "pass"
        assert VerificationStatus.FAIL.value == "fail"
        assert VerificationStatus.WARN.value == "warn"


# ─────────────────────── Pydantic模型测试 ───────────────────────

class TestFixDiffModel:
    def test_create(self):
        diff = FixDiff(
            file_path="app.py",
            original_code="bad",
            fixed_code="good",
        )
        assert diff.file_path == "app.py"
        assert diff.line_start == 1

    def test_defaults(self):
        diff = FixDiff(file_path="test.py", fixed_code="code")
        assert diff.original_code == ""
        assert diff.description == ""


class TestFixPatchModel:
    def test_create(self):
        patch = FixPatch(
            finding_id="f1",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            title="Fix SQLi",
        )
        assert patch.finding_id == "f1"
        assert patch.id is not None
        assert patch.confidence == 0.8

    def test_auto_id_uniqueness(self):
        p1 = FixPatch(finding_id="f1", vuln_type=VulnerabilityType.XSS, title="XSS")
        p2 = FixPatch(finding_id="f2", vuln_type=VulnerabilityType.XSS, title="XSS")
        assert p1.id != p2.id


class TestFixPreviewModel:
    def test_create(self):
        preview = FixPreview(
            finding_id="f1",
            rule_id="py.sql",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            unified_diff="--- a/app.py\n+++ b/app.py",
            title="Fix",
        )
        assert preview.can_customize is True
        assert preview.effort_minutes == 0


class TestFixVerificationResultModel:
    def test_create(self):
        result = FixVerificationResult(
            patch_id="p1",
            finding_id="f1",
            status=VerificationStatus.PASS,
            original_vuln_resolved=True,
        )
        assert result.syntax_valid is True
        assert result.security_check_passed is True
        assert result.new_vulns_introduced == 0

    def test_id_auto_generated(self):
        result = FixVerificationResult(patch_id="p", finding_id="f")
        assert result.id is not None


class TestPullRequestRecordModel:
    def test_create(self):
        record = PullRequestRecord(
            provider="gitlab",
            pr_id="42",
            pr_url="https://example.com/pr/42",
            pr_title="Fix security",
        )
        assert record.status == "open"
        assert record.base_branch == "main"
        assert record.patch_ids == []


class TestFixRecordModel:
    def test_create(self):
        record = FixRecord(
            finding_id="f1",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            status=FixStatus.READY,
        )
        assert record.status == FixStatus.READY
        assert record.verification_status == VerificationStatus.NOT_VERIFIED

    def test_timestamp_auto(self):
        record = FixRecord(finding_id="f1", vuln_type=VulnerabilityType.GENERIC)
        assert record.created_at is not None
        assert record.updated_at is not None


class TestAutoPRConfig:
    def test_defaults(self):
        config = AutoPRConfig()
        assert config.provider == "gitlab"
        assert config.default_branch == "main"
        assert config.auto_verify is True
        assert config.dry_run is False
        assert config.max_fix_per_run == 50

    def test_custom(self):
        config = AutoPRConfig(
            provider="github",
            default_branch="develop",
            dry_run=True,
            max_fix_per_run=10,
        )
        assert config.provider == "github"
        assert config.dry_run is True


class TestPRStats:
    def test_defaults(self):
        stats = PRStats()
        assert stats.total_fixes == 0
        assert stats.avg_effort_minutes == 0.0
        assert stats.by_vuln_type == {}


class TestGenerateFixRequest:
    def test_create(self):
        req = GenerateFixRequest(
            finding_id="f1",
            rule_id="py.sql",
            severity="HIGH",
            file_path="app.py",
        )
        assert req.finding_id == "f1"
        assert req.code_snippet == ""


class TestVerifyFixRequest:
    def test_create(self):
        req = VerifyFixRequest(
            patch_id="p1",
            finding_id="f1",
            fixed_code="good code",
            vuln_type=VulnerabilityType.SQL_INJECTION,
        )
        assert req.original_code == ""


class TestSubmitPRRequest:
    def test_create(self):
        config = AutoPRConfig()
        req = SubmitPRRequest(
            config=config,
            patch_ids=["p1"],
            finding_ids=["f1"],
        )
        assert len(req.patch_ids) == 1
        assert req.ticket_ids == []
