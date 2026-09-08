"""DevSecOps Models Tests"""

import pytest
from pydantic import ValidationError

from fp_sentinel.devops.models import (
    DevOpsConfig,
    DevOpsProvider,
    DevOpsStats,
    FindingRef,
    FindingTicketMapping,
    SyncDirection,
    SyncRecord,
    SyncStatus,
    TicketCloseRequest,
    TicketLinkRequest,
    TicketStatus,
    WebhookEventType,
    severity_rank,
)


class TestSeverityRank:
    def test_critical(self):
        assert severity_rank("CRITICAL") == 5

    def test_high(self):
        assert severity_rank("HIGH") == 4

    def test_medium(self):
        assert severity_rank("MEDIUM") == 3

    def test_low(self):
        assert severity_rank("LOW") == 2

    def test_info(self):
        assert severity_rank("INFO") == 1

    def test_empty(self):
        assert severity_rank("") == 0

    def test_case_insensitive(self):
        assert severity_rank("critical") == 5
        assert severity_rank("High") == 4

    def test_unknown(self):
        assert severity_rank("xyz") == 0


class TestFindingRef:
    def test_minimal(self):
        ref = FindingRef(severity="HIGH")
        assert ref.severity == "HIGH"
        assert ref.id == ""

    def test_full(self):
        ref = FindingRef(
            id="f1", severity="CRITICAL", rule_id="js.sql",
            file_path="src/app.js", line_start=42,
            message="SQL Injection", cwe="CWE-89",
        )
        assert ref.cwe == "CWE-89"
        assert ref.line_start == 42

    def test_serialize(self):
        ref = FindingRef(id="f1", severity="HIGH")
        d = ref.model_dump()
        assert d["severity"] == "HIGH"


class TestDevOpsConfig:
    def test_minimal(self):
        c = DevOpsConfig(provider=DevOpsProvider.GITLAB, base_url="https://gl.example.com")
        assert c.provider == DevOpsProvider.GITLAB

    def test_defaults(self):
        c = DevOpsConfig(provider=DevOpsProvider.GITLAB, base_url="")
        assert c.block_on_critical is True
        assert c.block_on_high is True
        assert c.warn_on_medium is True
        assert c.warn_on_low is False
        assert c.max_findings_threshold == 0
        assert c.auto_close_on_resolve is True
        assert c.timeout_seconds == 30
        assert c.max_retries == 3

    def test_extra_forbidden(self):
        with pytest.raises(ValidationError):
            DevOpsConfig(provider=DevOpsProvider.GITLAB, base_url="", bad="x")

    def test_custom(self):
        c = DevOpsConfig(
            provider=DevOpsProvider.JIRA, base_url="",
            jira_project_key="SEC", block_on_high=False,
            warn_on_low=True, max_findings_threshold=5,
        )
        assert c.jira_project_key == "SEC"
        assert c.block_on_high is False
        assert c.warn_on_low is True
        assert c.max_findings_threshold == 5


class TestFindingTicketMapping:
    def test_construction(self):
        m = FindingTicketMapping(
            id="m1", finding_id="f1",
            provider=DevOpsProvider.GITLAB, ticket_id="t1",
        )
        assert m.ticket_status == TicketStatus.OPEN
        assert m.sync_status == SyncStatus.PENDING

    def test_enum_fields(self):
        m = FindingTicketMapping(
            id="m1", finding_id="f1",
            provider=DevOpsProvider.GITHUB, ticket_id="t1",
            ticket_status=TicketStatus.CLOSED,
            sync_status=SyncStatus.SYNCED,
        )
        assert m.provider == DevOpsProvider.GITHUB

    def test_metadata(self):
        m = FindingTicketMapping(
            id="m1", finding_id="f1",
            provider=DevOpsProvider.GITLAB, ticket_id="t1",
            metadata={"key": "val"},
        )
        assert m.metadata == {"key": "val"}


class TestSyncRecord:
    def test_construction(self):
        r = SyncRecord(
            mapping_id="m1", finding_id="f1",
            provider=DevOpsProvider.GITLAB,
            sync_direction=SyncDirection.FINDING_TO_TICKET,
            status=SyncStatus.SYNCED,
        )
        assert r.attempt_count == 1
        assert r.status == SyncStatus.SYNCED


class TestTicketStatus:
    def test_values(self):
        assert TicketStatus.OPEN.value == "open"
        assert TicketStatus.CLOSED.value == "closed"
        assert TicketStatus.RESOLVED.value == "resolved"
        assert TicketStatus.IN_PROGRESS.value == "in_progress"
        assert TicketStatus.REOPENED.value == "reopened"


class TestSyncDirection:
    def test_values(self):
        assert SyncDirection.FINDING_TO_TICKET.value == "finding_to_ticket"
        assert SyncDirection.TICKET_TO_LOCAL.value == "ticket_to_local"


class TestDevOpsProvider:
    def test_values(self):
        assert DevOpsProvider.GITLAB.value == "gitlab"
        assert DevOpsProvider.JIRA.value == "jira"
        assert DevOpsProvider.GITHUB.value == "github"


class TestDevOpsStats:
    def test_default(self):
        s = DevOpsStats()
        assert s.total_mappings == 0
        assert s.by_provider == {}

    def test_with_values(self):
        s = DevOpsStats(total_mappings=10, by_provider={"gitlab": 6})
        assert s.by_provider["gitlab"] == 6

    def test_serialize(self):
        s = DevOpsStats(total_mappings=5)
        d = s.model_dump()
        assert d["total_mappings"] == 5
        assert "generated_at" in d


class TestTicketCloseRequest:
    def test_construction(self):
        r = TicketCloseRequest(
            provider=DevOpsProvider.JIRA, ticket_id="SEC-123",
            resolution="fixed", commit_hash="abc123",
        )
        assert r.ticket_id == "SEC-123"
        assert r.comment == ""


class TestTicketLinkRequest:
    def test_construction(self):
        r = TicketLinkRequest(
            provider=DevOpsProvider.GITHUB, ticket_id="42",
            commit_hash="abc123def456", close_after_link=True,
        )
        assert r.close_after_link is True
        assert r.resolution == "fixed"


class TestWebhookEventType:
    def test_values(self):
        assert WebhookEventType.ISSUE_CLOSED.value == "issue_closed"
        assert WebhookEventType.ISSUE_REOPENED.value == "issue_reopened"
        assert WebhookEventType.MERGE_REQUEST.value == "merge_request"
        assert WebhookEventType.PIPELINE_STATUS.value == "pipeline_status"
