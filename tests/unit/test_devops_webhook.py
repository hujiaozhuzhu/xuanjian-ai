"""DevSecOps Webhook Handler Tests"""

import pytest

from fp_sentinel.devops.models import (
    DevOpsProvider,
    TicketStatus,
    WebhookEventType,
)
from fp_sentinel.devops.webhook_handler import (
    build_ticket_status_change,
    parse_webhook_event,
    verify_gitlab_webhook,
    verify_github_webhook,
    verify_jira_webhook,
    _gitlab_state_to_ticket,
    _jira_status_to_ticket,
)


class TestVerifyGitlabWebhook:
    def test_valid(self):
        assert verify_gitlab_webhook(b"d", "secret", "secret") is True

    def test_invalid(self):
        assert verify_gitlab_webhook(b"d", "secret", "wrong") is False

    def test_no_token(self):
        assert verify_gitlab_webhook(b"d", "", "x") is True


class TestVerifyGitHubWebhook:
    def test_valid(self):
        import hmac, hashlib
        secret = "s"
        body = b"{}"
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        assert verify_github_webhook(body, secret, sig) is True

    def test_invalid(self):
        assert verify_github_webhook(b"{}", "s", "sha256=bad") is False

    def test_no_sig(self):
        assert verify_github_webhook(b"{}", "s", "") is False

    def test_no_secret(self):
        assert verify_github_webhook(b"{}", "", "sha256=x") is True


class TestVerifyJiraWebhook:
    def test_valid(self):
        assert verify_jira_webhook(b"d", "t", "Bearer t") is True

    def test_invalid(self):
        assert verify_jira_webhook(b"d", "t", "Bearer x") is False

    def test_no_secret(self):
        assert verify_jira_webhook(b"d", "", "Bearer x") is True


class TestParseWebhookEvent:
    def test_gitlab_issue_closed(self):
        et = parse_webhook_event(
            DevOpsProvider.GITLAB, "Issue Hook",
            {"object_attributes": {"state": "closed"}},
        )
        assert et == WebhookEventType.ISSUE_CLOSED

    def test_gitlab_issue_reopened(self):
        et = parse_webhook_event(
            DevOpsProvider.GITLAB, "Issue Hook",
            {"object_attributes": {"state": "reopened"}},
        )
        assert et == WebhookEventType.ISSUE_REOPENED

    def test_gitlab_merge_request(self):
        et = parse_webhook_event(DevOpsProvider.GITLAB, "Merge Request Hook", {})
        assert et == WebhookEventType.MERGE_REQUEST

    def test_gitlab_pipeline(self):
        et = parse_webhook_event(DevOpsProvider.GITLAB, "Pipeline Hook", {})
        assert et == WebhookEventType.PIPELINE_STATUS

    def test_github_issue_closed(self):
        et = parse_webhook_event(
            DevOpsProvider.GITHUB, "issues", {"action": "closed"},
        )
        assert et == WebhookEventType.ISSUE_CLOSED

    def test_github_issue_reopened(self):
        et = parse_webhook_event(
            DevOpsProvider.GITHUB, "issues", {"action": "reopened"},
        )
        assert et == WebhookEventType.ISSUE_REOPENED

    def test_github_pull_request(self):
        et = parse_webhook_event(
            DevOpsProvider.GITHUB, "pull_request", {"action": "opened"},
        )
        assert et == WebhookEventType.MERGE_REQUEST

    def test_jira_closed(self):
        et = parse_webhook_event(
            DevOpsProvider.JIRA, "",
            {"webhookEvent": "jira:issue_updated",
             "changelog": {"items": [{"field": "status", "toString": "Closed"}]}},
        )
        assert et == WebhookEventType.ISSUE_CLOSED

    def test_jira_in_progress(self):
        et = parse_webhook_event(
            DevOpsProvider.JIRA, "",
            {"webhookEvent": "jira:issue_updated",
             "changelog": {"items": [{"field": "status", "toString": "In Progress"}]}},
        )
        assert et == WebhookEventType.PIPELINE_STATUS


class TestBuildTicketStatusChange:
    def test_gitlab_closed(self):
        payload = {"object_attributes": {"iid": 5, "id": 42, "state": "closed", "project_id": 123}}
        event = build_ticket_status_change(DevOpsProvider.GITLAB, payload)
        assert event is not None
        assert event.ticket_id == "5"
        assert event.to_status == TicketStatus.CLOSED

    def test_gitlab_empty(self):
        assert build_ticket_status_change(DevOpsProvider.GITLAB, {}) is None

    def test_jira_closed(self):
        payload = {
            "issue": {"id": "10001", "key": "SEC-5", "fields": {"project": {"id": "1"}}},
            "changelog": {"items": [{"field": "status", "fromString": "Open", "toString": "Closed"}]},
            "user": {"displayName": "Alice"},
        }
        event = build_ticket_status_change(DevOpsProvider.JIRA, payload)
        assert event is not None
        assert event.ticket_id == "10001"
        assert event.ticket_key == "SEC-5"
        assert event.to_status == TicketStatus.CLOSED

    def test_jira_empty(self):
        assert build_ticket_status_change(DevOpsProvider.JIRA, {}) is None

    def test_github_closed(self):
        payload = {"action": "closed", "issue": {"number": 7, "id": 99}, "sender": {"login": "bob"}}
        event = build_ticket_status_change(DevOpsProvider.GITHUB, payload)
        assert event is not None
        assert event.ticket_id == "7"
        assert event.to_status == TicketStatus.CLOSED
        assert event.closed_by == "bob"

    def test_github_reopened(self):
        payload = {"action": "reopened", "issue": {"number": 7}, "sender": {"login": "bob"}}
        event = build_ticket_status_change(DevOpsProvider.GITHUB, payload)
        assert event.to_status == TicketStatus.REOPENED


class TestGitlabStateToTicket:
    def test_closed(self):
        assert _gitlab_state_to_ticket("closed") == TicketStatus.CLOSED

    def test_opened(self):
        assert _gitlab_state_to_ticket("opened") == TicketStatus.OPEN

    def test_unknown(self):
        assert _gitlab_state_to_ticket("xyz") == TicketStatus.OPEN


class TestJiraStatusToTicket:
    def test_close(self):
        assert _jira_status_to_ticket("Closed") == TicketStatus.CLOSED

    def test_done(self):
        assert _jira_status_to_ticket("Done") == TicketStatus.CLOSED

    def test_in_progress(self):
        assert _jira_status_to_ticket("In Progress") == TicketStatus.IN_PROGRESS

    def test_open(self):
        assert _jira_status_to_ticket("Open") == TicketStatus.OPEN
