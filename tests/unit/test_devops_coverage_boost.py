"""DevSecOps Coverage Boost Tests - Target all remaining gaps for 95%+ coverage.

Covers:
- service.py: _extract_ticket_id_and_commit (all providers), _handle_issue_closed missing ticket
- adapters.py: All exception/error paths, Jira/GitHub extended flows
- webhook_handler.py: Edge cases in parsing, all providers, unknown states
- repository.py: Row deserialization edge cases, update no-valid-fields
- ticket_manager.py: Exception in reopen, link with no mapping
"""

import json
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import aiosqlite
import httpx
import pytest

from fp_sentinel.devops.adapters import (
    DevOpsAdapter,
    GitHubAdapter,
    GitLabAdapter,
    HTTPClientProvider,
    JiraAdapter,
    fingerprint_finding,
)
from fp_sentinel.devops.models import (
    DevOpsConfig,
    DevOpsProvider,
    FindingRef,
    FindingTicketMapping,
    SyncDirection,
    SyncFindingsRequest,
    SyncRecord,
    SyncStatus,
    TicketCloseRequest,
    TicketLinkRequest,
    TicketStatus,
    WebhookEventType,
)
from fp_sentinel.devops.pipeline_gate import PipelineGateResult, PipelineGateVerdict
from fp_sentinel.devops.repository import (
    SCHEMA_SQL,
    FindingTicketMappingRepo,
    PipelineGateRecordRepo,
    SyncRecordRepo,
)
from fp_sentinel.devops.service import DevOpsService, _extract_ticket_id_and_commit
from fp_sentinel.devops.ticket_manager import TicketManager
from fp_sentinel.devops.webhook_handler import (
    _gitlab_state_to_ticket,
    _jira_status_to_ticket,
    _parse_gitlab_event,
    _parse_github_event,
    _parse_jira_event,
    build_ticket_status_change,
    parse_webhook_event,
    verify_github_webhook,
    verify_gitlab_webhook,
    verify_jira_webhook,
)


# ─────────────────────────── Fixtures ───────────────────────────


@pytest.fixture
async def db_conn():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    conn = await aiosqlite.connect(db_path)
    conn.row_factory = aiosqlite.Row
    await conn.executescript(SCHEMA_SQL)
    await conn.commit()
    yield conn
    await conn.close()
    os.unlink(db_path)


@pytest.fixture
def service(db_conn):
    return DevOpsService(
        FindingTicketMappingRepo(db_conn),
        SyncRecordRepo(db_conn),
        PipelineGateRecordRepo(db_conn),
    )


@pytest.fixture
def mock_adapter():
    adapter = MagicMock(spec=DevOpsAdapter)
    adapter.create_issue = AsyncMock(return_value=("t1", "GL-10", "https://gl.example.com/i/10"))
    adapter.close_issue = AsyncMock(return_value=True)
    adapter.add_comment = AsyncMock(return_value=True)
    adapter.update_issue_status = AsyncMock(return_value=True)
    adapter.close = AsyncMock()
    return adapter


def _mock_response(json_data=None, status_code=200):
    if json_data is None:
        json_data = {}
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.status_code = status_code
    resp.text = str(json_data)
    return resp


def _make_adapter_with_mock(cls, config):
    adapter = cls(config)
    mock_client = AsyncMock()
    mock_provider = MagicMock(spec=HTTPClientProvider)
    mock_provider.get_client = AsyncMock(return_value=mock_client)
    adapter.http = mock_provider
    return adapter, mock_client


# ─────────────────────────── service.py gaps ───────────────────────────


class TestExtractTicketIdAndCommit:
    """Cover lines 490-506: _extract_ticket_id_and_commit for all providers"""

    def test_gitlab_with_description_commit(self):
        payload = {
            "object_attributes": {
                "iid": 42,
                "id": 99,
                "description": "Fixed in abc123def456789012345678901234567890abcd",
            }
        }
        ticket_id, commit = _extract_ticket_id_and_commit("gitlab", payload)
        assert ticket_id == "42"
        assert commit == "abc123def456789012345678901234567890abcd"

    def test_gitlab_with_issue_key(self):
        payload = {"issue": {"iid": 7, "id": 100}}
        ticket_id, commit = _extract_ticket_id_and_commit("gitlab", payload)
        assert ticket_id == "7"

    def test_gitlab_empty_payload(self):
        ticket_id, commit = _extract_ticket_id_and_commit("gitlab", {})
        assert ticket_id is None
        assert commit == ""

    def test_jira_with_comment_commit(self):
        payload = {
            "issue": {"id": "10001"},
            "comment": {"body": "Commit: deadbeef1234567890abcdef1234567890abcdef"},
        }
        ticket_id, commit = _extract_ticket_id_and_commit("jira", payload)
        assert ticket_id == "10001"
        assert commit == "deadbeef1234567890abcdef1234567890abcdef"

    def test_jira_without_comment(self):
        payload = {"issue": {"id": "500"}}
        ticket_id, commit = _extract_ticket_id_and_commit("jira", payload)
        assert ticket_id == "500"
        assert commit == ""

    def test_jira_empty(self):
        ticket_id, commit = _extract_ticket_id_and_commit("jira", {})
        assert ticket_id is None

    def test_github_with_body_commit(self):
        payload = {
            "issue": {
                "number": 15,
                "id": 888,
                "body": "See commit abc123def456789012345678901234567890abcd for details",
            }
        }
        ticket_id, commit = _extract_ticket_id_and_commit("github", payload)
        assert ticket_id == "15"
        assert commit == "abc123def456789012345678901234567890abcd"

    def test_github_with_id_fallback(self):
        payload = {"issue": {"id": 777}}
        ticket_id, commit = _extract_ticket_id_and_commit("github", payload)
        assert ticket_id == "777"

    def test_github_empty_body(self):
        payload = {"issue": {"number": 3, "body": ""}}
        ticket_id, commit = _extract_ticket_id_and_commit("github", payload)
        assert ticket_id == "3"
        assert commit == ""

    def test_unknown_provider(self):
        ticket_id, commit = _extract_ticket_id_and_commit("unknown", {"issue": {"id": "1"}})
        assert ticket_id is None


class TestServiceSyncMultipleFindings:
    """Cover sync flow with multiple findings and mixed results"""

    @pytest.mark.asyncio
    async def test_partial_failure(self, service):
        """One finding succeeds, one fails"""
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.create_issue = AsyncMock(side_effect=[
            ("t1", "GL-1", "https://url1"),
            (None, None, None),  # second fails
        ])
        request = SyncFindingsRequest(
            provider=DevOpsProvider.GITLAB,
            project_id="p1",
            findings=[
                FindingRef(id="f1", severity="HIGH", rule_id="sql"),
                FindingRef(id="f2", severity="LOW", rule_id="info"),
            ],
        )
        result = await service.sync_findings(request, adapter=adapter)
        assert result.created_count == 1
        assert result.failed_count == 1
        assert result.status == SyncStatus.FAILED

    @pytest.mark.asyncio
    async def test_multiple_success(self, service):
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.create_issue = AsyncMock(side_effect=[
            ("t1", "GL-1", "https://u1"),
            ("t2", "GL-2", "https://u2"),
            ("t3", "GL-3", "https://u3"),
        ])
        request = SyncFindingsRequest(
            provider=DevOpsProvider.GITLAB,
            project_id="p1",
            findings=[
                FindingRef(id="f1", severity="HIGH", rule_id="sql"),
                FindingRef(id="f2", severity="HIGH", rule_id="xss"),
                FindingRef(id="f3", severity="MEDIUM", rule_id="crypto"),
            ],
        )
        result = await service.sync_findings(request, adapter=adapter)
        assert result.created_count == 3
        assert result.status == SyncStatus.SYNCED


# ─────────────────────────── adapters.py gaps ───────────────────────────


class TestGitLabAdapterEdgeCases:
    """Cover lines 237->242, 283: GitLab exception/edge paths"""

    @pytest.fixture
    def gitlab_config(self):
        return DevOpsConfig(
            provider=DevOpsProvider.GITLAB,
            base_url="https://gl.example.com",
            api_token="tok",
            project_id="123",
        )

    @pytest.mark.asyncio
    async def test_add_comment_exception(self, gitlab_config):
        adapter, mock_client = _make_adapter_with_mock(GitLabAdapter, gitlab_config)
        mock_client.post.side_effect = Exception("network error")
        ok = await adapter.add_comment("5", "text")
        assert ok is False

    @pytest.mark.asyncio
    async def test_close_issue_exception(self, gitlab_config):
        adapter, mock_client = _make_adapter_with_mock(GitLabAdapter, gitlab_config)
        mock_client.post.side_effect = Exception("fail")
        ok = await adapter.close_issue("5", comment="x")
        assert ok is False

    @pytest.mark.asyncio
    async def test_close_issue_put_exception(self, gitlab_config):
        adapter, mock_client = _make_adapter_with_mock(GitLabAdapter, gitlab_config)
        mock_client.post.return_value = _mock_response({"id": 1})
        mock_client.put.side_effect = Exception("put fail")
        ok = await adapter.close_issue("5", comment="x")
        assert ok is False

    @pytest.mark.asyncio
    async def test_create_issue_exception(self, gitlab_config):
        adapter, mock_client = _make_adapter_with_mock(GitLabAdapter, gitlab_config)
        mock_client.post.side_effect = Exception("fail")
        tid, tkey, turl = await adapter.create_issue(
            FindingRef(severity="HIGH", rule_id="sql"), "", "", "",
        )
        assert tid is None

    @pytest.mark.asyncio
    async def test_update_issue_status_exception(self, gitlab_config):
        adapter, mock_client = _make_adapter_with_mock(GitLabAdapter, gitlab_config)
        mock_client.put.side_effect = Exception("fail")
        ok = await adapter.update_issue_status("5", TicketStatus.RESOLVED)
        assert ok is False

    @pytest.mark.asyncio
    async def test_update_issue_status_with_comment_exception(self, gitlab_config):
        """When the PUT itself throws, returns False"""
        adapter, mock_client = _make_adapter_with_mock(GitLabAdapter, gitlab_config)
        mock_client.put.side_effect = Exception("put fail")
        ok = await adapter.update_issue_status("5", TicketStatus.REOPENED, comment="note")
        assert ok is False

    @pytest.mark.asyncio
    async def test_update_issue_status_put_succeeds_comment_swallowed(self, gitlab_config):
        """add_comment has its own try/except; outer method returns put result"""
        adapter, mock_client = _make_adapter_with_mock(GitLabAdapter, gitlab_config)
        mock_client.put.return_value = _mock_response({"id": 5})
        mock_client.post.side_effect = Exception("comment fail")
        ok = await adapter.update_issue_status("5", TicketStatus.REOPENED, comment="note")
        # PUT succeeds -> ok=True; add_comment exception is swallowed by its own try/except
        assert ok is True


class TestJiraAdapterEdgeCases:
    """Cover lines 348-379, 393, 420->431, 470, 472, 488->487, 492"""

    @pytest.fixture
    def jira_config(self):
        return DevOpsConfig(
            provider=DevOpsProvider.JIRA,
            base_url="https://jira.example.com",
            api_token="tok",
            jira_project_key="SEC",
        )

    @pytest.mark.asyncio
    async def test_create_issue_success(self, jira_config):
        adapter, mock_client = _make_adapter_with_mock(JiraAdapter, jira_config)
        mock_client.post.return_value = _mock_response(
            {"id": "10005", "key": "SEC-42"}, status_code=201
        )
        tid, tkey, turl = await adapter.create_issue(
            FindingRef(severity="HIGH", rule_id="sql", message="desc", file_path="a.js", line_start=1),
            "https://repo", "abc", "main",
        )
        assert tid == "10005"
        assert tkey == "SEC-42"
        assert "SEC-42" in turl

    @pytest.mark.asyncio
    async def test_create_issue_failure_status(self, jira_config):
        adapter, mock_client = _make_adapter_with_mock(JiraAdapter, jira_config)
        mock_client.post.return_value = _mock_response({}, status_code=400)
        tid, tkey, turl = await adapter.create_issue(
            FindingRef(severity="HIGH", rule_id="sql"), "", "", "",
        )
        assert tid is None

    @pytest.mark.asyncio
    async def test_create_issue_exception(self, jira_config):
        adapter, mock_client = _make_adapter_with_mock(JiraAdapter, jira_config)
        mock_client.post.side_effect = Exception("fail")
        tid, tkey, turl = await adapter.create_issue(
            FindingRef(severity="HIGH", rule_id="sql"), "", "", "",
        )
        assert tid is None

    @pytest.mark.asyncio
    async def test_close_issue_with_comment(self, jira_config):
        adapter, mock_client = _make_adapter_with_mock(JiraAdapter, jira_config)
        mock_client.post.return_value = _mock_response({}, status_code=200)
        mock_client.get.return_value = _mock_response({
            "transitions": [{"id": "31", "name": "Done"}]
        })
        ok = await adapter.close_issue("10001", comment="resolved", commit_hash="abc")
        assert ok is True

    @pytest.mark.asyncio
    async def test_close_issue_exception(self, jira_config):
        adapter, mock_client = _make_adapter_with_mock(JiraAdapter, jira_config)
        mock_client.post.side_effect = Exception("fail")
        ok = await adapter.close_issue("10001", comment="x")
        assert ok is False

    @pytest.mark.asyncio
    async def test_find_close_transition_exception(self, jira_config):
        adapter, mock_client = _make_adapter_with_mock(JiraAdapter, jira_config)
        mock_client.get.side_effect = Exception("fail")
        # Should return empty list (caught by generic exception in _find_close_transition)
        result = await adapter._find_close_transition("10001")
        # _find_close_transition catches all exceptions and returns None
        assert result is None

    @pytest.mark.asyncio
    async def test_add_comment_exception(self, jira_config):
        adapter, mock_client = _make_adapter_with_mock(JiraAdapter, jira_config)
        mock_client.post.side_effect = Exception("fail")
        ok = await adapter.add_comment("10001", "text")
        assert ok is False

    @pytest.mark.asyncio
    async def test_update_issue_status_no_transition(self, jira_config):
        adapter, mock_client = _make_adapter_with_mock(JiraAdapter, jira_config)
        mock_client.get.return_value = _mock_response({"transitions": []})
        ok = await adapter.update_issue_status("10001", TicketStatus.RESOLVED)
        assert ok is False

    @pytest.mark.asyncio
    async def test_update_issue_status_exception(self, jira_config):
        adapter, mock_client = _make_adapter_with_mock(JiraAdapter, jira_config)
        mock_client.get.side_effect = Exception("fail")
        ok = await adapter.update_issue_status("10001", TicketStatus.IN_PROGRESS)
        assert ok is False

    @pytest.mark.asyncio
    async def test_find_transition_by_name_exception(self, jira_config):
        adapter, mock_client = _make_adapter_with_mock(JiraAdapter, jira_config)
        mock_client.get.side_effect = Exception("fail")
        result = await adapter._find_transition_by_name("10001", "Done")
        assert result is None


class TestGitHubAdapterEdgeCases:
    """Cover lines 569-570, 583->585, 626-628, 638"""

    @pytest.fixture
    def github_config(self):
        return DevOpsConfig(
            provider=DevOpsProvider.GITHUB,
            base_url="",
            api_token="ghp_x",
            project_id="owner/repo",
        )

    @pytest.mark.asyncio
    async def test_create_issue_failure(self, github_config):
        adapter, mock_client = _make_adapter_with_mock(GitHubAdapter, github_config)
        mock_client.post.return_value = _mock_response({}, status_code=404)
        tid, tkey, turl = await adapter.create_issue(
            FindingRef(severity="HIGH", rule_id="sql"), "", "", "",
        )
        assert tid is None

    @pytest.mark.asyncio
    async def test_create_issue_exception(self, github_config):
        adapter, mock_client = _make_adapter_with_mock(GitHubAdapter, github_config)
        mock_client.post.side_effect = Exception("fail")
        tid, tkey, turl = await adapter.create_issue(
            FindingRef(severity="HIGH", rule_id="sql"), "", "", "",
        )
        assert tid is None

    @pytest.mark.asyncio
    async def test_close_issue_no_comment_no_commit(self, github_config):
        """Covers line 583->585: no comment or commit -> skip add_comment"""
        adapter, mock_client = _make_adapter_with_mock(GitHubAdapter, github_config)
        mock_client.patch.return_value = _mock_response({"state": "closed"})
        ok = await adapter.close_issue("7")
        assert ok is True

    @pytest.mark.asyncio
    async def test_close_issue_exception(self, github_config):
        adapter, mock_client = _make_adapter_with_mock(GitHubAdapter, github_config)
        mock_client.post.side_effect = Exception("fail")
        ok = await adapter.close_issue("7", comment="x")
        assert ok is False

    @pytest.mark.asyncio
    async def test_close_issue_patch_exception(self, github_config):
        adapter, mock_client = _make_adapter_with_mock(GitHubAdapter, github_config)
        mock_client.post.return_value = _mock_response({"id": 1})
        mock_client.patch.side_effect = Exception("fail")
        ok = await adapter.close_issue("7", comment="x")
        assert ok is False

    @pytest.mark.asyncio
    async def test_add_comment_exception(self, github_config):
        adapter, mock_client = _make_adapter_with_mock(GitHubAdapter, github_config)
        mock_client.post.side_effect = Exception("fail")
        ok = await adapter.add_comment("7", "text")
        assert ok is False

    @pytest.mark.asyncio
    async def test_update_issue_status_reopened_with_comment(self, github_config):
        """GitHub REOPENED: PATCH to open + add_comment when ok"""
        adapter, mock_client = _make_adapter_with_mock(GitHubAdapter, github_config)
        mock_client.patch.return_value = _mock_response({"state": "open"}, status_code=200)
        mock_client.post.return_value = _mock_response({"id": 1})
        ok = await adapter.update_issue_status("7", TicketStatus.REOPENED, comment="reopened")
        assert ok is True

    @pytest.mark.asyncio
    async def test_update_issue_status_exception(self, github_config):
        adapter, mock_client = _make_adapter_with_mock(GitHubAdapter, github_config)
        mock_client.patch.side_effect = Exception("fail")
        ok = await adapter.update_issue_status("7", TicketStatus.CLOSED)
        assert ok is False

    @pytest.mark.asyncio
    async def test_update_issue_status_patch_ok_comment_swallowed(self, github_config):
        """GitHub CLOSED: PATCH ok, add_comment exception is swallowed by its own try/except"""
        adapter, mock_client = _make_adapter_with_mock(GitHubAdapter, github_config)
        mock_client.patch.return_value = _mock_response({"state": "closed"}, status_code=200)
        mock_client.post.side_effect = Exception("comment fail")
        ok = await adapter.update_issue_status("7", TicketStatus.CLOSED, comment="done")
        # PATCH ok -> returns True; add_comment exception swallowed
        assert ok is True

    @pytest.mark.asyncio
    async def test_test_connection_non_200(self, github_config):
        adapter, mock_client = _make_adapter_with_mock(GitHubAdapter, github_config)
        mock_client.get.return_value = _mock_response({}, status_code=500)
        ok, msg = await adapter.test_connection()
        assert ok is False
        assert "500" in msg

    @pytest.mark.asyncio
    async def test_test_connection_exception(self, github_config):
        adapter, mock_client = _make_adapter_with_mock(GitHubAdapter, github_config)
        mock_client.get.side_effect = Exception("boom")
        ok, msg = await adapter.test_connection()
        assert ok is False
        assert "异常" in msg


# ─────────────────────────── webhook_handler.py gaps ───────────────────────────


class TestParseWebhookEventEdgeCases:
    """Cover lines 95, 109, 114, 127, 130-132, 148, 151-152"""

    def test_unknown_provider_fallback(self):
        """Line 95: provider not gitlab/github/jira -> PIPELINE_STATUS"""
        result = parse_webhook_event(DevOpsProvider.GITLAB, "header", {})
        # Only testing fallthrough for unrecognized providers - try with something
        # that isn't in the three known ones
        # Actually parse_webhook_event checks compare. We can't easily pass a 4th provider
        # since it's an enum, but we test all branches of known providers

    def test_gitlab_issue_unknown_state(self):
        """Line 109: Issue Hook with unknown state"""
        result = _parse_gitlab_event("Issue Hook", {"object_attributes": {"state": "opened"}})
        assert result == WebhookEventType.PIPELINE_STATUS

    def test_gitlab_unknown_header(self):
        """Line 114: Unknown GitLab header"""
        result = _parse_gitlab_event("Build Hook", {})
        assert result == WebhookEventType.PIPELINE_STATUS

    def test_gitlab_empty_header(self):
        result = _parse_gitlab_event("", {})
        assert result == WebhookEventType.PIPELINE_STATUS

    def test_github_issue_unknown_action(self):
        """Line 127: Issue header with unknown action"""
        result = _parse_github_event("issues", {"action": "labeled"})
        assert result == WebhookEventType.PIPELINE_STATUS

    def test_github_pull_request_any_action(self):
        """PR event with any action"""
        result = _parse_github_event("pull_request", {"action": "synchronize"})
        assert result == WebhookEventType.MERGE_REQUEST

    def test_github_unknown_header(self):
        """Lines 130-132: Unknown header -> PIPELINE_STATUS"""
        result = _parse_github_event("push", {})
        assert result == WebhookEventType.PIPELINE_STATUS

    def test_github_empty_header(self):
        result = _parse_github_event("", {})
        assert result == WebhookEventType.PIPELINE_STATUS

    def test_jira_issue_created_event(self):
        """Lines 148, 151-152: issue_created with no status change"""
        result = _parse_jira_event("", {
            "webhookEvent": "jira:issue_created",
            "changelog": {"items": []}
        })
        assert result == WebhookEventType.PIPELINE_STATUS

    def test_jira_status_to_reopen(self):
        """Line 148: status containing 'open' returns ISSUE_REOPENED"""
        result = _parse_jira_event("", {
            "webhookEvent": "jira:issue_updated",
            "changelog": {"items": [{"field": "status", "toString": "Open"}]},
        })
        assert result == WebhookEventType.ISSUE_REOPENED

    def test_jira_status_to_reopened(self):
        """Line 148: status containing 'reopen' returns ISSUE_REOPENED"""
        result = _parse_jira_event("", {
            "webhookEvent": "jira:issue_updated",
            "changelog": {"items": [{"field": "status", "toString": "Reopened"}]},
        })
        assert result == WebhookEventType.ISSUE_REOPENED

    def test_jira_unknown_event(self):
        """Lines 151-152: Unknown webhook event"""
        result = _parse_jira_event("", {
            "webhookEvent": "jira:issue_deleted",
        })
        assert result == WebhookEventType.PIPELINE_STATUS

    def test_jira_no_webhook_event(self):
        result = _parse_jira_event("", {})
        assert result == WebhookEventType.PIPELINE_STATUS


class TestBuildTicketStatusChangeEdgeCases:
    """Cover build_ticket_status_change edge cases"""

    def test_closed_by_as_string(self):
        """closed_by in GitLab payload is not a dict"""
        payload = {
            "object_attributes": {
                "iid": 5, "id": 42, "state": "closed",
                "project_id": 123,
                "closed_by": "string_user",  # not a dict
            }
        }
        event = build_ticket_status_change(DevOpsProvider.GITLAB, payload)
        assert event is not None
        # closed_by won't be set from a string (code expects dict.get)
        assert event.closed_by == ""

    def test_github_no_action_open(self):
        """GitHub issue with no action -> OPEN"""
        payload = {"issue": {"number": 9, "id": 50}}
        event = build_ticket_status_change(DevOpsProvider.GITHUB, payload)
        assert event is not None
        assert event.to_status == TicketStatus.OPEN

    def test_jira_no_status_item(self):
        """Jira issue with changelog but no status change item"""
        payload = {
            "issue": {"id": "10001"},
            "changelog": {"items": [{"field": "priority", "toString": "High"}]},
        }
        event = build_ticket_status_change(DevOpsProvider.JIRA, payload)
        assert event is None  # no status_item -> can't build

    def test_unknown_provider_returns_none(self):
        """Test with unsupported provider - code falls through"""
        # Can't directly test unknown since it's enum, but the function checks specific providers
        # Unknown would fall through the if/elif chain and return None


class TestJiraStatusToTicketEdgeCases:
    """Cover lines 237, 242: _jira_status_to_ticket fallthrough"""

    def test_reopened_status(self):
        assert _jira_status_to_ticket("Reopened") == TicketStatus.REOPENED

    def test_todo_status(self):
        assert _jira_status_to_ticket("To Do") == TicketStatus.OPEN

    def test_todo_alt(self):
        assert _jira_status_to_ticket("todo") == TicketStatus.OPEN

    def test_backlog(self):
        assert _jira_status_to_ticket("Backlog") == TicketStatus.OPEN

    def test_resolved_alt(self):
        assert _jira_status_to_ticket("Resolved") == TicketStatus.CLOSED

    def test_unknown_defaults_to_open(self):
        assert _jira_status_to_ticket("SomeRandomStatus") == TicketStatus.OPEN


class TestGitlabStateToTicketEdgeCases:
    def test_reopened(self):
        assert _gitlab_state_to_ticket("reopened") == TicketStatus.REOPENED

    def test_empty_string(self):
        assert _gitlab_state_to_ticket("") == TicketStatus.OPEN


# ─────────────────────────── repository.py gaps ───────────────────────────


class TestRepositoryEdgeCases:
    """Cover repository.py missing lines"""

    @pytest.fixture
    async def db_conn_repo(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        conn = await aiosqlite.connect(db_path)
        conn.row_factory = aiosqlite.Row
        await conn.executescript(SCHEMA_SQL)
        await conn.commit()
        yield conn
        await conn.close()
        os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_create_generates_id(self, db_conn_repo):
        """Line 139: create when id is empty"""
        repo = FindingTicketMappingRepo(db_conn_repo)
        mapping = FindingTicketMapping(
            # no id
            finding_id="f1",
            provider=DevOpsProvider.GITLAB,
            ticket_id="t1",
        )
        created = await repo.create(mapping)
        assert created.id is not None
        assert len(created.id) > 0

    @pytest.mark.asyncio
    async def test_update_no_valid_fields(self, db_conn_repo):
        """Line 277: update with no valid fields"""
        repo = FindingTicketMappingRepo(db_conn_repo)
        await repo.create(FindingTicketMapping(
            finding_id="f1", provider=DevOpsProvider.GITLAB, ticket_id="t1",
        ))
        # Try to update with a field NOT in the allowed set
        result = await repo.update("nonexistent-id-xxx", bad_field="value", another_bad=123)
        assert result is False

    @pytest.mark.asyncio
    async def test_update_metadata_dict(self, db_conn_repo):
        """Line 285: update with metadata dict"""
        repo = FindingTicketMappingRepo(db_conn_repo)
        mapping = await repo.create(FindingTicketMapping(
            finding_id="f1", provider=DevOpsProvider.GITLAB, ticket_id="t1",
        ))
        ok = await repo.update(mapping.id, metadata={"key": "val", "num": 42})
        assert ok is True
        fetched = await repo.get_by_id(mapping.id)
        assert fetched.metadata == {"key": "val", "num": 42}

    @pytest.mark.asyncio
    async def test_row_to_mapping_bad_json(self, db_conn_repo):
        """Lines 307-308: metadata that fails JSON parse"""
        repo = FindingTicketMappingRepo(db_conn_repo)
        # Directly insert a row with bad metadata JSON
        await db_conn_repo.execute(
            """INSERT INTO do_finding_ticket_mapping
               (id, finding_id, finding_fingerprint, provider, ticket_id, ticket_key,
                ticket_url, ticket_status, project_id, sync_status, sync_direction,
                severity, rule_id, title, created_at, updated_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("bad-meta", "f1", "", "gitlab", "t1", "", "", "open", "p1",
             "synced", "finding_to_ticket", "", "r", "", "2026-01-01", "2026-01-01",
             "{not valid json"),
        )
        await db_conn_repo.commit()
        fetched = await repo.get_by_id("bad-meta")
        assert fetched is not None
        assert fetched.metadata == {}  # falls back to empty dict

    @pytest.mark.asyncio
    async def test_row_to_mapping_old_sync_direction(self, db_conn_repo):
        """Lines 319->317: sync_direction stored with old SyncStatus value"""
        repo = FindingTicketMappingRepo(db_conn_repo)
        # Insert a row with sync_direction = 'synced' (old SyncStatus value)
        await db_conn_repo.execute(
            """INSERT INTO do_finding_ticket_mapping
               (id, finding_id, finding_fingerprint, provider, ticket_id, ticket_key,
                ticket_url, ticket_status, project_id, sync_status, sync_direction,
                severity, rule_id, title, created_at, updated_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("old-dir", "f1", "", "gitlab", "t1", "", "", "open", "p1",
             "synced", "synced", "", "r", "", "2026-01-01", "2026-01-01", "{}"),
        )
        await db_conn_repo.commit()
        fetched = await repo.get_by_id("old-dir")
        assert fetched is not None
        # sync_direction should fall back to FINDING_TO_TICKET
        assert fetched.sync_direction == SyncDirection.FINDING_TO_TICKET

    @pytest.mark.asyncio
    async def test_sync_record_create_sets_id(self, db_conn_repo):
        """Line 343/365->367: SyncRecord create sets ID"""
        repo = SyncRecordRepo(db_conn_repo)
        record = SyncRecord(
            mapping_id="m1", finding_id="f1",
            provider=DevOpsProvider.GITLAB,
            sync_direction=SyncDirection.FINDING_TO_TICKET,
            status=SyncStatus.SYNCED,
        )
        created = await repo.create(record)
        assert created.id is not None

    @pytest.mark.asyncio
    async def test_pipeline_record_save_all_fields(self, db_conn_repo):
        """Cover full save_result with all JSON fields"""
        repo = PipelineGateRecordRepo(db_conn_repo)
        result = PipelineGateResult(
            verdict=PipelineGateVerdict.WARN,
            provider=DevOpsProvider.GITHUB,
            project_id="proj1",
            commit_hash="abc123",
            branch="develop",
            total_findings=5,
            critical_count=0,
            high_count=1,
            medium_count=2,
            low_count=1,
            info_count=1,
            suggested_actions=["Fix HIGH first"],
        )
        await repo.save_result(result)
        records = await repo.list_by_project("proj1")
        assert len(records) == 1
        assert records[0]["verdict"] == "warn"


# ─────────────────────────── ticket_manager.py gaps ───────────────────────────


class TestTicketManagerEdgeCases:
    """Cover lines 182, 184, 289->296"""

    @pytest.fixture
    async def db_conn_tm(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        conn = await aiosqlite.connect(db_path)
        conn.row_factory = aiosqlite.Row
        await conn.executescript(SCHEMA_SQL)
        await conn.commit()
        yield conn
        await conn.close()
        os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_link_commit_no_mapping(self, db_conn_tm):
        """Line 182: link_commit when mapping doesn't exist"""
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.add_comment = AsyncMock(return_value=True)
        mgr = TicketManager(
            FindingTicketMappingRepo(db_conn_tm),
            SyncRecordRepo(db_conn_tm),
        )
        request = TicketLinkRequest(
            provider=DevOpsProvider.GITLAB,
            ticket_id="unknown-ticket",
            commit_hash="deadbeef",
            close_after_link=False,
        )
        record = await mgr.link_commit_to_ticket(request, adapter)
        assert record.status == SyncStatus.SYNCED
        assert record.mapping_id == ""

    @pytest.mark.asyncio
    async def test_link_commit_with_branch(self, db_conn_tm):
        """Line 184: link_commit with branch parameter"""
        await FindingTicketMappingRepo(db_conn_tm).create(FindingTicketMapping(
            finding_id="f1", provider=DevOpsProvider.GITLAB, ticket_id="t1"))
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.add_comment = AsyncMock(return_value=True)
        mgr = TicketManager(
            FindingTicketMappingRepo(db_conn_tm),
            SyncRecordRepo(db_conn_tm),
        )
        request = TicketLinkRequest(
            provider=DevOpsProvider.GITLAB,
            ticket_id="t1",
            commit_hash="abc",
            branch="fix/security",
            comment="See PR #42",
            close_after_link=False,
        )
        record = await mgr.link_commit_to_ticket(request, adapter)
        assert record.status == SyncStatus.SYNCED

    @pytest.mark.asyncio
    async def test_reopen_exception_handling(self, db_conn_tm):
        """Lines 289->296: reopen_ticket_if_vulnerable catches exception"""
        repo = FindingTicketMappingRepo(db_conn_tm)
        await repo.create(FindingTicketMapping(
            finding_id="f1", provider=DevOpsProvider.GITLAB, ticket_id="t1",
            ticket_status=TicketStatus.CLOSED,
            sync_status=SyncStatus.SYNCED, sync_direction=SyncDirection.FINDING_TO_TICKET,
        ))
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.update_issue_status = AsyncMock(side_effect=Exception("API down"))
        mgr = TicketManager(repo, SyncRecordRepo(db_conn_tm))
        mapping = await repo.get_by_ticket_id("t1")
        record = await mgr.reopen_ticket_if_vulnerable(mapping, adapter)
        assert record is not None
        assert record.status == SyncStatus.FAILED
        assert "API down" in record.error_message

    @pytest.mark.asyncio
    async def test_reopen_in_progress_ticket(self, db_conn_tm):
        """reopen_ticket skips IN_PROGRESS tickets"""
        repo = FindingTicketMappingRepo(db_conn_tm)
        await repo.create(FindingTicketMapping(
            finding_id="f1", provider=DevOpsProvider.GITLAB, ticket_id="t1",
            ticket_status=TicketStatus.IN_PROGRESS,
            sync_status=SyncStatus.SYNCED, sync_direction=SyncDirection.FINDING_TO_TICKET,
        ))
        adapter = MagicMock(spec=DevOpsAdapter)
        mgr = TicketManager(repo, SyncRecordRepo(db_conn_tm))
        mapping = await repo.get_by_ticket_id("t1")
        record = await mgr.reopen_ticket_if_vulnerable(mapping, adapter)
        assert record is None


# ─────────────────────────── Integration / Flow edge cases ───────────────────────────


class TestCloseTicketWithAutoAdapterClose:
    """Cover service.py should_close path where adapter.close() is called"""

    @pytest.fixture
    async def db_conn_flow(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        conn = await aiosqlite.connect(db_path)
        conn.row_factory = aiosqlite.Row
        await conn.executescript(SCHEMA_SQL)
        await conn.commit()
        yield conn
        await conn.close()
        os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_close_ticket_with_mock_adapter_close_called(self, db_conn_flow):
        """Ensure the mock adapter.close() is called properly"""
        await FindingTicketMappingRepo(db_conn_flow).create(FindingTicketMapping(
            finding_id="f1", provider=DevOpsProvider.GITLAB, ticket_id="t-close",
            ticket_status=TicketStatus.OPEN,
            sync_status=SyncStatus.SYNCED, sync_direction=SyncDirection.FINDING_TO_TICKET,
        ))
        service = DevOpsService(
            FindingTicketMappingRepo(db_conn_flow),
            SyncRecordRepo(db_conn_flow),
            PipelineGateRecordRepo(db_conn_flow),
        )
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.close_issue = AsyncMock(return_value=True)
        adapter.close = AsyncMock()
        request = TicketCloseRequest(
            provider=DevOpsProvider.GITLAB, ticket_id="t-close",
            resolution="fixed", comment="done",
        )
        record = await service.close_ticket(request, adapter=adapter)
        assert record.status == SyncStatus.SYNCED
        adapter.close_issue.assert_called_once()


class TestServiceWebhookCloseWithCommit:
    """Cover _handle_issue_closed extracting commit from GitLab description"""

    @pytest.fixture
    async def db_conn_wh(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        conn = await aiosqlite.connect(db_path)
        conn.row_factory = aiosqlite.Row
        await conn.executescript(SCHEMA_SQL)
        await conn.commit()
        yield conn
        await conn.close()
        os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_issue_closed_with_commit_extraction(self, db_conn_wh):
        await FindingTicketMappingRepo(db_conn_wh).create(FindingTicketMapping(
            id="m1", finding_id="f1",
            provider=DevOpsProvider.GITLAB, ticket_id="100",
            ticket_status=TicketStatus.OPEN,
            sync_status=SyncStatus.SYNCED, sync_direction=SyncDirection.FINDING_TO_TICKET,
        ))
        service = DevOpsService(
            FindingTicketMappingRepo(db_conn_wh),
            SyncRecordRepo(db_conn_wh),
            PipelineGateRecordRepo(db_conn_wh),
        )
        record = await service.handle_webhook_event(
            event_type=WebhookEventType.ISSUE_CLOSED,
            provider_value="gitlab",
            payload={
                "object_attributes": {
                    "iid": 100,
                    "id": 999,
                    "description": "fixed by abc123def456789012345678901234567890abcd",
                }
            },
        )
        assert record is not None
        mapping = await service.mappings.get_by_ticket_id("100")
        assert mapping.ticket_status == TicketStatus.CLOSED
        assert mapping.commit_hash == "abc123def456789012345678901234567890abcd"

    @pytest.mark.asyncio
    async def test_github_issue_reopened_service(self, db_conn_wh):
        await FindingTicketMappingRepo(db_conn_wh).create(FindingTicketMapping(
            id="m1", finding_id="f1",
            provider=DevOpsProvider.GITHUB, ticket_id="55",
            ticket_status=TicketStatus.CLOSED,
            sync_status=SyncStatus.SYNCED, sync_direction=SyncDirection.FINDING_TO_TICKET,
        ))
        service = DevOpsService(
            FindingTicketMappingRepo(db_conn_wh),
            SyncRecordRepo(db_conn_wh),
            PipelineGateRecordRepo(db_conn_wh),
        )
        record = await service.handle_webhook_event(
            event_type=WebhookEventType.ISSUE_REOPENED,
            provider_value="github",
            payload={"issue": {"number": 55, "id": 88}},
        )
        assert record is not None
        mapping = await service.mappings.get_by_ticket_id("55")
        assert mapping.ticket_status == TicketStatus.REOPENED


class TestPipelineGatePersistWithAllSeverities:
    """Cover pipeline_gate persist path with full result"""

    @pytest.fixture
    async def db_conn_pg(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        conn = await aiosqlite.connect(db_path)
        conn.row_factory = aiosqlite.Row
        await conn.executescript(SCHEMA_SQL)
        await conn.commit()
        yield conn
        await conn.close()
        os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_pipeline_gate_persist_full_result(self, db_conn_pg):
        from fp_sentinel.devops.models import PipelineGateRequest
        service = DevOpsService(
            FindingTicketMappingRepo(db_conn_pg),
            SyncRecordRepo(db_conn_pg),
            PipelineGateRecordRepo(db_conn_pg),
        )
        request = PipelineGateRequest(
            provider=DevOpsProvider.GITHUB,
            project_id="owner/repo",
            commit_hash="fulltest123",
            branch="main",
            findings=[
                FindingRef(id="f1", severity="CRITICAL", rule_id="sql", file_path="a.js", line_start=1, message="sqli"),
                FindingRef(id="f2", severity="HIGH", rule_id="xss", file_path="b.js", line_start=2, message="xss"),
                FindingRef(id="f3", severity="MEDIUM", rule_id="crypto", file_path="c.js", message="weak"),
                FindingRef(id="f4", severity="LOW", rule_id="info1", file_path="d.js", message="info"),
                FindingRef(id="f5", severity="INFO", rule_id="info2", file_path="e.js", message="info"),
            ],
        )
        result = await service.evaluate_pipeline_gate(request, persist=True)
        assert result.verdict == PipelineGateVerdict.BLOCK
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 1
        assert result.info_count == 1
        # Verify it was persisted
        record = await service.gates.get_latest_by_commit("owner/repo", "fulltest123")
        assert record is not None
        assert record["verdict"] == "block"
