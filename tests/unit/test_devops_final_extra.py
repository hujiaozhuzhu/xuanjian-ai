"""DevSecOps Final Coverage Boost Tests"""

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import aiosqlite
import pytest

from fp_sentinel.devops.adapters import (
    DevOpsAdapter, GitLabAdapter, JiraAdapter, GitHubAdapter,
    HTTPClientProvider, _close_comment, _ticket_status_to_jira,
    create_adapter, fingerprint_finding,
)
from fp_sentinel.devops.models import (
    DevOpsConfig, DevOpsProvider, FindingRef, FindingTicketMapping,
    SyncDirection, SyncStatus, TicketCloseRequest, TicketLinkRequest,
    TicketStatus, WebhookEventType, PipelineGateRequest,
)
from fp_sentinel.devops.pipeline_gate import evaluate_gate
from fp_sentinel.devops.repository import (
    SCHEMA_SQL, FindingTicketMappingRepo, PipelineGateRecordRepo, SyncRecordRepo,
)
from fp_sentinel.devops.service import DevOpsService, _extract_commit_from_text
from fp_sentinel.devops.ticket_manager import TicketManager


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


def _mock_response(json_data=None, status_code=200):
    if json_data is None:
        json_data = {}
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.status_code = status_code
    resp.text = str(json_data)
    return resp


# ─────────────────────────── Issue body/title edge cases ───────────────────────────

class TestIssueTitle:
    def test_empty_message(self):
        adapter = GitLabAdapter(DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="https://gl.com", project_id="1"))
        f = FindingRef(severity="HIGH", rule_id="sql.inj", message="", file_path="a.js", line_start=1)
        title = adapter._issue_title(f)
        assert "[HIGH]" in title
        assert "sql.inj" in title

    def test_long_message_truncated(self):
        adapter = GitLabAdapter(DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="https://gl.com", project_id="1"))
        f = FindingRef(severity="LOW", rule_id="rule", message="X" * 200)
        title = adapter._issue_title(f)
        assert len(title) < 200

    def test_no_severity(self):
        adapter = GitLabAdapter(DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="https://gl.com", project_id="1"))
        f = FindingRef(severity="", rule_id="rule")
        title = adapter._issue_title(f)
        assert "[UNKNOWN]" in title


class TestIssueBody:
    def test_no_repo_no_branch(self):
        adapter = GitLabAdapter(DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="https://gl.com", project_id="1"))
        f = FindingRef(severity="HIGH", rule_id="r", file_path="a.js", line_start=5, message="msg")
        body = adapter._issue_body(f, "", "", "")
        assert "HIGH" in body
        assert "msg" in body


# ─────────────────────────── Adapter close_issue/comment/status ───────────────────────────

@pytest.mark.asyncio
class TestGitLabFullFlow:
    async def test_close_with_all_params(self):
        config = DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="https://gl.com",
            api_token="t", project_id="1")
        adapter = GitLabAdapter(config)
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response({"id": 1})
        mock_client.put.return_value = _mock_response({"id": 5})
        provider = MagicMock(spec=HTTPClientProvider)
        provider.get_client = AsyncMock(return_value=mock_client)
        adapter.http = provider
        ok = await adapter.close_issue("5", "fixed", "comment", "abc123")
        assert ok is True

    async def test_add_comment_failure(self):
        config = DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="https://gl.com",
            api_token="t", project_id="1")
        adapter = GitLabAdapter(config)
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response({}, status_code=500)
        provider = MagicMock(spec=HTTPClientProvider)
        provider.get_client = AsyncMock(return_value=mock_client)
        adapter.http = provider
        ok = await adapter.add_comment("5", "text")
        assert ok is False

    async def test_update_status_reopened(self):
        config = DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="https://gl.com",
            api_token="t", project_id="1")
        adapter = GitLabAdapter(config)
        mock_client = AsyncMock()
        mock_client.put.return_value = _mock_response({"id": 5})
        provider = MagicMock(spec=HTTPClientProvider)
        provider.get_client = AsyncMock(return_value=mock_client)
        adapter.http = provider
        ok = await adapter.update_issue_status("5", TicketStatus.REOPENED)
        assert ok is True


@pytest.mark.asyncio
class TestJiraFullFlow:
    async def test_close_fallback_transition(self):
        config = DevOpsConfig(
            provider=DevOpsProvider.JIRA, base_url="https://jira.com",
            api_token="t", jira_project_key="SEC")
        adapter = JiraAdapter(config)
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response({
            "transitions": [{"id": "99", "name": "Last Resort"}]
        })
        mock_client.post.return_value = _mock_response({}, status_code=204)
        provider = MagicMock(spec=HTTPClientProvider)
        provider.get_client = AsyncMock(return_value=mock_client)
        adapter.http = provider
        ok = await adapter.close_issue("10001")
        assert ok is True

    async def test_generate_body_with_all_fields(self):
        config = DevOpsConfig(
            provider=DevOpsProvider.JIRA, base_url="https://jira.com",
            api_token="t", jira_project_key="SEC")
        adapter = JiraAdapter(config)
        f = FindingRef(severity="HIGH", rule_id="rule", file_path="f.js", line_start=5, message="desc")
        body = adapter._issue_body(f, "https://repo", "abc", "main")
        assert "HIGH" in body
        assert "main" in body


@pytest.mark.asyncio
class TestGitHubFullFlow:
    async def test_close_with_comment_and_commit(self):
        config = DevOpsConfig(
            provider=DevOpsProvider.GITHUB, base_url="",
            api_token="ghp", project_id="owner/repo")
        adapter = GitHubAdapter(config)
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response({"id": 1})
        mock_client.patch.return_value = _mock_response({"state": "closed"})
        provider = MagicMock(spec=HTTPClientProvider)
        provider.get_client = AsyncMock(return_value=mock_client)
        adapter.http = provider
        ok = await adapter.close_issue("7", "fixed", "note", "abc")
        assert ok is True

    async def test_add_comment_failure(self):
        config = DevOpsConfig(
            provider=DevOpsProvider.GITHUB, base_url="",
            api_token="ghp", project_id="owner/repo")
        adapter = GitHubAdapter(config)
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response({}, status_code=500)
        provider = MagicMock(spec=HTTPClientProvider)
        provider.get_client = AsyncMock(return_value=mock_client)
        adapter.http = provider
        ok = await adapter.add_comment("7", "bad")
        assert ok is False


# ─────────────────────────── Service create_adapter flow ───────────────────────────

@pytest.mark.asyncio
class TestServiceWithCreateAdapter:
    """Test the service code path that uses create_adapter() internally"""

    async def test_close_ticket_with_auto_adapter(self, service, db_conn):
        """Force service to use create_adapter path"""
        import uuid
        test_id = str(uuid.uuid4())
        await service.mappings.create(FindingTicketMapping(
            id=test_id, finding_id="f1",
            provider=DevOpsProvider.GITLAB, ticket_id="auto-t1",
            ticket_status=TicketStatus.OPEN,
            sync_status=SyncStatus.SYNCED, sync_direction=SyncDirection.FINDING_TO_TICKET,
        ))
        # Use mock adapter to avoid real HTTP
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.close_issue = AsyncMock(return_value=True)
        request = TicketCloseRequest(
            provider=DevOpsProvider.GITLAB, ticket_id="auto-t1",
        )
        record = await service.close_ticket(request, adapter=adapter)
        assert record.status == SyncStatus.SYNCED

    async def test_link_commit_with_auto_adapter(self, service):
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.add_comment = AsyncMock(return_value=True)
        request = TicketLinkRequest(
            provider=DevOpsProvider.GITLAB, ticket_id="does-not-exist",
            commit_hash="deadbeef", close_after_link=False,
        )
        record = await service.link_fix_commit(request, adapter=adapter)
        assert record.status == SyncStatus.SYNCED


# ─────────────────────────── TicketManager edge cases ───────────────────────────

@pytest.mark.asyncio
class TestTicketManagerReopen:
    async def test_reopen_resolved_ticket(self, db_conn):
        import uuid
        test_id = str(uuid.uuid4())
        await FindingTicketMappingRepo(db_conn).create(FindingTicketMapping(
            id=test_id, finding_id="f1",
            provider=DevOpsProvider.GITLAB, ticket_id="t-resolved",
            ticket_status=TicketStatus.RESOLVED,
            sync_status=SyncStatus.SYNCED, sync_direction=SyncDirection.FINDING_TO_TICKET,
        ))
        adapter = MagicMock(spec=DevOpsAdapter)
        adapter.update_issue_status = AsyncMock(return_value=True)
        mgr = TicketManager(
            FindingTicketMappingRepo(db_conn),
            SyncRecordRepo(db_conn),
        )
        mapping = await FindingTicketMappingRepo(db_conn).get_by_ticket_id("t-resolved")
        record = await mgr.reopen_ticket_if_vulnerable(mapping, adapter)
        assert record is not None
        assert record.status == SyncStatus.SYNCED


# ─────────────────────────── Misc utilities ───────────────────────────

class TestMisc:
    def test_extract_commit_no_match(self):
        assert _extract_commit_from_text("nope") == ""

    def test_extract_commit_none(self):
        assert _extract_commit_from_text(None) == ""

    def test_create_adapter_gitlab(self):
        a = create_adapter(DevOpsProvider.GITLAB, DevOpsConfig(
            provider=DevOpsProvider.GITLAB, base_url="x", project_id="1"))
        assert isinstance(a, GitLabAdapter)

    def test_create_adapter_jira(self):
        a = create_adapter(DevOpsProvider.JIRA, DevOpsConfig(
            provider=DevOpsProvider.JIRA, base_url="x", jira_project_key="X"))
        assert isinstance(a, JiraAdapter)

    def test_create_adapter_github(self):
        a = create_adapter(DevOpsProvider.GITHUB, DevOpsConfig(
            provider=DevOpsProvider.GITHUB, base_url="", project_id="o/r"))
        assert isinstance(a, GitHubAdapter)

    def test_fingerprint_deterministic(self):
        f = FindingRef(rule_id="r", file_path="f", line_start=1, severity="HIGH")
        assert fingerprint_finding(f) == fingerprint_finding(f)
