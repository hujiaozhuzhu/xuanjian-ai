"""DevSecOps Adapters Extra Tests - Cover close_issue, test_connection, comments"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fp_sentinel.devops.adapters import (
    GitLabAdapter,
    JiraAdapter,
    GitHubAdapter,
    HTTPClientProvider,
)
from fp_sentinel.devops.models import (
    DevOpsConfig,
    DevOpsProvider,
    FindingRef,
)


def _mock_response(json_data, status_code=200):
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.status_code = status_code
    resp.text = str(json_data)
    return resp


def _make_adapter_cls(cls, config):
    adapter = cls(config)
    mock_client = AsyncMock()
    mock_provider = MagicMock(spec=HTTPClientProvider)
    mock_provider.get_client = AsyncMock(return_value=mock_client)
    adapter.http = mock_provider
    return adapter, mock_client


@pytest.fixture
def gitlab_config():
    return DevOpsConfig(
        provider=DevOpsProvider.GITLAB, base_url="https://gl.example.com",
        api_token="tok", project_id="123",
    )


@pytest.fixture
def jira_config():
    return DevOpsConfig(
        provider=DevOpsProvider.JIRA, base_url="https://jira.example.com",
        api_token="tok", jira_project_key="SEC",
    )


@pytest.fixture
def github_config():
    return DevOpsConfig(
        provider=DevOpsProvider.GITHUB, base_url="",
        api_token="ghp_x", project_id="owner/repo",
    )


@pytest.mark.asyncio
class TestGitLabAdapter:
    async def test_test_connection_success(self, gitlab_config):
        adapter, mock_client = _make_adapter_cls(GitLabAdapter, gitlab_config)
        mock_client.get.return_value = _mock_response({"version": "15.0"})
        ok, msg = await adapter.test_connection()
        assert ok is True
        assert "15.0" in msg

    async def test_test_connection_401(self, gitlab_config):
        adapter, mock_client = _make_adapter_cls(GitLabAdapter, gitlab_config)
        mock_client.get.return_value = _mock_response({}, status_code=401)
        ok, msg = await adapter.test_connection()
        assert ok is False
        assert "401" in msg or "认证" in msg

    async def test_test_connection_timeout(self, gitlab_config):
        import httpx
        adapter, mock_client = _make_adapter_cls(GitLabAdapter, gitlab_config)
        mock_client.get.side_effect = httpx.TimeoutException("timeout")
        ok, msg = await adapter.test_connection()
        assert ok is False
        assert "超时" in msg

    async def test_close_issue(self, gitlab_config):
        adapter, mock_client = _make_adapter_cls(GitLabAdapter, gitlab_config)
        mock_client.post.return_value = _mock_response({})
        mock_client.put.return_value = _mock_response({"id": 5})
        ok = await adapter.close_issue("5", resolution="fixed", comment="done", commit_hash="abc")
        assert ok is True

    async def test_add_comment(self, gitlab_config):
        adapter, mock_client = _make_adapter_cls(GitLabAdapter, gitlab_config)
        mock_client.post.return_value = _mock_response({"id": 100})
        ok = await adapter.add_comment("5", "comment text")
        assert ok is True

    async def test_update_issue_status_close(self, gitlab_config):
        adapter, mock_client = _make_adapter_cls(GitLabAdapter, gitlab_config)
        mock_client.put.return_value = _mock_response({"id": 5})
        from fp_sentinel.devops.models import TicketStatus
        ok = await adapter.update_issue_status("5", TicketStatus.RESOLVED, comment="done")
        assert ok is True


@pytest.mark.asyncio
class TestJiraAdapter:
    async def test_test_connection_success(self, jira_config):
        adapter, mock_client = _make_adapter_cls(JiraAdapter, jira_config)
        mock_client.get.return_value = _mock_response({"displayName": "Alice"})
        ok, msg = await adapter.test_connection()
        assert ok is True
        assert "Alice" in msg

    async def test_test_connection_401(self, jira_config):
        adapter, mock_client = _make_adapter_cls(JiraAdapter, jira_config)
        mock_client.get.return_value = _mock_response({}, 401)
        ok, msg = await adapter.test_connection()
        assert ok is False

    async def test_close_issue_with_transition(self, jira_config):
        adapter, mock_client = _make_adapter_cls(JiraAdapter, jira_config)
        mock_client.get.return_value = _mock_response({
            "transitions": [{"id": "31", "name": "Done"}]
        })
        mock_client.post.return_value = _mock_response({}, status_code=204)
        ok = await adapter.close_issue("10001", resolution="fixed")
        assert ok is True

    async def test_close_issue_no_transition(self, jira_config):
        adapter, mock_client = _make_adapter_cls(JiraAdapter, jira_config)
        mock_client.get.return_value = _mock_response({"transitions": []})
        ok = await adapter.close_issue("10001")
        assert ok is False

    async def test_add_comment(self, jira_config):
        adapter, mock_client = _make_adapter_cls(JiraAdapter, jira_config)
        mock_client.post.return_value = _mock_response({"id": "1"})
        ok = await adapter.add_comment("10001", "note")
        assert ok is True

    async def test_update_issue_status(self, jira_config):
        adapter, mock_client = _make_adapter_cls(JiraAdapter, jira_config)
        mock_client.get.return_value = _mock_response({
            "transitions": [{"id": "21", "name": "In Progress"}]
        })
        mock_client.post.return_value = _mock_response({}, status_code=204)
        from fp_sentinel.devops.models import TicketStatus
        ok = await adapter.update_issue_status("10001", TicketStatus.IN_PROGRESS)
        assert ok is True


@pytest.mark.asyncio
class TestGitHubAdapter:
    async def test_test_connection_success(self, github_config):
        adapter, mock_client = _make_adapter_cls(GitHubAdapter, github_config)
        mock_client.get.return_value = _mock_response({"login": "alice"})
        ok, msg = await adapter.test_connection()
        assert ok is True
        assert "alice" in msg

    async def test_test_connection_401(self, github_config):
        adapter, mock_client = _make_adapter_cls(GitHubAdapter, github_config)
        mock_client.get.return_value = _mock_response({}, 401)
        ok, msg = await adapter.test_connection()
        assert ok is False

    async def test_close_issue(self, github_config):
        adapter, mock_client = _make_adapter_cls(GitHubAdapter, github_config)
        mock_client.post.return_value = _mock_response({"id": 100})
        mock_client.patch.return_value = _mock_response({"id": 100, "state": "closed"})
        ok = await adapter.close_issue("7", resolution="fixed", commit_hash="abc")
        assert ok is True

    async def test_add_comment(self, github_config):
        adapter, mock_client = _make_adapter_cls(GitHubAdapter, github_config)
        mock_client.post.return_value = _mock_response({"id": 50})
        ok = await adapter.add_comment("7", "fixed")
        assert ok is True

    async def test_update_issue_status_closed(self, github_config):
        adapter, mock_client = _make_adapter_cls(GitHubAdapter, github_config)
        mock_client.patch.return_value = _mock_response({"state": "closed"})
        from fp_sentinel.devops.models import TicketStatus
        ok = await adapter.update_issue_status("7", TicketStatus.CLOSED)
        assert ok is True

    async def test_update_issue_status_reopened(self, github_config):
        adapter, mock_client = _make_adapter_cls(GitHubAdapter, github_config)
        mock_client.patch.return_value = _mock_response({"state": "open"})
        from fp_sentinel.devops.models import TicketStatus
        ok = await adapter.update_issue_status("7", TicketStatus.REOPENED)
        assert ok is True
