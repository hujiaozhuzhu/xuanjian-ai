"""DevSecOps Adapters Tests - Mock HTTP"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fp_sentinel.devops.adapters import (
    GitLabAdapter,
    JiraAdapter,
    GitHubAdapter,
    HTTPClientProvider,
    create_adapter,
    fingerprint_finding,
    _close_comment,
    _ticket_status_to_jira,
)
from fp_sentinel.devops.models import (
    DevOpsConfig,
    DevOpsProvider,
    FindingRef,
    TicketStatus,
)


@pytest.fixture
def gitlab_config():
    return DevOpsConfig(
        provider=DevOpsProvider.GITLAB,
        base_url="https://gitlab.example.com",
        api_token="test-token",
        project_id="123",
    )


@pytest.fixture
def jira_config():
    return DevOpsConfig(
        provider=DevOpsProvider.JIRA,
        base_url="https://jira.example.com",
        api_token="test-token",
        jira_project_key="SEC",
    )


@pytest.fixture
def github_config():
    return DevOpsConfig(
        provider=DevOpsProvider.GITHUB,
        base_url="",
        api_token="ghp_test",
        project_id="owner/repo",
    )


def _mock_response(json_data, status_code=200):
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.status_code = status_code
    resp.text = str(json_data)
    return resp


class TestCreateAdapter:
    def test_gitlab(self):
        config = DevOpsConfig(provider=DevOpsProvider.GITLAB, base_url="")
        adapter = create_adapter(DevOpsProvider.GITLAB, config)
        assert isinstance(adapter, GitLabAdapter)

    def test_jira(self):
        adapter = create_adapter(DevOpsProvider.JIRA, DevOpsConfig(
            provider=DevOpsProvider.JIRA, base_url="", jira_project_key="X"))
        assert isinstance(adapter, JiraAdapter)

    def test_github(self):
        adapter = create_adapter(DevOpsProvider.GITHUB, DevOpsConfig(
            provider=DevOpsProvider.GITHUB, base_url="", project_id="o/r"))
        assert isinstance(adapter, GitHubAdapter)

    def test_invalid_provider(self):
        with pytest.raises(ValueError):
            create_adapter("invalid", DevOpsConfig(
                provider=DevOpsProvider.GITLAB, base_url=""))


class TestFingerprintFinding:
    def test_same_finding_same_fp(self):
        f1 = FindingRef(rule_id="sql", file_path="a.js", line_start=10, severity="HIGH")
        f2 = FindingRef(rule_id="sql", file_path="a.js", line_start=10, severity="HIGH")
        assert fingerprint_finding(f1) == fingerprint_finding(f2)

    def test_different_finding_different_fp(self):
        f1 = FindingRef(rule_id="sql", file_path="a.js", line_start=10, severity="HIGH")
        f2 = FindingRef(rule_id="xss", file_path="a.js", line_start=10, severity="HIGH")
        assert fingerprint_finding(f1) != fingerprint_finding(f2)

    def test_deterministic_fp(self):
        f = FindingRef(rule_id="r", file_path="f.js", line_start=1, severity="HIGH")
        fp1 = fingerprint_finding(f)
        fp2 = fingerprint_finding(f)
        assert fp1 == fp2


class TestCloseComment:
    def test_all_fields(self):
        c = _close_comment("fixed", "done", "abc123")
        assert "fixed" in c
        assert "abc123" in c
        assert "done" in c

    def test_minimal(self):
        c = _close_comment("fixed", "", "")
        assert "fixed" in c


class TestTicketStatusToJira:
    def test_open(self):
        assert _ticket_status_to_jira(TicketStatus.OPEN) == "To Do"

    def test_closed(self):
        assert _ticket_status_to_jira(TicketStatus.CLOSED) == "Done"

    def test_in_progress(self):
        assert _ticket_status_to_jira(TicketStatus.IN_PROGRESS) == "In Progress"


class TestGitLabAdapter:
    def test_headers_with_token(self, gitlab_config):
        adapter = GitLabAdapter(gitlab_config)
        h = adapter._headers()
        assert h["PRIVATE-TOKEN"] == "test-token"
        assert h["Content-Type"] == "application/json"

    def test_headers_without_token(self):
        config = DevOpsConfig(provider=DevOpsProvider.GITLAB, base_url="")
        adapter = GitLabAdapter(config)
        h = adapter._headers()
        assert "PRIVATE-TOKEN" not in h

    def test_issue_title(self, gitlab_config):
        adapter = GitLabAdapter(gitlab_config)
        f = FindingRef(severity="HIGH", rule_id="sql.inj", message="SQL Injection vulnerability")
        title = adapter._issue_title(f)
        assert "[HIGH]" in title
        assert "sql.inj" in title

    def test_issue_body(self, gitlab_config):
        adapter = GitLabAdapter(gitlab_config)
        f = FindingRef(severity="HIGH", rule_id="sql.inj", file_path="a.js", line_start=10, message="SQLi")
        body = adapter._issue_body(f, "https://repo.example.com", "abc123", "main")
        assert "HIGH" in body
        assert "abc123" in body
        assert "main" in body
        assert "a.js" in body

    @pytest.mark.asyncio
    async def test_create_issue_success(self, gitlab_config):
        from fp_sentinel.devops.adapters import GitLabAdapter
        adapter = GitLabAdapter(gitlab_config)
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response({
            "id": "42",
            "iid": "5",
            "web_url": "https://gitlab.example.com/proj/123/issues/5",
        })
        mock_provider = MagicMock(spec=HTTPClientProvider)
        mock_provider.get_client = AsyncMock(return_value=mock_client)
        adapter.http = mock_provider

        tid, tkey, turl = await adapter.create_issue(
            FindingRef(severity="HIGH", rule_id="sql"),
            "https://repo.example.com", "abc123", "main",
        )
        assert tid == "42"
        assert tkey == "5"
        assert "issues/5" in turl

    @pytest.mark.asyncio
    async def test_create_issue_failure(self, gitlab_config):
        adapter = GitLabAdapter(gitlab_config)
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response({}, status_code=401)
        mock_provider = MagicMock(spec=HTTPClientProvider)
        mock_provider.get_client = AsyncMock(return_value=mock_client)
        adapter.http = mock_provider

        tid, tkey, turl = await adapter.create_issue(
            FindingRef(severity="HIGH", rule_id="sql"),
            "", "", "",
        )
        assert tid is None
        assert tkey is None


class TestJiraAdapter:
    def test_headers_with_token(self, jira_config):
        adapter = JiraAdapter(jira_config)
        h = adapter._headers()
        assert "Authorization" in h
        assert h["Authorization"].startswith("Basic ")

    def test_issue_body_contains_commit(self, jira_config):
        adapter = JiraAdapter(jira_config)
        f = FindingRef(severity="CRITICAL", rule_id="sql", file_path="a.js", line_start=1, message="vuln")
        body = adapter._issue_body(f, "", "deadbeef", "main")
        assert "deadbeef" in body
        assert "CRITICAL" in body


class TestGitHubAdapter:
    def test_headers(self, github_config):
        adapter = GitHubAdapter(github_config)
        h = adapter._headers()
        assert "Authorization" in h
        assert h["Authorization"] == "Bearer ghp_test"
        assert "Accept" in h

    @pytest.mark.asyncio
    async def test_create_issue_success(self, github_config):
        adapter = GitHubAdapter(github_config)
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response({
            "id": 99,
            "number": 7,
            "html_url": "https://github.com/owner/repo/issues/7",
        })
        mock_provider = MagicMock(spec=HTTPClientProvider)
        mock_provider.get_client = AsyncMock(return_value=mock_client)
        adapter.http = mock_provider

        tid, tkey, turl = await adapter.create_issue(
            FindingRef(severity="HIGH", rule_id="xss"),
            "", "", "",
        )
        assert tid == "99"
        assert tkey == "7"
        assert "issues/7" in turl
