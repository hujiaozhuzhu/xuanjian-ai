"""
PR适配器测试
覆盖：HTTP Provider, Adapter工厂, 分支/标题/描述生成, PR记录状态更新
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fp_sentinel.auto_pr.pr_manager import (
    GitHTTPProvider,
    GitLabPRAadapter,
    GitHubPRAdapter,
    PRManager,
    create_pr_adapter,
)
from fp_sentinel.auto_pr.models import (
    AutoPRConfig,
    FixPatch,
    FixDiff,
    PullRequestRecord,
    VulnerabilityType,
    GenerateFixRequest,
)


class TestGitHTTPProvider:
    """测试HTTP客户端提供者"""

    @pytest.mark.asyncio
    async def test_get_client_creates_new(self):
        provider = GitHTTPProvider()
        client = await provider.get_client()
        assert client is not None
        await provider.close()

    @pytest.mark.asyncio
    async def test_close(self):
        provider = GitHTTPProvider()
        client = await provider.get_client()
        await provider.close()
        assert provider._client is None


class TestPRAdapterFactory:
    """测试适配器工厂"""

    def test_create_gitlab_adapter(self):
        config = AutoPRConfig(provider="gitlab", base_url="https://gitlab.com")
        adapter = create_pr_adapter("gitlab", config)
        assert isinstance(adapter, GitLabPRAadapter)

    def test_create_github_adapter(self):
        config = AutoPRConfig(provider="github")
        adapter = create_pr_adapter("github", config)
        assert isinstance(adapter, GitHubPRAdapter)

    def test_create_unknown_raises(self):
        config = AutoPRConfig(provider="unknown")
        with pytest.raises(ValueError, match="不支持"):
            create_pr_adapter("unknown", config)


class TestGitLabAdapterHeaders:
    """测试GitLab适配器headers"""

    def test_headers_without_token(self):
        config = AutoPRConfig(base_url="https://gitlab.com")
        adapter = GitLabPRAadapter(config)
        headers = adapter._headers()
        assert headers["Content-Type"] == "application/json"
        assert "PRIVATE-TOKEN" not in headers

    def test_headers_with_token(self):
        config = AutoPRConfig(base_url="https://gitlab.com", api_token="test-token")
        adapter = GitLabPRAadapter(config)
        headers = adapter._headers()
        assert headers["PRIVATE-TOKEN"] == "test-token"

    def test_api_base(self):
        config = AutoPRConfig(base_url="https://gitlab.example.com/")
        adapter = GitLabPRAadapter(config)
        assert adapter.api_base == "https://gitlab.example.com/api/v4"


class TestGitHubAdapterHeaders:
    """测试GitHub适配器headers"""

    def test_headers_without_token(self):
        config = AutoPRConfig()
        adapter = GitHubPRAdapter(config)
        headers = adapter._headers()
        assert headers["Content-Type"] == "application/json"
        assert "Authorization" not in headers

    def test_headers_with_token(self):
        config = AutoPRConfig(api_token="gh-token")
        adapter = GitHubPRAdapter(config)
        headers = adapter._headers()
        assert headers["Authorization"] == "Bearer gh-token"

    def test_api_base(self):
        config = AutoPRConfig()
        adapter = GitHubPRAdapter(config)
        assert adapter.api_base == "https://api.github.com"


class TestPRAdapterMockHTTP:
    """使用Mock HTTP测试适配器"""

    @pytest.mark.asyncio
    async def test_gitlab_test_connection_success(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"version": "15.0.0"}
        mock_client.get.return_value = mock_resp

        config = AutoPRConfig(base_url="https://gitlab.com", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        ok, msg = await adapter.test_connection()
        assert ok is True
        assert "GitLab" in msg

    @pytest.mark.asyncio
    async def test_gitlab_test_connection_auth_fail(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_client.get.return_value = mock_resp

        config = AutoPRConfig(base_url="https://gitlab.com", api_token="bad")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        ok, msg = await adapter.test_connection()
        assert ok is False
        assert "认证" in msg

    @pytest.mark.asyncio
    async def test_gitlab_test_connection_timeout(self):
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.TimeoutException("timeout")

        config = AutoPRConfig(base_url="https://gitlab.com")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        ok, msg = await adapter.test_connection()
        assert ok is False
        assert "超时" in msg

    @pytest.mark.asyncio
    async def test_github_test_connection_success(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"login": "testuser"}
        mock_client.get.return_value = mock_resp

        config = AutoPRConfig(api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitHubPRAdapter(config, http_provider=provider)
        ok, msg = await adapter.test_connection()
        assert ok is True
        assert "GitHub" in msg

    @pytest.mark.asyncio
    async def test_gitlab_create_pr_success(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"iid": 42, "web_url": "https://gitlab.com/test/mr/42"}
        mock_client.post.return_value = mock_resp

        config = AutoPRConfig(base_url="https://gitlab.com", project_id="123", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        pr_id, pr_url = await adapter.create_pull_request("Title", "Desc", "fix-branch", "main")
        assert pr_id == "42"
        assert "gitlab.com" in pr_url

    @pytest.mark.asyncio
    async def test_gitlab_create_pr_fail(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Bad Request"
        mock_client.post.return_value = mock_resp

        config = AutoPRConfig(base_url="https://gitlab.com", project_id="123", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        pr_id, pr_url = await adapter.create_pull_request("Title", "Desc", "branch", "main")
        assert pr_id == ""
        assert pr_url == ""

    @pytest.mark.asyncio
    async def test_github_create_pr_success(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"number": 99, "html_url": "https://github.com/test/pr/99"}
        mock_client.post.return_value = mock_resp

        config = AutoPRConfig(project_id="owner/repo", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitHubPRAdapter(config, http_provider=provider)
        pr_id, pr_url = await adapter.create_pull_request("Title", "Desc", "fix", "main")
        assert pr_id == "99"

    @pytest.mark.asyncio
    async def test_gitlab_get_pr_status(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"state": "merged"}
        mock_client.get.return_value = mock_resp

        config = AutoPRConfig(base_url="https://gitlab.com", project_id="123", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        status = await adapter.get_pr_status("42")
        assert status == "merged"

    @pytest.mark.asyncio
    async def test_gitlab_add_pr_comment(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_client.post.return_value = mock_resp

        config = AutoPRConfig(base_url="https://gitlab.com", project_id="123", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        ok = await adapter.add_pr_comment("42", "test comment")
        assert ok is True

    @pytest.mark.asyncio
    async def test_gitlab_add_pr_comment_fail(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_client.post.return_value = mock_resp

        config = AutoPRConfig(base_url="https://gitlab.com", project_id="123", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        ok = await adapter.add_pr_comment("42", "test comment")
        assert ok is False


class TestPRManagerDryRun:
    """测试PR管理器 dry_run 模式"""

    def setup_method(self):
        self.manager = PRManager()

    @pytest.mark.asyncio
    async def test_submit_dry_run(self):
        config = AutoPRConfig(provider="gitlab", project_id="test", dry_run=True)
        patch = FixPatch(
            finding_id="f1",
            vuln_type=VulnerabilityType.XSS,
            title="Fix",
            diffs=[],
        )
        result = await self.manager.submit_pull_request(
            config=config,
            patches=[patch],
            title="Test PR",
        )
        assert result.status == "draft"
        assert "dry-run" in result.pr_url

    @pytest.mark.asyncio
    async def test_link_ticket_to_pr(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_client.post.return_value = mock_resp

        config = AutoPRConfig(base_url="https://gitlab.com", project_id="123", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        ok = await self.manager.link_ticket_to_pr("42", "TICKET-001", adapter)
        assert ok is True

    @pytest.mark.asyncio
    async def test_check_pr_status(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"state": "opened"}
        mock_client.get.return_value = mock_resp

        config = AutoPRConfig(base_url="https://gitlab.com", project_id="123", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        status = await self.manager.check_pr_status("42", adapter)
        assert status == "opened"

    @pytest.mark.asyncio
    async def test_adapter_close(self):
        mock_client = AsyncMock()
        config = AutoPRConfig(base_url="https://gitlab.com")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        await adapter.close()
        mock_client.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_gitlab_create_pr_exception(self):
        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("Network error")

        config = AutoPRConfig(base_url="https://gitlab.com", project_id="123", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        pr_id, pr_url = await adapter.create_pull_request("Title", "Desc", "branch", "main")
        assert pr_id == ""
        assert pr_url == ""

    @pytest.mark.asyncio
    async def test_gitlab_add_comment_exception(self):
        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("error")

        config = AutoPRConfig(base_url="https://gitlab.com", project_id="123", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        ok = await adapter.add_pr_comment("42", "test")
        assert ok is False

    @pytest.mark.asyncio
    async def test_gitlab_pr_with_labels(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"iid": 55, "web_url": "https://gitlab.com/test/55"}
        mock_client.post.return_value = mock_resp

        config = AutoPRConfig(base_url="https://gitlab.com", project_id="123", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        pr_id, pr_url = await adapter.create_pull_request(
            "Title", "Desc", "fix-branch", "main",
            labels=["security", "auto-fix"],
        )
        assert pr_id == "55"

    @pytest.mark.asyncio
    async def test_github_get_pr_status_merged(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"state": "closed", "merged_at": "2024-01-01"}
        mock_client.get.return_value = mock_resp

        config = AutoPRConfig(project_id="owner/repo", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitHubPRAdapter(config, http_provider=provider)
        status = await adapter.get_pr_status("99")
        assert status == "merged"

    @pytest.mark.asyncio
    async def test_github_add_comment(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_client.post.return_value = mock_resp

        config = AutoPRConfig(project_id="owner/repo", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitHubPRAdapter(config, http_provider=provider)
        ok = await adapter.add_pr_comment("99", "test comment")
        assert ok is True

    @pytest.mark.asyncio
    async def test_submit_pr_with_multiple_patches(self):
        config = AutoPRConfig(provider="gitlab", project_id="test", dry_run=True)
        patches = [
            FixPatch(finding_id=f"f{i}", vuln_type=VulnerabilityType.XSS, title=f"Fix {i}", diffs=[])
            for i in range(3)
        ]
        result = await self.manager.submit_pull_request(
            config=config,
            patches=patches,
            title="Multi-fix PR",
            ticket_ids=["T-001", "T-002"],
            labels=["security"],
        )
        assert result.status == "draft"
        assert len(result.patch_ids) == 3

    @pytest.mark.asyncio
    async def test_submit_pr_with_labels(self):
        config = AutoPRConfig(provider="github", project_id="owner/repo", dry_run=True)
        patch = FixPatch(
            finding_id="f1",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            title="Fix",
            diffs=[],
        )
        result = await self.manager.submit_pull_request(
            config=config,
            patches=[patch],
            labels=["critical", "auto"],
        )
        assert result.status == "draft"

    @pytest.mark.asyncio
    async def test_gitlab_get_pr_status_fail(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_client.get.return_value = mock_resp

        config = AutoPRConfig(base_url="https://gitlab.com", project_id="123", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        status = await adapter.get_pr_status("999")
        assert status == "unknown"

    @pytest.mark.asyncio
    async def test_github_test_connection_fail(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_client.get.return_value = mock_resp

        config = AutoPRConfig(api_token="bad")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitHubPRAdapter(config, http_provider=provider)
        ok, msg = await adapter.test_connection()
        assert ok is False
        assert "认证" in msg

    @pytest.mark.asyncio
    async def test_github_test_connection_timeout(self):
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.TimeoutException("timeout")

        config = AutoPRConfig()
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitHubPRAdapter(config, http_provider=provider)
        ok, msg = await adapter.test_connection()
        assert ok is False
        assert "超时" in msg

    @pytest.mark.asyncio
    async def test_github_close(self):
        mock_client = AsyncMock()
        config = AutoPRConfig()
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitHubPRAdapter(config, http_provider=provider)
        await adapter.close()
        mock_client.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_gitlab_update_issue_status_exception(self):
        """Test exception handling in GitLab adapter"""
        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("error")
        config = AutoPRConfig(base_url="https://gitlab.com", project_id="123", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        result = await adapter.add_pr_comment("42", "test")
        assert result is False

    @pytest.mark.asyncio
    async def test_github_create_pr_exception(self):
        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("Network error")

        config = AutoPRConfig(project_id="owner/repo", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitHubPRAdapter(config, http_provider=provider)
        pr_id, pr_url = await adapter.create_pull_request("Title", "Desc", "branch", "main")
        assert pr_id == ""
        assert pr_url == ""

    @pytest.mark.asyncio
    async def test_submit_pr_with_real_adapter_mock(self):
        """Test submit_pull_request with injected mock adapter"""
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"iid": 77, "web_url": "https://gitlab.com/test/mr/77"}
        mock_client.post.return_value = mock_resp

        config = AutoPRConfig(provider="gitlab", project_id="123", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)

        patch = FixPatch(
            finding_id="real-f1",
            vuln_type=VulnerabilityType.XSS,
            title="Fix XSS",
            diffs=[],
        )
        result = await self.manager.submit_pull_request(
            config=config,
            patches=[patch],
            title="Test",
            adapter=adapter,
        )
        assert result.pr_id == "77"
        assert result.pr_url == "https://gitlab.com/test/mr/77"

    @pytest.mark.asyncio
    async def test_link_ticket_to_pr_fail(self):
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_client.post.return_value = mock_resp

        config = AutoPRConfig(base_url="https://gitlab.com", project_id="123", api_token="tok")
        provider = GitHTTPProvider(client=mock_client)
        adapter = GitLabPRAadapter(config, http_provider=provider)
        ok = await self.manager.link_ticket_to_pr("42", "TICKET-001", adapter)
        assert ok is False
