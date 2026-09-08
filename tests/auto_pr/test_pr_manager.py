"""
PR管理器测试
覆盖：PR记录创建、分支名生成、PR标题/描述生成、工具函数
"""

import pytest
from fp_sentinel.auto_pr.pr_manager import (
    PRManager,
    _generate_branch_name,
    _generate_pr_title,
    _generate_pr_description,
)
from fp_sentinel.auto_pr.models import (
    FixPatch,
    VulnerabilityType,
    FixDiff,
)
from fp_sentinel.auto_pr.pr_manager import create_pr_adapter


# ─────────────────────── 工具函数测试 ───────────────────────

class TestUtilityFunctions:
    def test_generate_branch_name(self):
        name = _generate_branch_name("xuanjian-fix/")
        assert name.startswith("xuanjian-fix/")
        assert len(name) > len("xuanjian-fix/")

    def test_generate_branch_name_unique(self):
        """每次生成的分支名应不同"""
        names = {_generate_branch_name("test/") for _ in range(10)}
        assert len(names) == 10

    def test_generate_pr_title_single_patch(self):
        patch = FixPatch(
            finding_id="f1",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            title="SQL 注入修复",
            diffs=[],
        )
        title = _generate_pr_title([patch])
        assert "SQL" in title
        assert title.startswith("[玄鉴]")

    def test_generate_pr_title_multiple_patches(self):
        patches = [
            FixPatch(finding_id="f1", vuln_type=VulnerabilityType.SQL_INJECTION, title="Fix SQLi", diffs=[]),
            FixPatch(finding_id="f2", vuln_type=VulnerabilityType.XSS, title="Fix XSS", diffs=[]),
        ]
        title = _generate_pr_title(patches)
        assert "2" in title
        assert title.startswith("[玄鉴]")

    def test_generate_pr_title_empty(self):
        title = _generate_pr_title([])
        assert title == "[玄鉴] 安全修复"

    def test_generate_pr_description(self):
        patch = FixPatch(
            finding_id="f1",
            vuln_type=VulnerabilityType.XSS,
            title="XSS Fix",
            diffs=[FixDiff(
                file_path="app.js",
                original_code="el.innerHTML = userInput",
                fixed_code="el.textContent = userInput",
                description="Use textContent",
            )],
            effort_minutes=30,
            reference_cve="CVE-2014-9031",
            incident_note="XSS incident note",
        )
        desc = _generate_pr_description([patch], ticket_ids=["TICKET-001"])
        assert "玄鉴 v3.0" in desc
        assert "XSS" in desc
        assert "CVE-2014-9031" in desc
        assert "TICKET-001" in desc
        assert "关联工单" in desc


# ─────────────────────── PR记录管理测试 ───────────────────────

class TestPRManager:
    def setup_method(self):
        self.manager = PRManager()

    def test_create_pr_record(self):
        record = self.manager.create_pr_record(
            provider="gitlab",
            project_id="123",
            repository_url="https://gitlab.com/test/repo",
            pr_id="42",
            pr_url="https://gitlab.com/test/repo/merge_requests/42",
            pr_title="Test PR",
            branch="xuanjian-fix/test-001",
            patch_ids=["p1", "p2"],
            finding_ids=["f1", "f2"],
            ticket_ids=["T-001"],
        )
        assert record.pr_id == "42"
        assert record.provider == "gitlab"
        assert record.status == "open"
        assert len(record.patch_ids) == 2

    def test_create_draft_record(self):
        """没有pr_id的记录状态应为draft"""
        record = self.manager.create_pr_record(
            provider="gitlab",
            project_id="123",
            repository_url="",
            branch="xuanjian-fix/test",
        )
        assert record.status == "draft"
        assert record.pr_id == ""

    def test_get_record(self):
        self.manager.create_pr_record(
            provider="gitlab",
            project_id="123",
            repository_url="",
            pr_id="99",
            pr_title="Test",
        )
        record = self.manager.get_record("99")
        assert record is not None
        assert record.pr_title == "Test"

    def test_get_record_not_found(self):
        assert self.manager.get_record("nonexistent") is None

    def test_list_records(self):
        for i in range(3):
            self.manager.create_pr_record(
                provider="gitlab",
                project_id="123",
                repository_url="",
                pr_id=f"pr-{i}",
            )
        records = self.manager.list_records()
        assert len(records) == 3

    def test_update_record_status(self):
        self.manager.create_pr_record(
            provider="gitlab",
            project_id="123",
            repository_url="",
            pr_id="100",
        )
        ok = self.manager.update_record_status("100", "merged", merge_commit_hash="abc123")
        assert ok is True
        record = self.manager.get_record("100")
        assert record.status == "merged"
        assert record.merge_commit_hash == "abc123"

    def test_update_nonexistent_record(self):
        assert self.manager.update_record_status("nonexistent", "closed") is False


# ─────────────────────── 适配器工厂测试 ───────────────────────

class TestAdapterFactory:
    def test_create_gitlab_adapter(self):
        from fp_sentinel.auto_pr.pr_manager import GitLabPRAadapter
        from fp_sentinel.auto_pr.models import AutoPRConfig
        config = AutoPRConfig(provider="gitlab", base_url="https://gitlab.com")
        adapter = create_pr_adapter("gitlab", config)
        assert isinstance(adapter, GitLabPRAadapter)

    def test_create_github_adapter(self):
        from fp_sentinel.auto_pr.pr_manager import GitHubPRAdapter
        from fp_sentinel.auto_pr.models import AutoPRConfig
        config = AutoPRConfig(provider="github")
        adapter = create_pr_adapter("github", config)
        assert isinstance(adapter, GitHubPRAdapter)

    def test_create_unknown_adapter_raises(self):
        from fp_sentinel.auto_pr.models import AutoPRConfig
        config = AutoPRConfig(provider="unknown")
        with pytest.raises(ValueError, match="不支持的Git平台"):
            create_pr_adapter("unknown", config)
