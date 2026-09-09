"""
AutoPR 业务编排服务测试
覆盖：编排流程、修复历史、统计、自定义修改、PR状态查询
"""

import pytest
from fp_sentinel.auto_pr.service import AutoPRService
from fp_sentinel.auto_pr.models import (
    AutoPRConfig,
    FixRecord,
    FixStatus,
    GenerateFixRequest,
    VerificationStatus,
    VulnerabilityType,
)


class TestAutoPRService:
    """测试业务编排服务"""

    def setup_method(self):
        self.service = AutoPRService()

    # ─────────────────── 预览生成 ───────────────────

    @pytest.mark.asyncio
    async def test_generate_and_preview(self):
        requests = [
            GenerateFixRequest(
                finding_id="svc-f1",
                rule_id="py.injection.sql",
                severity="HIGH",
                file_path="app.py",
                code_snippet='cursor.execute("SELECT * FROM users WHERE id = " + uid)',
            ),
        ]
        results = await self.service.generate_and_preview(requests)
        assert len(results) == 1
        assert results[0]["finding_id"] == "svc-f1"
        assert results[0]["vuln_type"] == "sql_injection"
        assert "unified_diff" in results[0]

    @pytest.mark.asyncio
    async def test_generate_and_preview_multiple(self):
        requests = [
            GenerateFixRequest(
                finding_id=f"multi-{i}",
                rule_id=f"py.rule.{i}",
                severity="HIGH",
                file_path="app.py",
                code_snippet="test code",
            )
            for i in range(3)
        ]
        results = await self.service.generate_and_preview(requests)
        assert len(results) == 3

    # ─────────────────── 生成+验证 ───────────────────

    @pytest.mark.asyncio
    async def test_generate_and_verify(self):
        requests = [
            GenerateFixRequest(
                finding_id="verify-f1",
                rule_id="py.injection.sql",
                severity="HIGH",
                file_path="app.py",
                code_snippet='cursor.execute("SELECT * FROM users WHERE id = " + uid)',
            ),
        ]
        results = await self.service.generate_and_verify(requests, auto_verify=True)
        assert len(results) == 1
        assert "patch_id" in results[0]
        assert "verification" in results[0]

    @pytest.mark.asyncio
    async def test_generate_and_verify_with_original_codes(self):
        requests = [
            GenerateFixRequest(
                finding_id="verify-f2",
                rule_id="py.injection.sql",
                severity="HIGH",
                file_path="app.py",
                code_snippet="original bad code",
            ),
        ]
        original_codes = {"verify-f2": 'cursor.execute("SELECT * FROM users WHERE id = " + uid)'}
        results = await self.service.generate_and_verify(
            requests, original_codes=original_codes
        )
        assert len(results) == 1
        assert "verification" in results[0]

    @pytest.mark.asyncio
    async def test_generate_and_verify_with_custom_codes(self):
        requests = [
            GenerateFixRequest(
                finding_id="verify-f3",
                rule_id="py.injection.sql",
                severity="HIGH",
                file_path="app.py",
                code_snippet="bad code",
            ),
        ]
        custom_codes = {"verify-f3": 'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))'}
        results = await self.service.generate_and_verify(
            requests, custom_codes=custom_codes
        )
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_generate_without_verify(self):
        requests = [
            GenerateFixRequest(
                finding_id="no-verify-f1",
                rule_id="py.injection.sql",
                severity="HIGH",
                file_path="app.py",
                code_snippet="test",
            ),
        ]
        results = await self.service.generate_and_verify(requests, auto_verify=False)
        assert len(results) == 1
        assert "verification" not in results[0]

    # ─────────────────── PR提交 ───────────────────

    @pytest.mark.asyncio
    async def test_submit_fix_pr_dry_run(self):
        """Generate preview first so patch exists, then submit"""
        requests = [
            GenerateFixRequest(
                finding_id="dryrun-f1",
                rule_id="py.xss.dom",
                severity="HIGH",
                file_path="app.js",
                code_snippet="el.innerHTML = x",
            ),
        ]
        await self.service.generate_and_verify(requests, auto_verify=False)
        config = AutoPRConfig(provider="gitlab", project_id="test-project", dry_run=True)
        result = await self.service.submit_fix_pr(
            config=config,
            finding_ids=["dryrun-f1"],
            title="Test PR",
        )
        assert result.get("status") in ("error", "submitted")

    @pytest.mark.asyncio
    async def test_submit_fix_pr_with_errors(self):
        config = AutoPRConfig(provider="gitlab", project_id="test")
        result = await self.service.submit_fix_pr(
            config=config,
            finding_ids=["nonexistent"],
        )
        assert result.get("status") == "error"
        assert len(result.get("errors", [])) > 0

    @pytest.mark.asyncio
    async def test_submit_fix_pr_empty(self):
        config = AutoPRConfig(provider="gitlab", project_id="test")
        result = await self.service.submit_fix_pr(
            config=config,
            finding_ids=[],
        )
        assert result.get("status") == "error"

    # ─────────────────── 修复历史 ───────────────────

    @pytest.mark.asyncio
    async def test_get_fix_history_empty(self):
        history = await self.service.get_fix_history()
        assert isinstance(history, list)
        assert len(history) == 0

    @pytest.mark.asyncio
    async def test_get_fix_history_after_preview(self):
        requests = [
            GenerateFixRequest(
                finding_id="hist-f1",
                rule_id="py.injection.sql",
                severity="HIGH",
                file_path="app.py",
                code_snippet="test",
            ),
        ]
        await self.service.generate_and_preview(requests)
        history = await self.service.get_fix_history()
        assert len(history) == 1
        assert history[0].finding_id == "hist-f1"

    @pytest.mark.asyncio
    async def test_get_fix_history_by_finding_id(self):
        requests = [
            GenerateFixRequest(finding_id="hist-f2", rule_id="py.rule", severity="HIGH",
                             file_path="app.py", code_snippet="test"),
        ]
        await self.service.generate_and_preview(requests)
        history = await self.service.get_fix_history(finding_id="hist-f2")
        assert len(history) == 1
        assert history[0].finding_id == "hist-f2"

    # ─────────────────── 统计 ───────────────────

    @pytest.mark.asyncio
    async def test_get_pr_stats_empty(self):
        stats = await self.service.get_pr_stats()
        assert stats.total_fixes == 0
        assert stats.pending_fixes == 0
        assert stats.avg_effort_minutes == 0.0

    @pytest.mark.asyncio
    async def test_get_pr_stats_after_operations(self):
        requests = [
            GenerateFixRequest(
                finding_id="stats-f1",
                rule_id="py.xss.dom",
                severity="HIGH",
                file_path="app.js",
                code_snippet="el.innerHTML = x",
            ),
        ]
        await self.service.generate_and_verify(requests, auto_verify=False)
        stats = await self.service.get_pr_stats()
        assert stats.total_fixes >= 1

    # ─────────────────── 自定义修改 ───────────────────

    @pytest.mark.asyncio
    async def test_customize_fix(self):
        requests = [
            GenerateFixRequest(
                finding_id="custom-f1",
                rule_id="py.injection.sql",
                severity="HIGH",
                file_path="app.py",
                code_snippet='cursor.execute("SELECT * FROM users WHERE id = " + uid)',
            ),
        ]
        await self.service.generate_and_preview(requests)

        custom_code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))'
        result = await self.service.customize_fix("custom-f1", custom_code)
        assert result is not None
        assert result["custom_code"] == custom_code
        assert "verification_status" in result

    @pytest.mark.asyncio
    async def test_customize_fix_not_found(self):
        result = await self.service.customize_fix("nonexistent", "code")
        assert result is None

    # ─────────────────── PR状态查询 ───────────────────

    @pytest.mark.asyncio
    async def test_get_pr_status_not_found(self):
        result = await self.service.get_pr_status("nonexistent-pr")
        assert result.get("status") == "not_found"

    @pytest.mark.asyncio
    async def test_list_prs_empty(self):
        prs = await self.service.list_prs()
        assert isinstance(prs, list)

    @pytest.mark.asyncio
    async def test_customize_fix_and_reverify(self):
        """测试自定义修改后重新验证"""
        requests = [
            GenerateFixRequest(
                finding_id="reverify-f1",
                rule_id="py.xss.dom",
                severity="HIGH",
                file_path="app.js",
                code_snippet="el.innerHTML = x",
            ),
        ]
        await self.service.generate_and_preview(requests)

        # 自定义修复代码
        custom_code = "el.textContent = x"
        result = await self.service.customize_fix(
            "reverify-f1", custom_code, original_code="el.innerHTML = x"
        )
        assert result is not None
        assert result["custom_code"] == custom_code

    @pytest.mark.asyncio
    async def test_generate_and_verify_no_auto_verify(self):
        """不自动验证时没有verification字段"""
        requests = [
            GenerateFixRequest(
                finding_id="noauto-f1",
                rule_id="py.xss.dom",
                severity="HIGH",
                file_path="app.js",
                code_snippet="el.innerHTML = x",
            ),
        ]
        results = await self.service.generate_and_verify(requests, auto_verify=False)
        assert "verification" not in results[0]

    @pytest.mark.asyncio
    async def test_history_with_limit(self):
        """测试历史记录limit"""
        for i in range(5):
            requests = [
                GenerateFixRequest(
                    finding_id=f"limit-{i}",
                    rule_id="py.xss.dom",
                    severity="HIGH",
                    file_path="app.js",
                    code_snippet="el.innerHTML = x",
                ),
            ]
            await self.service.generate_and_preview(requests)

        history = await self.service.get_fix_history(limit=3)
        assert len(history) == 3

    @pytest.mark.asyncio
    async def test_history_by_status(self):
        """测试按状态过滤历史"""
        requests = [
            GenerateFixRequest(
                finding_id="status-filter-1",
                rule_id="py.xss.dom",
                severity="HIGH",
                file_path="app.js",
                code_snippet="el.innerHTML = x",
            ),
        ]
        await self.service.generate_and_preview(requests)

        # Preview sets status to READY
        history = await self.service.get_fix_history(status="ready")
        assert len(history) >= 1

    @pytest.mark.asyncio
    async def test_submit_pr_skip_verification(self):
        """测试跳过验证提交PR"""
        requests = [
            GenerateFixRequest(
                finding_id="skip-verify-f1",
                rule_id="py.xss.dom",
                severity="HIGH",
                file_path="app.js",
                code_snippet="el.innerHTML = x",
            ),
        ]
        await self.service.generate_and_verify(requests, auto_verify=False)

        config = AutoPRConfig(provider="gitlab", project_id="test", dry_run=True)
        result = await self.service.submit_fix_pr(
            config=config,
            finding_ids=["skip-verify-f1"],
            skip_verification=True,
        )
        assert result.get("status") == "submitted"

    @pytest.mark.asyncio
    async def test_list_prs_with_status_filter(self):
        """测试按状态过滤PR列表"""
        prs = await self.service.list_prs(status_filter="open")
        assert isinstance(prs, list)

    @pytest.mark.asyncio
    async def test_get_pr_status_with_mock_pr(self):
        """测试获取已创建PR的状态"""
        self.service.pr_manager.create_pr_record(
            provider="gitlab",
            project_id="test",
            repository_url="",
            pr_id="test-pr-123",
            pr_title="Test PR",
        )
        status = await self.service.get_pr_status("test-pr-123")
        assert status.get("status") == "open"
