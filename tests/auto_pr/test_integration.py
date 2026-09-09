"""
集成测试：完整工作流端到端测试

测试从修复生成到验证到PR提交的完整流程。
使用 dry_run 模式避免真实API调用。
"""

import pytest
from fp_sentinel.auto_pr.auto_fix_generator import AutoFixGenerator
from fp_sentinel.auto_pr.fix_validator import FixValidator
from fp_sentinel.auto_pr.pr_manager import PRManager
from fp_sentinel.auto_pr.service import AutoPRService
from fp_sentinel.auto_pr.models import (
    AutoPRConfig,
    FixStatus,
    GenerateFixRequest,
    VerificationStatus,
    VulnerabilityType,
)


class TestEndToEndWorkflow:
    """端到端工作流测试"""

    def test_full_workflow_sql_injection(self):
        """SQL注入修复完整工作流"""
        # 1. 生成修复预览
        service = AutoPRService()
        requests = [
            GenerateFixRequest(
                finding_id="e2e-sql-001",
                rule_id="python.lang.security.injection.sql-injection",
                severity="CRITICAL",
                file_path="src/api/users.py",
                code_snippet='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
                message="SQL Injection via string concatenation",
                language="python",
                cwe="CWE-89",
            ),
        ]

        import asyncio
        previews = asyncio.run(service.generate_and_preview(requests))
        assert len(previews) == 1
        assert previews[0]["vuln_type"] == "sql_injection"
        assert "unified_diff" in previews[0]

        # 2. 跳过验证提交PR (dry_run)
        config = AutoPRConfig(
            provider="gitlab",
            project_id="test-project",
            dry_run=True,
        )
        pr_result = asyncio.run(service.submit_fix_pr(
            config=config,
            finding_ids=["e2e-sql-001"],
            title="[玄鉴] 修复 SQL 注入",
            skip_verification=True,
        ))
        assert pr_result.get("status") in ("submitted", "error")

    def test_full_workflow_xss(self):
        """XSS修复完整工作流"""
        service = AutoPRService()
        requests = [
            GenerateFixRequest(
                finding_id="e2e-xss-001",
                rule_id="py.xss.dom.innerHTML",
                severity="HIGH",
                file_path="src/templates/profile.js",
                code_snippet="element.innerHTML = userData.bio",
                message="DOM XSS via innerHTML",
                language="javascript",
                cwe="CWE-79",
            ),
        ]

        previews = __import__("asyncio").run(service.generate_and_preview(requests))
        assert previews[0]["vuln_type"] == "xss"

        results = __import__("asyncio").run(service.generate_and_verify(requests, auto_verify=True))
        assert results[0]["vuln_type"] == "xss"

    def test_full_workflow_command_injection(self):
        """命令注入修复完整工作流"""
        service = AutoPRService()
        requests = [
            GenerateFixRequest(
                finding_id="e2e-cmd-001",
                rule_id="py.command.injection",
                severity="CRITICAL",
                file_path="src/utils/helpers.py",
                code_snippet="os.system('ping ' + hostname)",
                message="Command Injection via os.system",
                language="python",
                cwe="CWE-78",
            ),
        ]
        previews = __import__("asyncio").run(service.generate_and_preview(requests))
        assert previews[0]["vuln_type"] == "command_injection"

        original_codes = {"e2e-cmd-001": "os.system('ping ' + hostname)"}
        results = __import__("asyncio").run(service.generate_and_verify(
            requests, original_codes=original_codes
        ))
        assert results[0]["verification"]["original_vuln_resolved"] is True

    def test_custom_code_workflow(self):
        """自定义修复代码工作流"""
        service = AutoPRService()
        requests = [
            GenerateFixRequest(
                finding_id="e2e-custom-001",
                rule_id="py.xss.dom",
                severity="HIGH",
                file_path="app.js",
                code_snippet="el.innerHTML = x",
            ),
        ]
        __import__("asyncio").run(service.generate_and_preview(requests))

        # 提供自定义修复代码
        custom_codes = {
            "e2e-custom-001": "el.textContent = x"
        }
        original_codes = {"e2e-custom-001": "el.innerHTML = x"}
        results = __import__("asyncio").run(service.generate_and_verify(
            requests, custom_codes=custom_codes, original_codes=original_codes
        ))
        assert results[0]["verification"]["original_vuln_resolved"] is True

    def test_batch_multi_vuln_workflow(self):
        """多漏洞批量修复工作流"""
        service = AutoPRService()
        requests = [
            GenerateFixRequest(
                finding_id="e2e-batch-sql",
                rule_id="py.injection.sql",
                severity="HIGH",
                file_path="app.py",
                code_snippet="bad_sql",
            ),
            GenerateFixRequest(
                finding_id="e2e-batch-xss",
                rule_id="py.xss.dom",
                severity="MEDIUM",
                file_path="app.js",
                code_snippet="bad_xss",
            ),
            GenerateFixRequest(
                finding_id="e2e-batch-cmd",
                rule_id="py.command.injection",
                severity="CRITICAL",
                file_path="utils.py",
                code_snippet="bad_cmd",
            ),
        ]
        previews = __import__("asyncio").run(service.generate_and_preview(requests))
        assert len(previews) == 3

        results = __import__("asyncio").run(service.generate_and_verify(requests, auto_verify=True))
        assert len(results) == 3

    def test_stats_after_workflow(self):
        """工作流完成后统计信息"""
        service = AutoPRService()
        requests = [
            GenerateFixRequest(
                finding_id="e2e-stats-001",
                rule_id="py.xss.dom",
                severity="HIGH",
                file_path="app.js",
                code_snippet="el.innerHTML = x",
            ),
        ]
        __import__("asyncio").run(service.generate_and_verify(requests, auto_verify=False))

        stats = __import__("asyncio").run(service.get_pr_stats())
        assert stats.total_fixes >= 1
        assert stats.generated_at is not None

    def test_history_after_workflow(self):
        """工作流完成后历史记录"""
        service = AutoPRService()
        requests = [
            GenerateFixRequest(
                finding_id="e2e-hist-001",
                rule_id="py.injection.sql",
                severity="HIGH",
                file_path="app.py",
                code_snippet="bad code",
            ),
        ]
        __import__("asyncio").run(service.generate_and_preview(requests))

        history = __import__("asyncio").run(service.get_fix_history())
        assert len(history) >= 1
        assert any(h.finding_id == "e2e-hist-001" for h in history)

    def test_rejected_verification_workflow(self):
        """验证失败的工作流"""
        validator = FixValidator()
        from fp_sentinel.auto_pr.models import VerifyFixRequest

        request = VerifyFixRequest(
            patch_id="bad-patch",
            finding_id="bad-f1",
            original_code="os.system(cmd)",
            fixed_code="os.system(cmd)",  # same as original = not fixed
            rule_id="py.os.system",
            vuln_type=VulnerabilityType.OS_COMMAND,
        )
        result = validator.verify_fix(request)
        assert result.status == VerificationStatus.FAIL
        assert result.original_vuln_resolved is False
