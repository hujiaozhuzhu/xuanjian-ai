"""
自动修复代码生成器测试
覆盖：规则匹配、Diff生成、自定义修改、批量生成、所有VulnerabilityType
"""

import pytest
from fp_sentinel.auto_pr.auto_fix_generator import (
    AutoFixGenerator,
    _match_vuln_type,
    _extract_bad_lines,
    _build_unified_diff,
    generate_fix_preview,
)
from fp_sentinel.auto_pr.models import (
    FixPatch,
    FixPreview,
    GenerateFixRequest,
    VulnerabilityType,
)


# ─────────────────────── 规则匹配测试 ───────────────────────

class TestVulnTypeMatching:
    """测试 rule_id -> VulnerabilityType 映射"""

    def test_sql_injection(self):
        assert _match_vuln_type("python.lang.security.injection.sql-injection") == VulnerabilityType.SQL_INJECTION
        assert _match_vuln_type("semgrep.sqli") == VulnerabilityType.SQL_INJECTION

    def test_xss(self):
        assert _match_vuln_type("py.xss.dom") == VulnerabilityType.XSS
        assert _match_vuln_type("javascript.browser.security.xss") == VulnerabilityType.XSS

    def test_command_injection(self):
        assert _match_vuln_type("py.command.injection") == VulnerabilityType.COMMAND_INJECTION
        assert _match_vuln_type("python.lang.security.injection.command-injection") == VulnerabilityType.COMMAND_INJECTION

    def test_os_command(self):
        assert _match_vuln_type("py.os.system") == VulnerabilityType.OS_COMMAND
        assert _match_vuln_type("python.lang.security.dangerous-os-system") == VulnerabilityType.OS_COMMAND

    def test_path_traversal(self):
        assert _match_vuln_type("py.path.traversal") == VulnerabilityType.PATH_TRAVERSAL

    def test_hardcoded_secret(self):
        assert _match_vuln_type("py.hardcoded.credential") == VulnerabilityType.HARDCODED_SECRET

    def test_jwt_weak(self):
        assert _match_vuln_type("py.jwt.weak") == VulnerabilityType.JWT_WEAK

    def test_yaml_unsafe(self):
        assert _match_vuln_type("py.yaml.load") == VulnerabilityType.YAML_UNSAFE

    def test_pickle_deserialize(self):
        assert _match_vuln_type("py.pickle.loads") == VulnerabilityType.PICKLE_DESERIALIZE

    def test_eval_injection(self):
        assert _match_vuln_type("py.eval.injection") == VulnerabilityType.EVAL_INJECTION

    def test_ssrf(self):
        assert _match_vuln_type("py.ssrf") == VulnerabilityType.SSRF

    def test_weak_hash(self):
        assert _match_vuln_type("py.weak.hash.md5") == VulnerabilityType.WEAK_HASH

    def test_ecb_mode(self):
        assert _match_vuln_type("py.ecb.mode") == VulnerabilityType.ECB_MODE

    def test_debug_exposure(self):
        assert _match_vuln_type("py.debug.exposure") == VulnerabilityType.DEBUG_EXPOSURE

    def test_open_redirect(self):
        assert _match_vuln_type("py.open.redirect") == VulnerabilityType.OPEN_REDIRECT

    def test_generic_fallback(self):
        assert _match_vuln_type("unknown.rule.id") == VulnerabilityType.GENERIC
        assert _match_vuln_type("") == VulnerabilityType.GENERIC


# ─────────────────────── 提取坏行测试 ───────────────────────

class TestExtractBadLines:
    def test_basic(self):
        code = "import os\nos.system('ls')\nprint('hello')"
        lines = _extract_bad_lines(code, ["os.system("])
        assert any("os.system" in l for l in lines)

    def test_empty_code(self):
        assert _extract_bad_lines("", ["test"]) == []

    def test_no_match(self):
        code = "print('hello')\nreturn True"
        lines = _extract_bad_lines(code, ["os.system("])
        # 无匹配时返回第一行
        assert len(lines) > 0

    def test_empty_lines_skipped(self):
        code = "\n\nprint('hello')\n\n"
        lines = _extract_bad_lines(code, ["print"])
        assert all(l.strip() for l in lines)


# ─────────────────────── Diff构建测试 ───────────────────────

class TestBuildUnifiedDiff:
    def test_basic(self):
        diff = _build_unified_diff("app.py", ["os.system('ls')"], "subprocess.run(['ls'])")
        assert "--- a/app.py" in diff
        assert "+++ b/app.py" in diff
        assert "-os.system('ls')" in diff
        assert "+subprocess.run(['ls'])" in diff

    def test_empty_bad_lines(self):
        diff = _build_unified_diff("test.py", [], "fix code")
        assert "--- a/test.py" in diff


# ─────────────────────── 生成器测试 ───────────────────────

class TestAutoFixGenerator:
    def test_generate_preview_sql_injection(self):
        gen = AutoFixGenerator()
        request = GenerateFixRequest(
            finding_id="test-001",
            rule_id="python.lang.security.injection.sql-injection",
            severity="HIGH",
            file_path="app.py",
            code_snippet='query = "SELECT * FROM users WHERE id = " + user_id\ncursor.execute(query)',
            message="SQL Injection",
            language="python",
            cwe="CWE-89",
        )
        preview = gen.generate_fix_preview(request)
        assert preview.vuln_type == VulnerabilityType.SQL_INJECTION
        assert "SQL" in preview.title
        assert preview.effort_minutes > 0
        assert preview.can_customize is True
        assert preview.finding_id == "test-001"
        assert preview.unified_diff is not None and len(preview.unified_diff) > 0

    def test_generate_preview_xss(self):
        gen = AutoFixGenerator()
        request = GenerateFixRequest(
            finding_id="test-002",
            rule_id="py.xss.dom",
            severity="HIGH",
            file_path="app.js",
            code_snippet="el.innerHTML = userInput",
            message="XSS vulnerability",
        )
        preview = gen.generate_fix_preview(request)
        assert preview.vuln_type == VulnerabilityType.XSS
        assert "XSS" in preview.title

    def test_generate_preview_command_injection(self):
        gen = AutoFixGenerator()
        request = GenerateFixRequest(
            finding_id="test-003",
            rule_id="py.command.injection",
            severity="CRITICAL",
            file_path="app.py",
            code_snippet="os.system(user_input)",
            message="Command Injection",
        )
        preview = gen.generate_fix_preview(request)
        assert preview.vuln_type == VulnerabilityType.COMMAND_INJECTION

    def test_generate_preview_generic_fallback(self):
        gen = AutoFixGenerator()
        request = GenerateFixRequest(
            finding_id="test-004",
            rule_id="some.unknown.rule",
            severity="MEDIUM",
            file_path="app.py",
            code_snippet="suspicious_code()",
            message="Unknown issue",
        )
        preview = gen.generate_fix_preview(request)
        assert preview.vuln_type == VulnerabilityType.GENERIC
        assert preview.reference_cve == ""

    def test_generate_patch(self):
        gen = AutoFixGenerator()
        request = GenerateFixRequest(
            finding_id="test-005",
            rule_id="py.injection.sql",
            severity="HIGH",
            file_path="app.py",
            code_snippet='cursor.execute("SELECT * FROM users WHERE id = " + uid)',
        )
        patch = gen.generate_patch(request)
        assert isinstance(patch, FixPatch)
        assert patch.finding_id == "test-005"
        assert patch.vuln_type == VulnerabilityType.SQL_INJECTION
        assert len(patch.diffs) > 0
        assert patch.effort_minutes > 0

    def test_generate_patch_with_custom_code(self):
        gen = AutoFixGenerator()
        request = GenerateFixRequest(
            finding_id="test-006",
            rule_id="py.injection.sql",
            severity="HIGH",
            file_path="app.py",
            code_snippet="cursor.execute(f'SELECT * FROM t WHERE id = {uid}')",
        )
        custom = "cursor.execute('SELECT * FROM t WHERE id = %s', [uid])"
        patch = gen.generate_patch(request, custom_fix_code=custom)
        assert patch.diffs[0].fixed_code == custom
        assert "fixed_code" in patch.custom_modifications

    def test_customize_patch(self):
        gen = AutoFixGenerator()
        request = GenerateFixRequest(
            finding_id="test-007",
            rule_id="py.injection.sql",
            severity="HIGH",
            file_path="app.py",
            code_snippet="SELECT * FROM users WHERE id = " + "uid",
        )
        patch = gen.generate_patch(request)
        new_code = "cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))"
        result = gen.customize_patch(patch.id, new_code)
        assert result is not None
        assert result.diffs[0].fixed_code == new_code

    def test_customize_nonexistent_patch(self):
        gen = AutoFixGenerator()
        result = gen.customize_patch("nonexistent-id", "fix code")
        assert result is None

    def test_get_patch(self):
        gen = AutoFixGenerator()
        request = GenerateFixRequest(
            finding_id="test-008",
            rule_id="py.injection.sql",
            severity="HIGH",
            file_path="app.py",
            code_snippet="os.system(cmd)",
        )
        patch = gen.generate_patch(request)
        assert gen.get_patch(patch.id) is not None
        assert gen.get_patch("nonexistent") is None

    def test_batch_generate_previews(self):
        gen = AutoFixGenerator()
        requests = [
            GenerateFixRequest(finding_id=f"batch-{i}", rule_id=f"py.rule.{i}", severity="HIGH",
                             file_path="app.py", code_snippet="test")
            for i in range(5)
        ]
        previews = gen.batch_generate_previews(requests)
        assert len(previews) == 5
        assert all(isinstance(p, FixPreview) for p in previews)

    def test_batch_generate_patches(self):
        gen = AutoFixGenerator()
        requests = [
            GenerateFixRequest(finding_id=f"batch-p-{i}", rule_id="py.injection.sql", severity="HIGH",
                             file_path="app.py", code_snippet="test")
            for i in range(3)
        ]
        patches = gen.batch_generate_patches(requests)
        assert len(patches) == 3
        assert all(isinstance(p, FixPatch) for p in patches)


# ─────────────────────── 便捷函数测试 ───────────────────────

class TestGenerateFixPreview:
    def test_convenience_function(self):
        preview = generate_fix_preview(
            finding_id="conv-001",
            rule_id="py.injection.sql",
            severity="HIGH",
            file_path="app.py",
            code_snippet='cursor.execute("SELECT * FROM t WHERE id = " + uid)',
            message="SQL Injection",
            language="python",
            cwe="CWE-89",
        )
        assert preview.vuln_type == VulnerabilityType.SQL_INJECTION
        assert preview.finding_id == "conv-001"

    def test_convenience_function_xss(self):
        preview = generate_fix_preview(
            finding_id="conv-002",
            rule_id="py.xss.dom",
            severity="MEDIUM",
            file_path="app.js",
            code_snippet="el.innerHTML = userInput",
            message="XSS",
        )
        assert preview.vuln_type == VulnerabilityType.XSS

    def test_convenience_function_generic(self):
        preview = generate_fix_preview(
            finding_id="conv-003",
            rule_id="custom.rule",
            severity="LOW",
            file_path="test.py",
            code_snippet="some_code()",
        )
        assert preview.vuln_type == VulnerabilityType.GENERIC
