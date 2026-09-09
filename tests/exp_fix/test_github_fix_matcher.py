"""
Tests for fp_sentinel.reporting.github_fix_matcher module.
Target: >= 95% code coverage.
"""

import pytest
from unittest.mock import MagicMock

from fp_sentinel.reporting.github_fix_matcher import (
    CodeFix,
    TechFingerprint,
    GitHubFixMatcher,
    _FIX_CASE_LIBRARY,
    _FRAMEWORK_PATTERNS,
    _extract_vuln_category,
    detect_tech_fingerprint,
    generate_fix_suggestions,
    fix_to_markdown,
)


def _make_finding(
    rule_id="java-sql-injection",
    severity="CRITICAL",
    file_path="src/main/UserController.java",
    code_snippet="String sql = 'SELECT * FROM users WHERE id = ' + userId;",
):
    """Create a mock Finding."""
    f = MagicMock()
    f.rule_id = rule_id
    f.severity = severity
    f.file_path = file_path
    f.code_snippet = code_snippet
    f.category = "SQL_INJECTION"
    return f


# ─────────────────────── Case Library Tests ───────────────────────

class TestFixCaseLibrary:
    def test_library_not_empty(self):
        assert len(_FIX_CASE_LIBRARY) > 0

    def test_all_cases_have_required_fields(self):
        required = {"fix_id", "vuln_category", "tech_framework", "title", "severity",
                     "before_code", "after_code"}
        for case in _FIX_CASE_LIBRARY:
            for field in required:
                assert field in case, f"Case {case.get('fix_id', '?')} missing {field}"

    def test_categories_covered(self):
        cats = {c["vuln_category"] for c in _FIX_CASE_LIBRARY}
        assert "SQL_INJECTION" in cats
        assert "XSS" in cats
        assert "COMMAND_INJECTION" in cats
        assert "DESERIALIZATION" in cats

    def test_frameworks_covered(self):
        fws = {c["tech_framework"] for c in _FIX_CASE_LIBRARY}
        assert "spring-boot" in fws
        assert "django" in fws
        assert "express" in fws

    def test_before_after_differ(self):
        """Before and after code should be different."""
        for case in _FIX_CASE_LIBRARY:
            assert case["before_code"] != case["after_code"], \
                f"Case {case['fix_id']} has identical before/after"


# ─────────────────────── Framework Detection Tests ───────────────────────

class TestTechFingerprint:
    def test_detect_java_spring(self):
        findings = [_make_finding(rule_id="java-sql-injection")]
        fp = detect_tech_fingerprint(findings)
        assert fp.language == "java"
        assert fp.framework == "spring-boot"

    def test_detect_python_django(self):
        findings = [_make_finding(rule_id="python-sql-raw", file_path="views.py")]
        fp = detect_tech_fingerprint(findings)
        assert fp.language == "python"

    def test_detect_javascript_express(self):
        findings = [_make_finding(rule_id="node-xss-innerhtml", file_path="app.js")]
        fp = detect_tech_fingerprint(findings)
        assert fp.language == "javascript"

    def test_detect_php_laravel(self):
        findings = [_make_finding(rule_id="php-unserialize-user-input", file_path="Controller.php")]
        fp = detect_tech_fingerprint(findings)
        assert fp.language == "php"

    def test_detect_go(self):
        findings = [_make_finding(rule_id="go-sql-concat", file_path="handlers/user.go")]
        fp = detect_tech_fingerprint(findings)
        assert fp.language == "go"

    def test_empty_findings(self):
        fp = detect_tech_fingerprint([])
        assert fp.language == ""
        assert fp.framework == ""

    def test_detected_patterns(self):
        findings = [_make_finding(rule_id="java-jackson-json")]
        fp = detect_tech_fingerprint(findings)
        assert len(fp.detected_patterns) > 0


# ─────────────────────── Vulnerability Category Extraction ───────────────────────

class TestExtractVulnCategory:
    def test_explicit_category(self):
        f = MagicMock()
        f.category = "SQL_INJECTION"
        f.rule_id = "anything"
        assert _extract_vuln_category(f) == "SQL_INJECTION"

    def test_rule_id_sql(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "java-sql-injection"
        assert _extract_vuln_category(f) == "SQL_INJECTION"

    def test_rule_id_xss(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "reflected-xss"
        assert _extract_vuln_category(f) == "XSS"

    def test_rule_id_command(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "py-cmd-exec"
        assert _extract_vuln_category(f) == "COMMAND_INJECTION"

    def test_rule_id_command_os_system(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "python-os.system-injection"
        assert _extract_vuln_category(f) == "COMMAND_INJECTION"

    def test_rule_id_code_injection_eval(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "js-eval-exec"
        assert _extract_vuln_category(f) == "CODE_INJECTION"

    def test_rule_id_code_injection_function(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "js-function-constructor"
        assert _extract_vuln_category(f) == "CODE_INJECTION"

    def test_rule_id_path(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "path-traversal"
        assert _extract_vuln_category(f) == "PATH_TRAVERSAL"

    def test_rule_id_travers(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "file-traversal-read"
        assert _extract_vuln_category(f) == "PATH_TRAVERSAL"

    def test_rule_id_ssrf(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "http-ssrf-request"
        assert _extract_vuln_category(f) == "SSRF"

    def test_rule_id_deserialization(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "java-pickle-loads"
        result = _extract_vuln_category(f)
        assert "DESER" in result or "OTHER" in result

    def test_rule_id_hardcoded_secret(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "hardcoded-api-key"
        assert _extract_vuln_category(f) == "HARDCODED_SECRET"

    def test_rule_id_jwt(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "jwt-weak-key"
        assert _extract_vuln_category(f) == "JWT_BYPASS"

    def test_rule_id_redirect(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "open-redirect"
        assert _extract_vuln_category(f) == "OPEN_REDIRECT"

    def test_rule_id_crypto_md5(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "weak-hash-md5"
        assert _extract_vuln_category(f) == "CRYPTO_FAILURE"

    def test_rule_id_debug(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "debug-mode-enabled"
        assert _extract_vuln_category(f) == "DEBUG_MODE"

    def test_rule_id_xxe(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "xxe-xml-parsing"
        assert _extract_vuln_category(f) == "XXE"

    def test_rule_id_prototype(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "js-prototype-pollution"
        assert _extract_vuln_category(f) == "PROTOTYPE_POLLUTION"

    def test_rule_id_upload(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "file-upload-unsafe"
        assert _extract_vuln_category(f) == "FILE_UPLOAD"

    def test_unknown_category(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "custom-xyz-rule"
        assert _extract_vuln_category(f) == "OTHER"

    def test_category_precedence(self):
        """Explicit category takes precedence over rule_id inference."""
        f = MagicMock()
        f.category = "XSS"
        f.rule_id = "sql-injection-rule"
        assert _extract_vuln_category(f) == "XSS"

    def test_injection_sql_variant(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "injection.sql.raw"
        assert _extract_vuln_category(f) == "SQL_INJECTION"

    def test_unserialize_detection(self):
        f = MagicMock()
        f.category = ""
        f.rule_id = "php-unserialize-input"
        assert _extract_vuln_category(f) == "DESERIALIZATION"


# ─────────────────────── GitHub Fix Matcher Tests ───────────────────────

class TestGitHubFixMatcher:
    def test_init(self):
        matcher = GitHubFixMatcher()
        assert matcher._library is not None
        assert matcher._index is not None

    def test_custom_library(self):
        custom = [{"fix_id": "C1", "vuln_category": "SQL_INJECTION", "tech_framework": "django",
                   "title": "t", "severity": "HIGH", "before_code": "a", "after_code": "b"}]
        matcher = GitHubFixMatcher(custom)
        assert matcher.get_library_stats()["total_cases"] == 1

    def test_match_sql_injection_spring(self):
        finding = _make_finding(rule_id="java-sql-injection")
        fp = TechFingerprint(language="java", framework="spring-boot")
        matcher = GitHubFixMatcher()
        results = matcher.match_fixes([finding], fp)
        assert len(results) > 0
        # First match should be the SQL injection fix
        assert results[0].vuln_category == "SQL_INJECTION"

    def test_match_xss_express(self):
        finding = _make_finding(rule_id="reflected-xss", file_path="routes/comment.js")
        fp = TechFingerprint(language="javascript", framework="express")
        matcher = GitHubFixMatcher()
        results = matcher.match_fixes([finding], fp)
        assert len(results) > 0
        assert any(r.vuln_category == "XSS" for r in results)

    def test_match_empty_findings(self):
        matcher = GitHubFixMatcher()
        results = matcher.match_fixes([])
        assert results == []

    def test_match_with_max_results(self):
        finding = _make_finding()
        matcher = GitHubFixMatcher()
        results = matcher.match_fixes([finding], max_results=3)
        assert len(results) <= 3

    def test_confidence_score_valid(self):
        finding = _make_finding(rule_id="java-sql-injection")
        fp = TechFingerprint(language="java", framework="spring-boot")
        matcher = GitHubFixMatcher()
        results = matcher.match_fixes([finding], fp)
        for r in results:
            assert 0 <= r.confidence <= 1

    def test_results_sorted_by_confidence(self):
        finding = _make_finding(rule_id="java-sql-injection")
        fp = TechFingerprint(language="java", framework="spring-boot")
        matcher = GitHubFixMatcher()
        results = matcher.match_fixes([finding], fp)
        if len(results) > 1:
            for i in range(len(results) - 1):
                assert results[i].confidence >= results[i + 1].confidence

    def test_fix_has_required_fields(self):
        finding = _make_finding()
        fp = TechFingerprint(language="java", framework="spring-boot")
        matcher = GitHubFixMatcher()
        results = matcher.match_fixes([finding], fp)
        if results:
            fix = results[0]
            assert fix.fix_id
            assert fix.title
            assert fix.before_code
            assert fix.after_code
            assert fix.confidence > 0

    def test_pr_template_generated(self):
        finding = _make_finding()
        fp = TechFingerprint(language="java", framework="spring-boot")
        matcher = GitHubFixMatcher()
        results = matcher.match_fixes([finding], fp)
        if results:
            assert results[0].pr_template
            assert "CVE" in results[0].pr_template

    def test_no_duplicates(self):
        finding = _make_finding()
        fp = TechFingerprint(language="java", framework="spring-boot")
        matcher = GitHubFixMatcher()
        results = matcher.match_fixes([finding], fp)
        fix_ids = [r.fix_id for r in results]
        assert len(fix_ids) == len(set(fix_ids))

    def test_auto_detect_fingerprint(self):
        finding = _make_finding(rule_id="java-sql-injection")
        matcher = GitHubFixMatcher()
        # No fingerprint provided - should auto-detect
        results = matcher.match_fixes([finding])
        assert len(results) > 0

    def test_fix_with_snippet_uses_actual_code(self):
        custom_lib = [{
            "fix_id": "TEST-001",
            "vuln_category": "SQL_INJECTION",
            "tech_framework": "spring-boot",
            "title": "Test Fix",
            "severity": "CRITICAL",
            "description": "Test",
            "before_code": "generic before",
            "after_code": "generic after",
        }]
        finding = _make_finding(
            rule_id="java-sql-injection",
            code_snippet="String q = 'SELECT * FROM t WHERE id=' + input;"
        )
        fp = TechFingerprint(language="java", framework="spring-boot")
        matcher = GitHubFixMatcher(custom_lib)
        results = matcher.match_fixes([finding], fp)
        if results:
            # Should use actual code snippet as before
            assert results[0].before_code == "String q = 'SELECT * FROM t WHERE id=' + input;"


# ─────────────────────── Convenience Functions Tests ───────────────────────

class TestConvenienceFunctions:
    def test_generate_fix_suggestions(self):
        findings = [_make_finding()]
        results = generate_fix_suggestions(findings)
        assert isinstance(results, list)

    def test_generate_fix_suggestions_empty(self):
        results = generate_fix_suggestions([])
        assert results == []

    def test_fix_to_markdown(self):
        fix = CodeFix(
            fix_id="test-fix-001",
            vuln_category="SQL_INJECTION",
            tech_framework="spring-boot",
            title="Fix SQL Injection",
            severity="CRITICAL",
            description="Use parameterized queries",
            before_code="String q = 'SELECT *' + input",
            after_code="String q = 'SELECT *'",
            reference_cve="CVE-2022-22965",
        )
        md = fix_to_markdown(fix)
        assert "SQL_INJECTION" in md
        assert "Fix SQL Injection" in md
        assert "CVE-2022-22965" in md
        assert "修复前" in md
        assert "修复后" in md

    def test_fix_to_markdown_with_test(self):
        fix = CodeFix(
            fix_id="test-fix-002",
            vuln_category="XSS",
            tech_framework="express",
            title="Fix XSS",
            severity="HIGH",
            description="Sanitize",
            before_code="<div>${userInput}</div>",
            after_code="<div>${sanitize(userInput)}</div>",
            test_code="test('xss', () => { expect(sanitize('<script>')).toBe(''); })",
        )
        md = fix_to_markdown(fix)
        assert "验证测试" in md


# ─────────────────────── Library Stats Tests ───────────────────────

class TestLibraryStats:
    def test_stats_format(self):
        matcher = GitHubFixMatcher()
        stats = matcher.get_library_stats()
        assert "total_cases" in stats
        assert "categories" in stats
        assert "frameworks" in stats
        assert stats["total_cases"] > 0

    def test_stats_accuracy(self):
        matcher = GitHubFixMatcher()
        stats = matcher.get_library_stats()
        assert stats["total_cases"] == len(_FIX_CASE_LIBRARY)


# ─────────────────────── Framework Patterns Tests ───────────────────────

class TestFrameworkPatterns:
    def test_all_patterns_have_indicators(self):
        for fw, info in _FRAMEWORK_PATTERNS.items():
            assert "indicators" in info
            assert len(info["indicators"]) > 0
            assert "language" in info

    def test_pattern_prefix_format(self):
        for fw, info in _FRAMEWORK_PATTERNS.items():
            prefixes = info.get("rule_prefixes", [])
            assert len(prefixes) > 0
            for p in prefixes:
                assert isinstance(p, str) and len(p) > 0
