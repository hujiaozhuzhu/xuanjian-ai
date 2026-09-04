"""
A6-1. Diff 修复建议测试（S2：绝不修改用户源文件）
"""

import os

from fp_sentinel.models import Finding, Severity
from fp_sentinel.reporting.fix_advisor import (
    FixSuggestion,
    covered_categories,
    suggest_fix,
)


def _f(rule_id, code, file_path="app.py"):
    return Finding(
        scanner="python_scanner",
        rule_id=rule_id,
        severity=Severity.HIGH,
        file_path=file_path,
        line_start=10,
        code_snippet=code,
    )


class TestRuleCoverage:
    def test_at_least_15_categories(self):
        """高频 15 类规则映射齐全"""
        assert covered_categories() >= 15

    def test_sqli_suggestion(self):
        sug = suggest_fix(_f("py.injection.sql", 'q = "SELECT " + user_id'))
        assert isinstance(sug, FixSuggestion)
        assert "参数化" in sug.diff or "execute" in sug.diff
        assert sug.reference_cve.startswith("CVE-")
        assert sug.effort_minutes > 0

    def test_yaml_suggestion(self):
        sug = suggest_fix(_f("py.deserialization.yaml", "yaml.load(data)"))
        assert "safe_load" in sug.diff

    def test_pickle_suggestion(self):
        sug = suggest_fix(_f("py.deserialization.pickle", "pickle.loads(data)"))
        assert "json.loads" in sug.diff

    def test_md5_suggestion(self):
        sug = suggest_fix(_f("py.crypto.weak_hash", "hashlib.md5(x)"))
        assert "bcrypt" in sug.diff

    def test_jwt_suggestion(self):
        sug = suggest_fix(_f("js.node.jwt-weak", "jwt.sign(payload, JWT_SECRET)"))
        assert "process.env.JWT_SECRET" in sug.diff

    def test_hardcoded_secret(self):
        sug = suggest_fix(_f("py.crypto.hardcoded_key", 'SECRET_KEY = "abc123"'))
        assert "os.environ" in sug.diff

    def test_generic_fallback(self):
        """未映射规则回退通用建议"""
        sug = suggest_fix(_f("some.unknown.rule", "weird_code()"))
        assert sug.generic is True
        assert "some.unknown.rule" in sug.diff


class TestDiffFormat:
    def test_diff_structure(self):
        sug = suggest_fix(_f("py.injection.sql", 'q = "SELECT " + user_id'))
        lines = sug.diff.splitlines()
        assert any(l.startswith("--- a/") for l in lines)
        assert any(l.startswith("+") for l in lines)

    def test_diff_is_string_not_file(self, tmp_path):
        """S2：建议是 diff 字符串，不触碰源文件"""
        src = tmp_path / "app.py"
        src.write_text('q = "SELECT " + user_id\n', encoding="utf-8")
        before = src.read_text(encoding="utf-8")
        sug = suggest_fix(_f("py.injection.sql", src.read_text(encoding="utf-8")))
        assert isinstance(sug.diff, str)
        assert src.read_text(encoding="utf-8") == before

    def test_incident_note_present(self):
        sug = suggest_fix(_f("py.injection.command", "os.system(cmd)"))
        assert sug.incident_note

    def test_xss_suggestion(self):
        sug = suggest_fix(_f("js.xss.innerhtml", "el.innerHTML = userInput"))
        assert "textContent" in sug.diff or "DOMPurify" in sug.diff

    def test_ssrf_suggestion(self):
        sug = suggest_fix(_f("js.node.ssrf", "axios.get(url)"))
        assert "ALLOWED" in sug.diff or "白名单" in sug.incident_note

    def test_debug_mode(self):
        sug = suggest_fix(_f("py.auth.debug_mode", "app.run(debug=True)"))
        assert "debug=False" in sug.diff

    def test_open_redirect(self):
        sug = suggest_fix(_f("js.node.open-redirect", "res.redirect(url)"))
        assert sug.effort_minutes > 0
