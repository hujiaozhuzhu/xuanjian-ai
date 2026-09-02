"""
玄鉴 v2.1.0 Phase A-JS 规则修复测试

覆盖:
- A1: 全部 JS 规则可编译守护（防坏正则回归）
- A2: 扫描器 per-rule 容错（坏正则不殃及其他规则）
- A3: 上下文窗口 guard 抑制机制
- A4: Node 规则正则形态（变量传递）命中
- A5: JS 靶场闭环（vulnerability 全检出 + safe 零误报）
"""

import asyncio
import json
from pathlib import Path

import pytest

from fp_sentinel.rules.js import (
    JS_FALSE_POSITIVE_RULES,
    JS_SECURITY_GUARD_PATTERNS,
    JS_SECURITY_RULES,
)
from fp_sentinel.rules.js.rules import CustomRule
from fp_sentinel.scanners import js_scanner as js_scanner_module
from fp_sentinel.scanners.js_scanner import JSScanner

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PLAYGROUND_DIR = PROJECT_ROOT / "playground" / "js-vuln-app"
EXPECTED_FILE = PLAYGROUND_DIR / "expected-findings.json"


def _run_scan(target):
    scanner = JSScanner(config={"check_dependencies": False})
    return asyncio.run(scanner.scan(str(target)))


# ─────────────────────── A1: 规则编译守护 ───────────────────────

class TestAllRulesCompile:
    """守护测试：所有 JS 规则正则必须可编译（防止 [sk-ant-] 类坏正则回归）"""

    def test_all_js_rules_compile(self):
        import re
        for rule in JS_SECURITY_RULES:
            if rule.code_pattern:
                try:
                    re.compile(rule.code_pattern)
                except re.error as e:
                    pytest.fail(f"{rule.rule_id} 正则非法: {rule.code_pattern!r} ({e})")

    def test_all_false_positive_rules_compile(self):
        for rule in JS_FALSE_POSITIVE_RULES:
            if rule.code_pattern:
                import re
                re.compile(rule.code_pattern)

    def test_all_guard_patterns_compile(self):
        import re
        for group, patterns in JS_SECURITY_GUARD_PATTERNS.items():
            for p in patterns:
                try:
                    re.compile(p)
                except re.error as e:
                    pytest.fail(f"guard 组 {group} 存在非法正则: {p!r} ({e})")

    def test_llm_api_key_rule_fixed(self):
        """v2.1.0 修复点：js.aigc.llm-api-key-exposure 不再含 [sk-ant-] 坏字符类"""
        rule = next(r for r in JS_SECURITY_RULES if r.rule_id == "js.aigc.llm-api-key-exposure")
        assert "[sk-ant-]" not in rule.code_pattern
        import re
        pattern = re.compile(rule.code_pattern, re.IGNORECASE)
        assert pattern.search('OPENAI_API_KEY = "sk-abc123def456ghi789"')
        assert pattern.search('ANTHROPIC_API_KEY = "sk-ant-abc123"')


# ─────────────────────── A2: per-rule 容错 ───────────────────────

class TestPerRuleFaultTolerance:
    """坏规则只跳过自身，不中断同文件其他规则"""

    def test_bad_regex_does_not_break_other_rules(self, tmp_path, monkeypatch):
        bad_rule = CustomRule(
            rule_id="js.test.bad-regex",
            description="坏正则规则",
            code_pattern=r"[sk-ant-]",  # 非法字符类
            category="SECRETS",
        )
        good_rule = CustomRule(
            rule_id="js.test.good-rule",
            description="正常规则",
            code_pattern=r"eval\s*\(",
            category="INJECTION",
        )
        monkeypatch.setattr(js_scanner_module, "JS_SECURITY_RULES", [bad_rule, good_rule])

        target = tmp_path / "vuln.js"
        target.write_text("const r = eval(userInput);\n", encoding="utf-8")

        results = _run_scan(target)
        rule_ids = {r.rule_id for r in results}
        assert "js.test.good-rule" in rule_ids, "坏正则不应影响后续规则检出"
        assert "js.test.bad-regex" not in rule_ids

    def test_multiple_bad_rules_all_skipped(self, tmp_path, monkeypatch):
        rules = [
            CustomRule(rule_id=f"js.test.bad-{i}", description="bad",
                       code_pattern=r"[k-a]", category="SECRETS")
            for i in range(3)
        ]
        rules.append(CustomRule(
            rule_id="js.test.survivor", description="good",
            code_pattern=r"document\.cookie\s*=", category="UNSAFE",
        ))
        monkeypatch.setattr(js_scanner_module, "JS_SECURITY_RULES", rules)

        target = tmp_path / "vuln.js"
        target.write_text("document.cookie = token;\n", encoding="utf-8")

        results = _run_scan(target)
        assert any(r.rule_id == "js.test.survivor" for r in results)

    def test_compile_cache_reused(self):
        """compile 缓存：同一 pattern 第二次获取走缓存"""
        from fp_sentinel.scanners.js_scanner import _RULE_COMPILE_CACHE
        pattern = r"eval\s*\("
        first = JSScanner._compile_rule_pattern(pattern)
        second = JSScanner._compile_rule_pattern(pattern)
        assert _RULE_COMPILE_CACHE.get(pattern) is first
        assert second is first


# ─────────────────────── A3: 上下文窗口 guard ───────────────────────

class TestGuardWindow:
    """命中行前后 6 行窗口内出现对应 category 的 guard 模式则抑制"""

    def setup_method(self):
        self.scanner = JSScanner()

    def _lines_with_guard_at(self, guard_line: int, total: int = 30):
        lines = ["// filler line"] * total
        lines[9] = "exec(cmd, (error, stdout, stderr) => {"
        lines[guard_line] = "const allowed = ['ls', 'pwd'];"
        return lines

    def test_guard_within_window_suppresses(self):
        lines = self._lines_with_guard_at(guard_line=13)  # 命中行 idx=9，±6 窗口内
        assert self.scanner._suppressed_by_guard(lines, 9, "INJECTION") is True

    def test_guard_outside_window_does_not_suppress(self):
        lines = self._lines_with_guard_at(guard_line=17)  # 距命中行 8 行 > 6
        assert self.scanner._suppressed_by_guard(lines, 9, "INJECTION") is False

    def test_no_guard_at_all(self):
        lines = self._lines_with_guard_at(guard_line=25)
        assert self.scanner._suppressed_by_guard(lines, 9, "INJECTION") is False

    def test_category_without_mapping(self):
        lines = ["const allowed = 'x';"] * 10
        assert self.scanner._suppressed_by_guard(lines, 5, "XSS") is False
        assert self.scanner._suppressed_by_guard(lines, 5, None) is False

    def test_ssrf_guard_group(self):
        lines = ["// filler"] * 20
        lines[11] = "const response = await axios.get(url);"
        lines[14] = "if (!allowed.some(a => url.startsWith(a))) {"
        assert self.scanner._suppressed_by_guard(lines, 11, "SSRF") is True

    def test_sql_injection_guard_group(self):
        lines = ["// filler"] * 20
        lines[11] = 'const sql = "SELECT * FROM users WHERE id = " + userId;'
        lines[13] = "db.execute(sql, [userId]);  // parameterized"
        assert self.scanner._suppressed_by_guard(lines, 11, "SQL_INJECTION") is True

    def test_path_traversal_guard_group(self):
        lines = ["// filler"] * 20
        lines[11] = "const filepath = path.join(baseDir, filename);"
        lines[13] = "const normalized = path.resolve(filepath);"
        assert self.scanner._suppressed_by_guard(lines, 11, "PATH_TRAVERSAL") is True


# ─────────────────────── A4: Node 规则形态命中 ───────────────────────

class TestNodeRulePatterns:
    """变量传递形态：exec(cmd,)/axios.get(url)/path.join(..., filename)"""

    def _rule(self, rule_id):
        return next(r for r in JS_SECURITY_RULES if r.rule_id == rule_id)

    def _match(self, rule_id, line):
        import re
        return re.search(self._rule(rule_id).code_pattern, line, re.IGNORECASE)

    def test_command_injection_variable_form(self):
        assert self._match("js.node.command-injection", "exec(cmd, (error, stdout) => {")
        assert self._match("js.node.command-injection", 'spawn("ls " + userInput)')

    def test_ssrf_variable_form(self):
        assert self._match("js.node.ssrf", "const response = await axios.get(url);")
        assert self._match("js.node.ssrf", "fetch(target)")

    def test_path_traversal_variable_form(self):
        assert self._match(
            "js.node.path-traversal",
            "const filepath = path.join(__dirname, 'uploads', filename);",
        )

    def test_sql_injection_concat_form(self):
        assert self._match(
            "js.node.sql-injection",
            'const sql = "SELECT * FROM users WHERE id = " + userId;',
        )
        assert not self._match(
            "js.node.sql-injection",
            'const sql = "SELECT * FROM users WHERE id = ?";',
        )

    def test_jwt_weak_rule_exists_and_matches(self):
        rule = self._rule("js.node.jwt-weak")
        assert rule.severity == "HIGH"
        assert rule.cwe == "CWE-347"
        assert rule.category == "AUTH"
        import re
        assert re.search(rule.code_pattern, "jwt.sign(payload, JWT_SECRET)")
        assert re.search(rule.code_pattern, 'jwt.sign(payload, "abc123")')
        assert not re.search(rule.code_pattern, "jwt.sign(payload, strongSecret, { algorithm: 'HS256' })")


# ─────────────────────── A5: JS 靶场闭环 ───────────────────────

@pytest.fixture(scope="module")
def scan_results():
    return _run_scan(PLAYGROUND_DIR / "app.js")


@pytest.fixture(scope="module")
def expected():
    return json.loads(EXPECTED_FILE.read_text(encoding="utf-8"))


class TestJSPlayground:
    """靶场：8 条 vulnerability 全检出（±3 行）、7 条 safe 零误报"""

    def test_vulnerabilities_all_detected(self, scan_results, expected):
        vulns = [f for f in expected["findings"] if f["type"] == "vulnerability"]
        assert len(vulns) == 8
        misses = []
        for v in vulns:
            hit = any(
                r.rule_id == v["rule_id"] and abs(r.line - v["line_approx"]) <= 3
                for r in scan_results
            )
            if not hit:
                misses.append(f"{v['id']}({v['rule_id']}@~{v['line_approx']})")
        assert not misses, f"漏检: {misses}"

    def test_safe_lines_zero_false_positive(self, scan_results, expected):
        safes = [f for f in expected["findings"] if f["type"] == "safe"]
        assert len(safes) == 7
        fps = []
        for s in safes:
            bad = [
                r for r in scan_results
                if r.rule_id == s["rule_id"] and abs(r.line - s["line_approx"]) <= 3
            ]
            if bad:
                fps.append(f"{s['id']}({s['rule_id']}@~{s['line_approx']}): {[r.line for r in bad]}")
        assert not fps, f"误报: {fps}"

    def test_expected_counts_consistent(self, expected):
        assert expected["total_vulnerabilities"] == 8
        assert expected["total_safe_patterns"] == 7
