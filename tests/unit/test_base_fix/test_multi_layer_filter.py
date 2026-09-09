"""
多层误报过滤测试 v3.2.0
"""


import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))


class TestMultiLayerFilter:

    def setup_method(self):
        from fp_sentinel.filters.multi_layer_filter import (
            MultiLayerFilter,
            ScanFinding,
            is_false_positive,
            batch_filter_findings,
        )
        self.cls = MultiLayerFilter
        self.finding_cls = ScanFinding
        self.is_fp = is_false_positive
        self.batch = batch_filter_findings

    def _finding(self, rule_id="rule-X", line=5, code="a = 1",
                 severity="HIGH", confidence=0.8):
        return self.finding_cls(
            rule_id=rule_id,
            file_path="src/main.py",
            line_number=line,
            matched_code=code,
            severity=severity,
            confidence=confidence,
            category="XSS",
        )

    def test_test_file_is_filtered(self):
        """测试文件中的命中应被过滤"""
        f = self._finding()
        code_lines = ["line" + str(i) for i in range(10)]
        result = self.is_fp(f, code_lines, "tests/test_login.py")
        assert result.is_false_positive
        assert result.layer in ("L0", "L1")

    def test_vendor_file_is_filtered(self):
        """第三方库文件应被过滤"""
        f = self._finding()
        code_lines = ["line" for _ in range(10)]
        result = self.is_fp(f, code_lines, "node_modules/x/dist/a.min.js")
        assert result.is_false_positive

    def test_env_var_in_code_is_filtered(self):
        """代码包含环境变量读取应被过滤"""
        f = self._finding(code="x = os.environ.get('KEY')")
        code_lines = ["import os", "x = os.environ.get('KEY')", "y = x"]
        result = self.is_fp(f, code_lines, "src/app.py")
        assert result.is_false_positive

    def test_context_guard_filters(self):
        """上下文中存在 PreparedStatement 等 guard 应被过滤"""
        f = self._finding(
            rule_id="sql.injection",
            code="cursor.execute(sql)",
        )
        code_lines = [
            "def query(id):",
            "  sql = 'SELECT * FROM t WHERE id = ?'",
            "  stmt = conn.prepareStatement(sql)",  # guard
            "  stmt.setString(1, id)",
            "  cursor.execute(stmt)",
        ]
        mlf = self.cls(code_lines, "src/db.py")
        result = mlf.evaluate(f)
        assert result.is_false_positive

    def test_real_finding_passes(self):
        """无 guard 的真实发现不应被过滤"""
        f = self._finding(
            rule_id="sql.injection",
            code='cursor.execute("SELECT * FROM t WHERE id = " + user_id)',
            line=3,
        )
        code_lines = [
            "def query(id):",
            "  # no guard here",
            '  cursor.execute("SELECT * FROM t WHERE id = " + user_id)',
        ]
        mlf = self.cls(code_lines, "src/db.py")
        result = mlf.evaluate(f)
        assert not result.is_false_positive

    def test_framework_vue_autoescape(self):
        """Vue 模板中 v-text 自动转义"""
        f = self._finding(
            rule_id="js.xss.innerhtml",
            code="<div>{{ userInput }}</div>",
            line=2,
        )
        code_lines = [
            "<template>",
            "  <div>{{ userInput }}</div>",
            "</template>",
        ]
        mlf = self.cls(code_lines, "src/App.vue", "vue")
        result = mlf.evaluate(f)
        assert result.is_false_positive

    def test_batch_filter(self):
        """批量过滤"""
        findings = [
            self._finding("rule-1", 2, "x = os.environ.get('A')"),
            self._finding("rule-2", 5, 'y = input()'),
        ]
        code_lines = [
            "import os",
            "x = os.environ.get('A')",
            "def foo():",
            "  pass",
            "y = input()",
        ]
        real, fp = self.batch(findings, code_lines, "src/app.py")
        assert len(real) + len(fp) == 2

    def test_filter_result_fields(self):
        """过滤结果包含必要字段"""
        f = self._finding()
        code_lines = ["a" for _ in range(10)]
        result = self.is_fp(f, code_lines, "src/app.py")
        assert hasattr(result, "is_false_positive")
        assert hasattr(result, "confidence")
        assert hasattr(result, "layer")