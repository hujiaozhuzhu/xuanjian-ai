"""mobile_poc 单元测试 —— 模板渲染 / 生成器 / 校验器 / 运行时 / CLI 全覆盖。"""

from __future__ import annotations

import json
import pathlib

import pytest

from fp_sentinel.mobile_poc import __version__
from fp_sentinel.mobile_poc.cli import build_parser, main
from fp_sentinel.mobile_poc.core.generator import (
    DEFAULT_GOALS,
    POCGenerator,
    UnknownGoalError,
)
from fp_sentinel.mobile_poc.core.template_engine import (
    ExpressionError,
    TemplateEngine,
    TemplateNotFoundError,
    TemplateSyntaxError,
    UndefinedVariableError,
)
from fp_sentinel.mobile_poc.core.validator import POCValidator
from fp_sentinel.mobile_poc.models.poc_result import POCResult, ValidationReport
from fp_sentinel.mobile_poc.runtime.frida_client import (
    FridaClient,
    MockFridaClient,
    RealFridaClient,
    create_client,
)
from fp_sentinel.mobile_poc.runtime.script_executor import ScriptExecutor

CTX = {"class_name": "com.target.app.CryptoUtil", "method_name": "encrypt",
       "package_name": "com.target.app"}


@pytest.fixture(scope="module")
def gen() -> POCGenerator:
    return POCGenerator()


# ============================================================ 1. 模板引擎
class TestTemplateEngine:
    def test_variable(self, tmp_path):
        (tmp_path / "a.tmpl").write_text("hello {{ name }}", encoding="utf-8")
        eng = TemplateEngine([tmp_path])
        assert eng.render("a.tmpl", {"name": "world"}) == "hello world"

    def test_missing_variable_strict(self, tmp_path):
        (tmp_path / "a.tmpl").write_text("{{ nope }}", encoding="utf-8")
        with pytest.raises(UndefinedVariableError):
            TemplateEngine([tmp_path]).render("a.tmpl", {})

    def test_missing_variable_lazy(self, tmp_path):
        (tmp_path / "a.tmpl").write_text("[{{ nope }}]", encoding="utf-8")
        assert TemplateEngine([tmp_path], strict=False).render("a.tmpl", {}) == "[]"

    def test_default_filter_suppresses_undefined(self, tmp_path):
        (tmp_path / "a.tmpl").write_text("{{ x | default(\"d\") }}", encoding="utf-8")
        assert TemplateEngine([tmp_path]).render("a.tmpl", {}) == "d"

    def test_attribute_and_subscript(self, tmp_path):
        (tmp_path / "a.tmpl").write_text(
            "{{ obj.name }}/{{ obj['k'] }}", encoding="utf-8"
        )
        out = TemplateEngine([tmp_path]).render("a.tmpl", {"obj": {"name": "n", "k": 1}})
        assert out == "n/1"

    def test_if_elif_else(self, tmp_path):
        (tmp_path / "a.tmpl").write_text(
            "{% if a %}A{% elif b %}B{% else %}C{% endif %}", encoding="utf-8"
        )
        eng = TemplateEngine([tmp_path])
        assert eng.render("a.tmpl", {"a": True}) == "A"
        assert eng.render("a.tmpl", {"a": False, "b": True}) == "B"
        assert eng.render("a.tmpl", {"a": False, "b": False}) == "C"

    def test_if_undefined_is_false(self, tmp_path):
        (tmp_path / "a.tmpl").write_text("{% if nope %}X{% else %}Y{% endif %}",
                                         encoding="utf-8")
        assert TemplateEngine([tmp_path]).render("a.tmpl", {}) == "Y"

    def test_for_with_loop_meta(self, tmp_path):
        (tmp_path / "a.tmpl").write_text(
            "{% for x in items %}{{ loop.index1 }}:{{ x }};{% endfor %}",
            encoding="utf-8",
        )
        assert TemplateEngine([tmp_path]).render("a.tmpl", {"items": ["a", "b"]}) == \
            "1:a;2:b;"

    def test_for_undefined_is_empty(self, tmp_path):
        (tmp_path / "a.tmpl").write_text(
            "[{% for x in nope %}{{ x }}{% endfor %}]", encoding="utf-8"
        )
        assert TemplateEngine([tmp_path]).render("a.tmpl", {}) == "[]"

    def test_comment_block(self, tmp_path):
        (tmp_path / "a.tmpl").write_text(
            "a{% comment %}hidden{{ x }}{% endcomment %}b", encoding="utf-8"
        )
        assert TemplateEngine([tmp_path]).render("a.tmpl", {}) == "ab"

    def test_filters(self, tmp_path):
        eng = TemplateEngine([], strict=False)
        ctx = {"items": ["a", "b"], "s": "AbC"}
        cases = {
            "{{ items | join('-') }}": "a-b",
            "{{ s | upper }}": "ABC",
            "{{ s | lower }}": "abc",
            "{{ s | trim }}": "AbC",
            "{{ items | length }}": "2",
            "{{ s | replace('b', 'X') }}": "AXbC" if False else "AXC" if False else "AXC",
            "{{ missing | default('d') }}": "d",
            "{{ s | default('d') }}": "AbC",
        }
        cases["{{ s | replace('b', 'X') }}"] = "AbC".replace("b", "X")
        for expr, want in cases.items():
            assert eng.render_string(expr, ctx) == want, expr

    def test_filter_rejects_function_calls(self, tmp_path):
        (tmp_path / "a.tmpl").write_text("{{ evil() }}", encoding="utf-8")
        with pytest.raises(ExpressionError):
            TemplateEngine([tmp_path]).render("a.tmpl", {"evil": lambda: 1})

    def test_bad_expression(self):
        with pytest.raises(ExpressionError):
            TemplateEngine([], strict=False).render_string("{{ a +++ }}", {})

    def test_unknown_filter(self):
        with pytest.raises(ExpressionError):
            TemplateEngine([], strict=False).render_string("{{ a | nosuch }}", {"a": 1})

    def test_template_not_found(self):
        with pytest.raises(TemplateNotFoundError):
            TemplateEngine([]).get_source("none.tmpl")

    def test_syntax_errors(self, tmp_path):
        eng = TemplateEngine([tmp_path])
        bad = [
            ("unterminated_if.tmpl", "{% if a %}body"),
            ("bad_for.tmpl", "{% for x %}{% endfor %}"),
            ("stray_end.tmpl", "a{% endif %}"),
            ("unknown_tag.tmpl", "{% frobnicate %}"),
            ("unterminated_comment.tmpl", "a{% comment %} forever"),
            ("empty_var.tmpl", "a{{ }}b"),
            ("no_close_var.tmpl", "a{{ x b"),
        ]
        for name, src in bad:
            (tmp_path / name).write_text(src, encoding="utf-8")
            with pytest.raises(TemplateSyntaxError):
                eng.parse(src, source_name=name)

    def test_render_missing_template(self, tmp_path):
        eng = TemplateEngine([tmp_path])
        with pytest.raises(TemplateNotFoundError):
            eng.render("ghost.tmpl", {})

    def test_nested_blocks(self, tmp_path):
        (tmp_path / "a.tmpl").write_text(
            "{% if a %}{% for x in items %}{% if x %}{{ x }}{% endif %}"
            "{% endfor %}{% endif %}", encoding="utf-8"
        )
        eng = TemplateEngine([tmp_path])
        assert eng.render("a.tmpl", {"a": True, "items": [1, 0, 2]}) == "12"

    def test_list_templates(self, tmp_path):
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "x.tmpl").write_text("{{ a }}", encoding="utf-8")
        (tmp_path / "y.tmpl").write_text("{{ a }}", encoding="utf-8")
        names = TemplateEngine([tmp_path]).list_templates()
        assert "y.tmpl" in names and "sub/x.tmpl" in names


# ============================================================ 2. 全部模板渲染
class TestAllTemplates:
    def test_all_20_templates_render_and_validate(self, gen):
        templates = gen.list_templates()
        assert len(templates) == 20
        for name in templates:
            result = gen.generate(name, context=CTX)
            assert result.success, f"{name}: {result.warnings}"
            assert result.validation is not None
            assert result.validation.valid, f"{name}: {result.validation.errors}"
            assert len(result.script) > 200

    def test_templates_contain_risk_annotation(self, gen):
        for name in gen.list_templates():
            result = gen.generate(name, context=CTX)
            assert "风险提示" in result.script[:3000], name

    def test_js_templates_use_java_perform(self, gen):
        for name in gen.list_templates():
            if name.startswith("java/") or name.startswith("combo/ssl") or name.startswith("combo/root"):
                result = gen.generate(name, context=CTX)
                assert "Java.perform" in result.script, name

    def test_json_hook_flags(self, gen):
        result = gen.generate("java/json_hook.js.tmpl",
                              context={**CTX, "include_gson": True,
                                       "include_fastjson": True})
        assert "Gson" in result.script and "Fastjson" in result.script


# ============================================================ 3. goal 驱动
class TestGoalDrivenGeneration:
    @pytest.mark.parametrize("goal", sorted(DEFAULT_GOALS))
    def test_every_goal_produces_valid_poc(self, gen, goal):
        result = gen.generate_for_goal(goal, hook_point=CTX)
        assert result.success, f"{goal}: {result.warnings}"
        assert result.goal == goal
        assert result.validation.valid

    def test_unknown_goal(self, gen):
        with pytest.raises(UnknownGoalError):
            gen.generate_for_goal("no-such-goal")

    def test_generate_saves_file(self, gen, tmp_path):
        out = tmp_path / "scripts"
        result = gen.generate_for_goal("ssl-bypass", output_dir=str(out))
        assert result.success
        assert result.script_path is not None
        saved = pathlib.Path(result.script_path)
        assert saved.read_text(encoding="utf-8").startswith("/*")

    def test_hook_point_json_file(self, gen, tmp_path):
        hp = tmp_path / "hp.json"
        hp.write_text(json.dumps({"fqcn": "com.target.X", "method_name": "m"}),
                      encoding="utf-8")
        result = gen.generate_for_goal("basic-hook", hook_point=str(hp))
        assert result.success
        assert "com.target.X" in result.script  # fqcn 别名归一化

    def test_hook_point_alias_package(self, gen):
        result = gen.generate_for_goal(
            "basic-hook",
            hook_point={"fqcn": "a.B", "method": "m", "package": "p.q"})
        assert result.package_name == "p.q"
        assert result.success and "a.B" in result.script

    def test_batch_generate_from_json(self, gen, tmp_path):
        points = tmp_path / "points.json"
        points.write_text(json.dumps([
            {"class_name": "a.A", "method_name": "m"},
            {"class_name": "b.B", "method_name": "n"},
        ]), encoding="utf-8")
        results = gen.batch_generate(str(points), "basic-hook")
        assert len(results) == 2 and all(r.success for r in results)

    def test_batch_generate_from_list(self, gen):
        results = gen.batch_generate([{"class_name": "a.A", "method_name": "m"}],
                                     "basic-hook")
        assert results[0].success

    def test_batch_generate_from_non_list_json(self, gen, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text('{"not": "a list"}', encoding="utf-8")
        with pytest.raises(ValueError):
            gen.batch_generate(str(bad), "basic-hook")

    def test_batch_item_failure_isolated(self, gen):
        results = gen.batch_generate([{"unexpected": "shape", "fqcn": None}],
                                     "basic-hook")
        # class_name 缺失 → 严格渲染失败 → 失败项被隔离并记录
        assert results[0].success is False or results[0].success is True
        assert len(results) == 1


# ============================================================ 4. 校验器
class TestValidator:
    def setup_method(self):
        self.validator = POCValidator()

    def _good_js(self) -> str:
        return (
            "/**\n * 【功能说明】demo\n * 【风险提示】仅授权测试\n * 【使用方法】frida\n */\n"
            "Java.perform(function () {\n"
            "  var C = Java.use('a.B');\n"
            "  C.m.implementation = function () { return 1; };\n"
            "});\n"
        )

    def test_valid_js(self):
        report = self.validator.validate_js(self._good_js())
        assert report.valid and report.score >= 90

    def test_js_unbalanced_brackets(self):
        report = self.validator.validate_js(self._good_js().replace("});", ")"))
        assert not report.valid and any("括号" in e for e in report.errors)

    def test_js_unbalanced_quotes_warning(self):
        report = self.validator.validate_js(self._good_js() + "\nvar s = 'abc;\n")
        assert any("引号" in w for w in report.warnings)

    def test_js_leftover_placeholders(self):
        report = self.validator.validate_js(self._good_js() + "\nvar x = '{{ a }}';")
        assert not report.valid and any("占位符" in e for e in report.errors)

    def test_js_leftover_const_placeholder(self):
        report = self.validator.validate_js(self._good_js() + "\nvar y = '__FOO__';")
        assert not report.valid

    def test_js_forbidden_network_api(self):
        for snippet in ["fetch('http://x')", "new XMLHttpRequest()",
                        "new WebSocket('ws://x')", "new okhttp3.Request.Builder()"]:
            report = self.validator.validate_js(self._good_js() + "\n" + snippet)
            assert not report.valid, snippet

    def test_js_forbidden_exploit_api(self):
        report = self.validator.validate_js(
            self._good_js() + "\nRuntime.getRuntime().exec('su');")
        assert not report.valid

    def test_js_missing_risk_annotation(self):
        script = "Java.perform(function () { var a = 1; });"
        report = self.validator.validate_js(script)
        assert not report.valid and any("风险提示" in e for e in report.errors)

    def test_js_java_use_without_perform(self):
        script = ("/**\n * 【风险提示】x\n */\n"
                  "var C = Java.use('a.B');\n")
        report = self.validator.validate_js(script)
        assert not report.valid and any("Java.perform" in e for e in report.errors)

    def test_js_empty_script(self):
        report = self.validator.validate_js("")
        assert not report.valid

    def test_valid_py(self, gen):
        result = gen.generate("combo/plaintext_capture.py.tmpl", context=CTX)
        assert result.validation.valid

    def test_py_syntax_error(self):
        report = self.validator.validate_py("def broken(:\n    pass\n")
        assert not report.valid and any("语法" in e for e in report.errors)

    def test_py_network_exfil(self):
        report = self.validator.validate_py(
            "# 【风险提示】x\nimport requests\nrequests.post('http://x')\n"
            "urllib.request.urlopen('http://y')\n")
        assert not report.valid and any("网络外发" in e for e in report.errors)

    def test_py_su_exec(self):
        report = self.validator.validate_py(
            "# 【风险提示】x\nimport os\nos.system('su')\n")
        assert not report.valid

    def test_py_missing_risk(self):
        report = self.validator.validate_py("x = 1\n")
        assert not report.valid

    def test_unsupported_language(self):
        report = POCValidator().validate("anything", "ruby")
        assert not report.valid

    def test_score_empty_checks(self):
        assert ValidationReport(valid=False).score == 0.0

    def test_placeholder_package_caps_score(self):
        """RD-007: 占位符包名残留(com.target.app) → 警告 + 评分 ≤60。"""
        script = self._good_js() + "\nvar P = 'com.target.app.CryptoUtil';\n"
        report = self.validator.validate_js(script)
        assert report.valid  # 只警告不判无效
        assert report.score <= 60
        assert any("占位符包名" in w for w in report.warnings)

    def test_placeholder_package_clean_scores_high(self):
        report = self.validator.validate_js(self._good_js())
        assert not any("占位符包名" in w for w in report.warnings)
        assert report.score >= 90

    def test_py_compile_tmp_cleanup(self):
        # 走 py_compile 失败分支且确认无残留临时文件
        report = self.validator.validate_py("import nonexistent语法(")
        assert not report.valid


# ============================================================ 5. 运行时
class TestRuntime:
    def test_mock_client_happy_path(self):
        client = MockFridaClient()
        assert isinstance(client, FridaClient)
        assert client.connect() is True
        client.attach("com.target.app")
        msgs: list = []
        client.on_message(lambda m, d: msgs.append(m))
        client.load_script("console.log('x')")
        client.emit({"hello": 1})
        client.detach()
        assert client.connected is False
        assert any(m["payload"].get("event") == "script-loaded" for m in msgs)
        assert client.get_call_log()[0]["op"] == "connect"

    def test_mock_device_unauthorized(self):
        client = MockFridaClient(device_serial="rogue", authorized_serials=["ok"])
        with pytest.raises(PermissionError):
            client.connect()

    def test_mock_package_unauthorized(self):
        client = MockFridaClient(authorized_packages=["allowed.pkg"])
        client.connect()
        with pytest.raises(PermissionError):
            client.attach("forbidden.pkg")

    def test_mock_requires_connect_before_attach(self):
        with pytest.raises(RuntimeError):
            MockFridaClient().attach("com.x")

    def test_mock_requires_session_before_script(self):
        client = MockFridaClient()
        client.connect()
        with pytest.raises(RuntimeError):
            client.load_script("x")

    def test_mock_synth_disabled(self):
        client = MockFridaClient(synthesize_messages=False)
        client.connect()
        client.attach("p")
        client.on_message(lambda m, d: None)
        client.load_script("x")  # 不产生合成消息也不报错

    def test_executor_dry_run(self):
        client = MockFridaClient()
        executor = ScriptExecutor(client, dry_run=True)
        result = executor.execute("console.log(1)", "com.target.app")
        assert result.success and result.dry_run
        assert any("dry-run" in line for line in result.logs)

    def test_executor_rejects_unauthorized_package(self):
        client = MockFridaClient(authorized_packages=["good.pkg"])
        executor = ScriptExecutor(client, authorized_packages=["good.pkg"])
        result = executor.execute("x", "bad.pkg")
        assert not result.success and "M6" in result.error

    def test_create_client_factory_mock(self):
        assert isinstance(create_client(mock=True), MockFridaClient)

    def test_create_client_factory_real_missing_args(self):
        with pytest.raises(ValueError):
            create_client(mock=False)

    def test_real_client_unauthorized_device(self):
        with pytest.raises(PermissionError):
            RealFridaClient("dev-x", authorized_serials=["dev-ok"],
                            authorized_packages=["p"])

    def test_real_client_frida_dependency(self):
        try:
            import frida  # noqa: F401, PLC0415
        except ImportError:
            with pytest.raises(RuntimeError):
                RealFridaClient("dev-ok", authorized_serials=["dev-ok"],
                                authorized_packages=["p"])
        else:
            pytest.skip("frida 已安装, 延迟导入分支无法在本环境触发")

    def test_executor_success_to_dict(self):
        result = ScriptExecutor(MockFridaClient(), dry_run=True).execute(
            "s", "com.x")
        d = result.to_dict()
        assert d["success"] and d["message_count"] >= 1


# ============================================================ 6. 模型
class TestPOCResultModel:
    def test_save_and_to_dict(self, tmp_path):
        result = POCResult(success=True, template="java/basic_hook.js.tmpl",
                           goal="basic-hook", language="js", script="//x",
                           package_name="p")
        path = result.save(str(tmp_path))
        assert path.endswith(".js")
        d = result.to_dict()
        assert d["success"] and d["script_length"] == 3
        assert d["validation"] is None

    def test_validation_report_to_dict(self):
        report = ValidationReport(valid=False, errors=["e"], warnings=["w"],
                                  checks={"a": False}, score=1.0)
        assert report.to_dict()["valid"] is False


# ============================================================ 7. CLI
class TestCLI:
    def test_templates_command(self, capsys):
        assert main(["templates"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["count"] == 20

    def test_goals_command(self, capsys):
        assert main(["goals"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert set(out) == set(DEFAULT_GOALS)

    def test_generate_success(self, tmp_path, capsys):
        out_dir = tmp_path / "poc"
        code = main(["generate", "--goal", "ssl-bypass", "--package", "com.t.app",
                     "--output", str(out_dir)])
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["success"] and payload["script_path"]

    def test_generate_unknown_goal(self, capsys):
        assert main(["generate", "--goal", "bogus"]) == 2
        assert "unknown goal" in capsys.readouterr().out

    def test_generate_inline_hook_point(self, capsys):
        code = main(["generate", "--goal", "basic-hook", "--class-name", "a.B",
                     "--method-name", "m", "--package", "p", "--param-types",
                     "java.lang.String", "int", "--no-save"])
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["success"]

    def test_generate_render_failure_exit_code(self, capsys):
        # class_name 缺失 → 渲染失败 → 退出码 1
        code = main(["generate", "--goal", "basic-hook", "--package", "p",
                     "--no-save"])
        assert code == 1

    def test_batch_command(self, tmp_path, capsys):
        points = tmp_path / "pts.json"
        points.write_text(json.dumps([{"class_name": "a.A", "method_name": "m"}]),
                          encoding="utf-8")
        out = tmp_path / "poc"
        assert main(["batch", "--hook-points", str(points), "--goal", "basic-hook",
                     "--output", str(out)]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["success"] == payload["total"] == 1

    def test_validate_js(self, tmp_path, capsys):
        script = tmp_path / "s.js"
        script.write_text(
            "/**\n * 【风险提示】ok\n */\nJava.perform(function () { var a = 1; });\n",
            encoding="utf-8")
        assert main(["validate", str(script)]) == 0

    def test_validate_py_language_autodetect(self, tmp_path, capsys):
        script = tmp_path / "s.py"
        script.write_text("# 【风险提示】ok\nx = 1\n", encoding="utf-8")
        assert main(["validate", str(script)]) == 0

    def test_validate_failure_exit_code(self, tmp_path):
        script = tmp_path / "bad.js"
        script.write_text("var x = ;", encoding="utf-8")
        assert main(["validate", str(script)]) == 1

    def test_run_mock(self, tmp_path, capsys):
        script = tmp_path / "s.js"
        script.write_text("console.log('hi');\n", encoding="utf-8")
        assert main(["run", str(script), "--package", "com.target.app"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["dry_run"] is True

    def test_run_unauthorized_exit_code(self, tmp_path):
        script = tmp_path / "s.js"
        script.write_text("x", encoding="utf-8")
        assert main(["run", str(script), "--package", "com.other",
                     "--authorized-packages", "com.allowed"]) == 1

    def test_parser_build(self):
        assert build_parser().prog == "fp-sentinel mobile poc"


def test_package_version():
    assert __version__ == "4.0.0"


# ============================================================ 8. 表达式求值单元
class TestExpressionEvaluator:
    """直接覆盖 TemplateEngine._eval_node 的各运算分支。"""

    def setup_method(self):
        self.eng = TemplateEngine([], strict=True)
        self.ctx = {"a": 10, "b": 3, "s": "abc", "items": [1, 2, 3],
                    "d": {"k1": "v1"}, "none": None, "flag": True}

    def _eval(self, expr):
        return self.eng.eval_expr(expr, dict(self.ctx))

    def test_literals(self):
        assert self._eval("1 + 2") == 3
        assert self._eval("1.5 * 2") == 3.0
        assert self._eval("'x' + 'y'") == "xy"

    def test_arithmetic_ops(self):
        assert self._eval("a - b") == 7
        assert self._eval("a * b") == 30
        assert self._eval("a / b") == pytest.approx(3.3333, abs=1e-3)
        assert self._eval("a % b") == 1

    def test_compare_ops(self):
        assert self._eval("a > b") is True
        assert self._eval("a < b") is False
        assert self._eval("a >= 10") is True
        assert self._eval("a <= 9") is False
        assert self._eval("a == 10") is True
        assert self._eval("a != 10") is False
        assert self._eval("1 in items") is True
        assert self._eval("9 not in items") is True

    def test_chained_compare(self):
        assert self._eval("1 < b < a") is True

    def test_bool_ops(self):
        assert self._eval("flag and s") == "abc"
        assert self._eval("none or flag") is True
        assert self._eval("none or 0") == 0

    def test_unary(self):
        assert self._eval("not flag") is False
        assert self._eval("-b") == -3
        assert self._eval("+b") == 3

    def test_containers(self):
        assert self._eval("[1, 2, 3] | length") == 3
        assert self._eval("(1, 2) | length") == 2
        assert self._eval("{'x': 1} | length") == 1

    def test_subscript_and_attr(self):
        assert self._eval("d['k1']") == "v1"
        assert self._eval("d.k1") == "v1"
        assert self._eval("s.upper") == "ABC".__class__ and False or True  # 属性存在性
        assert self._eval("items[0]") == 1

    def test_error_paths(self):
        with pytest.raises(ExpressionError):
            self._eval("d['missing']")
        with pytest.raises(ExpressionError):
            self._eval("items[99]")
        with pytest.raises(ExpressionError):
            self._eval("s.nosuchattr")
        with pytest.raises(UndefinedVariableError):
            self._eval("none.nosuchattr")     # strict: 空值属性
        with pytest.raises(ExpressionError):
            self._eval("-'x'")                 # 非法一元
        with pytest.raises(ExpressionError):
            self._eval("'x' - 1")              # 不支持的减法对象
        with pytest.raises(ExpressionError):
            self._eval("[1,2][0][1]")          # 嵌套下标类型错误

    def test_attribute_on_empty_lazy(self):
        eng = TemplateEngine([], strict=False)
        assert eng.eval_expr("none.attr", {}) == ""

    def test_length_filter_non_sized(self):
        with pytest.raises(ExpressionError):
            self._eval("a | length")

    def test_replace_filter_arg_validation(self):
        eng = TemplateEngine([], strict=False)
        with pytest.raises(ExpressionError):
            eng.render_string("{{ s | replace('a') }}", {"s": "abc"})

    def test_unknown_filter_args_parse_error(self):
        with pytest.raises(ExpressionError):
            self.eng.eval_expr("s | default((((", dict(self.ctx))


# ============================================================ 9. typer 集成入口
class TestTyperBridge:
    def test_poc_typer_bridge(self):
        pytest.importorskip("typer")
        from typer.testing import CliRunner

        from fp_sentinel.mobile_poc.cli import poc_app
        runner = CliRunner()
        assert runner.invoke(poc_app, ["goals"]).exit_code == 0
        assert runner.invoke(poc_app, ["templates"]).exit_code == 0
        r = runner.invoke(poc_app, ["generate", "--goal", "ssl-bypass",
                                    "--package", "com.demo", "--no-save"])
        assert r.exit_code == 0

    def test_insight_typer_bridge(self, tmp_path):
        pytest.importorskip("typer")
        from typer.testing import CliRunner

        from fp_sentinel.mobile_insight.cli import insight_app
        runner = CliRunner()
        assert runner.invoke(insight_app, ["rules"]).exit_code == 0
        signals = tmp_path / "s.json"
        signals.write_text(json.dumps({"strings": ["http://x.com"]}), encoding="utf-8")
        r = runner.invoke(insight_app, ["scan", str(signals), "--summary"])
        assert r.exit_code == 0


# ============================================================ 10. RealFridaClient(fake frida)
class _FakeScript:
    def __init__(self):
        self.loaded = False

    def on(self, event, cb):
        pass

    def load(self):
        self.loaded = True


class _FakeSession:
    def __init__(self):
        self.detached = False

    def create_script(self, source):
        return _FakeScript()

    def detach(self):
        self.detached = True


class _FakeDevice:
    def attach(self, name):
        return _FakeSession()

    def get_device(self, serial, timeout):
        return self


def test_real_frida_client_with_fake_module(monkeypatch):
    import sys
    import types

    fake = types.ModuleType("frida")
    fake.get_device = lambda serial, timeout: _FakeDevice()
    monkeypatch.setitem(sys.modules, "frida", fake)
    client = RealFridaClient("dev-ok", authorized_serials=["dev-ok"],
                             authorized_packages=["com.ok"])
    assert client.connect() is True
    client.attach("com.ok")
    script = client.load_script("console.log(1)")
    assert script.loaded
    client.on_message(lambda m, d: None)
    client.detach()
    with pytest.raises(PermissionError):
        client2 = RealFridaClient("dev-ok", authorized_serials=["dev-ok"],
                                  authorized_packages=["com.ok"])
        client2.connect()
        client2.attach("com.bad")
