"""
降噪引擎单元测试

覆盖 L1-L3 降噪器的正向/负向/异常路径
"""

import pytest
from fp_sentinel.filters.noise_reducer import (
    NoiseReducerL1,
    NoiseReducerL2,
    NoiseReducerL3,
    NoisePipeline,
    FilterResult,
)


class TestNoiseReducerL1:
    """L1 语法降噪器测试"""

    def setup_method(self):
        self.reducer = NoiseReducerL1()

    # ── 白名单注释 ──

    def test_nosec_comment_filtered(self):
        finding = type('Finding', (), {
            'code_snippet': 'eval(x)  # nosec',
            'file_path': 'app.js',
            'rule_id': 'js.injection.eval',
        })()
        result = self.reducer.filter(finding)
        assert not result.passed
        assert "白名单注释" in result.reason

    def test_noqa_comment_filtered(self):
        finding = type('Finding', (), {
            'code_snippet': 'os.system(cmd)  # noqa',
            'file_path': 'app.py',
            'rule_id': 'py.injection.command',
        })()
        result = self.reducer.filter(finding)
        assert not result.passed

    def test_nosonar_comment_filtered(self):
        finding = type('Finding', (), {
            'code_snippet': 'exec(code);  // NOSONAR',
            'file_path': 'app.js',
            'rule_id': 'js.injection.eval',
        })()
        result = self.reducer.filter(finding)
        assert not result.passed

    def test_suppress_warnings_filtered(self):
        finding = type('Finding', (), {
            'code_snippet': '@SuppressWarnings("sql")\nquery(user)',
            'file_path': 'App.java',
            'rule_id': 'java.sql.injection',
        })()
        result = self.reducer.filter(finding)
        assert not result.passed

    # ── 常量表达式 ──

    def test_constant_eval_filtered(self):
        finding = type('Finding', (), {
            'code_snippet': 'eval("1+1")',
            'file_path': 'app.js',
            'rule_id': 'js.injection.eval',
        })()
        result = self.reducer.filter(finding)
        assert not result.passed
        assert "常量表达式" in result.reason

    def test_constant_exec_filtered(self):
        finding = type('Finding', (), {
            'code_snippet': 'exec("print(1)")',
            'file_path': 'app.py',
            'rule_id': 'py.injection.eval',
        })()
        result = self.reducer.filter(finding)
        assert not result.passed

    # ── 测试文件 ──

    def test_test_file_filtered(self):
        finding = type('Finding', (), {
            'code_snippet': 'eval(userInput)',
            'file_path': 'tests/test_app.py',
            'rule_id': 'js.injection.eval',
        })()
        result = self.reducer.filter(finding)
        assert not result.passed
        assert "测试文件" in result.reason

    def test_spec_file_filtered(self):
        finding = type('Finding', (), {
            'code_snippet': 'eval(x)',
            'file_path': 'src/app.test.js',
            'rule_id': 'js.injection.eval',
        })()
        result = self.reducer.filter(finding)
        assert not result.passed

    # ── 安全函数 ──

    def test_dompurify_not_filtered_as_safe(self):
        """DOMPurify 应该被识别为安全函数"""
        finding = type('Finding', (), {
            'code_snippet': 'element.innerHTML = DOMPurify.sanitize(input)',
            'file_path': 'app.js',
            'rule_id': 'js.xss.innerhtml',
        })()
        result = self.reducer.filter(finding)
        assert not result.passed
        assert "安全函数" in result.reason

    def test_yaml_safe_load_not_filtered(self):
        finding = type('Finding', (), {
            'code_snippet': 'data = yaml.safe_load(input)',
            'file_path': 'app.py',
            'rule_id': 'py.deserialization.yaml',
        })()
        result = self.reducer.filter(finding)
        assert not result.passed

    # ── 正向测试（不应过滤） ──

    def test_real_vulnerability_passed(self):
        """真实漏洞不应被过滤"""
        finding = type('Finding', (), {
            'code_snippet': 'eval(userInput)',
            'file_path': 'app.js',
            'rule_id': 'js.injection.eval',
        })()
        result = self.reducer.filter(finding)
        assert result.passed

    def test_real_xss_passed(self):
        finding = type('Finding', (), {
            'code_snippet': 'element.innerHTML = userInput',
            'file_path': 'app.js',
            'rule_id': 'js.xss.innerhtml',
        })()
        result = self.reducer.filter(finding)
        assert result.passed

    # ── 边界条件 ──

    def test_empty_code(self):
        finding = type('Finding', (), {
            'code_snippet': '',
            'file_path': 'app.js',
            'rule_id': 'js.injection.eval',
        })()
        result = self.reducer.filter(finding)
        assert result.passed

    def test_none_code(self):
        finding = type('Finding', (), {
            'code_snippet': None,
            'file_path': 'app.js',
            'rule_id': 'js.injection.eval',
        })()
        result = self.reducer.filter(finding)
        assert result.passed


class TestNoiseReducerL2:
    """L2 语义降噪器测试"""

    def setup_method(self):
        self.reducer = NoiseReducerL2()

    def test_security_decorator_filtered(self):
        finding = type('Finding', (), {
            'code_snippet': '@login_required\ndef view(request):\n    db.query(sql)',
            'file_path': 'views.py',
            'rule_id': 'py.injection.sql',
        })()
        result = self.reducer.filter(finding, [finding.code_snippet])
        assert not result.passed
        assert "安全装饰器" in result.reason

    def test_django_orm_filtered(self):
        finding = type('Finding', (), {
            'code_snippet': 'User.objects.filter(id=user_id)',
            'file_path': 'views.py',
            'rule_id': 'py.injection.sql',
        })()
        result = self.reducer.filter(finding, [finding.code_snippet])
        assert not result.passed
        assert "框架安全特性" in result.reason

    def test_input_validation_filtered(self):
        context = [
            'user_id = int(request.args["id"])',
            'cursor.execute("SELECT * WHERE id=%s", (user_id,))',
        ]
        finding = type('Finding', (), {
            'code_snippet': context[1],
            'file_path': 'db.py',
            'rule_id': 'py.injection.sql',
        })()
        result = self.reducer.filter(finding, context)
        # int() 转换是输入校验
        assert not result.passed

    def test_real_vulnerability_no_guard(self):
        """无安全守卫的真实漏洞"""
        finding = type('Finding', (), {
            'code_snippet': 'cursor.execute("SELECT * WHERE id=" + user_id)',
            'file_path': 'db.py',
            'rule_id': 'py.injection.sql',
        })()
        result = self.reducer.filter(finding, [finding.code_snippet])
        assert result.passed


class TestNoiseReducerL3:
    """L3 统计降噪器测试"""

    def setup_method(self):
        self.reducer = NoiseReducerL3()

    def test_duplicate_detection_filtered(self):
        """重复检测应被过滤"""
        finding = type('Finding', (), {
            'code_snippet': 'eval(userInput)',
            'file_path': 'app.js',
            'line_start': 10,
            'line': 10,
            'rule_id': 'js.injection.eval',
        })()
        # 第一次通过
        result1 = self.reducer.filter(finding)
        assert result1.passed
        # 第二次被去重
        result2 = self.reducer.filter(finding)
        assert not result2.passed
        assert "重复检测" in result2.reason

    def test_different_code_not_deduped(self):
        """不同代码不应被去重"""
        finding1 = type('Finding', (), {
            'code_snippet': 'eval(userInput)',
            'file_path': 'app.js',
            'line_start': 10,
            'line': 10,
            'rule_id': 'js.injection.eval',
        })()
        finding2 = type('Finding', (), {
            'code_snippet': 'exec(userInput)',
            'file_path': 'app.js',
            'line_start': 20,
            'line': 20,
            'rule_id': 'py.injection.eval',
        })()
        result1 = self.reducer.filter(finding1)
        result2 = self.reducer.filter(finding2)
        assert result1.passed
        assert result2.passed

    def test_clear_cache(self):
        """清除缓存后重复检测应通过"""
        finding = type('Finding', (), {
            'code_snippet': 'eval(userInput)',
            'file_path': 'app.js',
            'line_start': 10,
            'line': 10,
            'rule_id': 'js.injection.eval',
        })()
        self.reducer.filter(finding)
        self.reducer.clear_cache()
        result = self.reducer.filter(finding)
        assert result.passed


class TestNoisePipeline:
    """降噪流水线测试"""

    def test_pipeline_basic(self):
        pipeline = NoisePipeline(enable_l1=True, enable_l2=True, enable_l3=True)

        findings = [
            type('Finding', (), {
                'code_snippet': 'eval(userInput)',
                'file_path': 'app.js',
                'line_start': 10,
                'line': 10,
                'rule_id': 'js.injection.eval',
                'confidence': 0.8,
            })(),
            type('Finding', (), {
                'code_snippet': 'eval("1+1")',
                'file_path': 'app.js',
                'line_start': 20,
                'line': 20,
                'rule_id': 'js.injection.eval',
                'confidence': 0.8,
            })(),
        ]

        # 需要异步测试
        import asyncio
        result = asyncio.run(pipeline.process(findings))
        # 常量表达式应被L1过滤
        assert len(result) == 1

    def test_pipeline_stats(self):
        pipeline = NoisePipeline()
        assert pipeline.get_stats()["total"] == 0
        pipeline.reset_stats()
