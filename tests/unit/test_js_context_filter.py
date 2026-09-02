"""
JS 上下文过滤器单元测试
"""

import pytest
from fp_sentinel.filters.js_context_filter import JSContextFilter
from fp_sentinel.models import ScanResult, ScanTool, Severity


class TestJSContextFilter:
    """JS 上下文过滤器测试"""

    def setup_method(self):
        self.filter = JSContextFilter()

    def test_detect_framework_react(self, tmp_path):
        """检测React框架"""
        file_path = str(tmp_path / "App.jsx")
        context = 'import React from "react"\nconst App = () => <div/>'
        result = self.filter._detect_framework(file_path, context)
        assert result == "react"

    def test_detect_framework_vue(self, tmp_path):
        """检测Vue框架"""
        file_path = str(tmp_path / "App.vue")
        context = ""
        result = self.filter._detect_framework(file_path, context)
        assert result == "vue"

    def test_detect_framework_jquery(self, tmp_path):
        """检测jQuery"""
        file_path = str(tmp_path / "app.js")
        context = 'jQuery("#element").html("test")'
        result = self.filter._detect_framework(file_path, context)
        assert result == "jquery"

    def test_detect_framework_none(self, tmp_path):
        """无框架"""
        file_path = str(tmp_path / "app.js")
        context = 'const x = 1;'
        result = self.filter._detect_framework(file_path, context)
        assert result is None

    def test_check_dead_code(self):
        """死代码检测"""
        lines = ['if (false) { eval(x); }']
        result = self.filter._check_dead_code(lines)
        assert result is True

    def test_is_test_file(self):
        """测试文件检测"""
        assert self.filter._is_test_file("tests/app.test.js")
        assert self.filter._is_test_file("src/__tests__/app.js")
        assert not self.filter._is_test_file("src/app.js")

    def test_check_safe_api_usage_innerhtml(self):
        """innerHTML 的安全替代检测"""
        lines = ['element.textContent = userInput']
        result = self.filter._check_safe_api_usage(lines, "js.xss.innerhtml")
        assert result is True

    def test_check_safe_api_usage_eval(self):
        """eval 的安全替代检测"""
        lines = ['const data = JSON.parse(input)']
        result = self.filter._check_safe_api_usage(lines, "js.injection.eval")
        assert result is True

    def test_check_safe_api_usage_none(self):
        """无安全替代"""
        lines = ['eval(userInput)']
        result = self.filter._check_safe_api_usage(lines, "js.injection.eval")
        assert result is False

    def test_check_input_validation(self):
        """输入校验检测"""
        lines = ['const id = parseInt(userInput)', 'if (isNaN(id)) return']
        result = self.filter._check_input_validation(lines)
        assert result is True

    def test_check_pattern(self):
        """模式匹配"""
        assert self.filter._check_pattern("element.innerHTML = x", r"\.innerHTML\s*=")
        assert not self.filter._check_pattern("element.textContent = x", r"\.innerHTML\s*=")

    def test_get_rule_category_from_rule_id(self):
        """从规则ID获取类别"""
        assert self.filter._get_rule_category("js.xss.innerhtml") == "xss"
        # injection 包含在 eval 之前，所以匹配 injection
        assert self.filter._get_rule_category("js.injection.eval") in ("eval", "injection")
