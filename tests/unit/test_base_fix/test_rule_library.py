"""
规则库测试 v3.2.0
测试新增框架规则库的正确性：SpringBoot、Tomcat、Vue、Openfire、Python Web
"""

import re
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def _compile_ok(pattern: str) -> bool:
    """验证正则是否可编译"""
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


# ─────────────────────── SpringBoot 规则测试 ───────────────────────

class TestSpringBootRules:
    """SpringBoot 规则库测试"""

    def setup_method(self):
        from fp_sentinel.rules.java.springboot_rules import (
            SPRINGBOOT_SECURITY_RULES,
            SPRINGBOOT_RULES_INDEX,
            SPRINGBOOT_RULE_COUNT,
            SPRINGBOOT_RULES_BY_SEVERITY,
        )
        self.rules = SPRINGBOOT_SECURITY_RULES
        self.index = SPRINGBOOT_RULES_INDEX
        self.count = SPRINGBOOT_RULE_COUNT
        self.by_severity = SPRINGBOOT_RULES_BY_SEVERITY

    def test_rule_count(self):
        """规则数量正确"""
        assert self.count > 0
        assert self.count == len(self.rules)

    def test_all_rules_have_valid_id(self):
        """所有规则都有 rule_id"""
        for rule in self.rules:
            assert rule.rule_id.startswith("springboot.")
            assert len(rule.rule_id) > 10

    def test_all_patterns_compile(self):
        """所有正则表达式可编译"""
        for rule in self.rules:
            if rule.code_pattern:
                assert _compile_ok(rule.code_pattern), \
                    f"Bad regex in {rule.rule_id}: {rule.code_pattern}"

    def test_all_rules_have_severity(self):
        """所有规则都有有效严重程度"""
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for rule in self.rules:
            assert rule.severity in valid, f"{rule.rule_id}: bad severity {rule.severity}"

    def test_all_rules_have_cwe(self):
        """所有规则都有 CWE 编号"""
        for rule in self.rules:
            assert rule.cwe.startswith("CWE-")

    def test_index_consistency(self):
        """规则索引内容一致"""
        assert len(self.index) == len(self.rules)

    def test_severity_classification(self):
        """按严重程度分类正确"""
        total_from_severity = sum(len(v) for v in self.by_severity.values())
        assert total_from_severity == len(self.rules)

    def test_spel_rules(self):
        """SpEL 注入规则存在"""
        spel_rules = [r for r in self.rules if r.category == "SPEL_INJECTION"]
        assert len(spel_rules) >= 5

    def test_actuator_rules(self):
        """Actuator 端点暴露规则存在"""
        actuator_rules = [r for r in self.rules if r.category == "ACTUATOR_EXPOSURE"]
        assert len(actuator_rules) >= 4

    def test_confidence_range(self):
        """置信度在有效范围"""
        for rule in self.rules:
            assert 0.0 <= rule.confidence <= 1.0


# ─────────────────────── Tomcat 规则测试 ───────────────────────

class TestTomcatRules:
    """Tomcat 规则库测试"""

    def setup_method(self):
        from fp_sentinel.rules.java.tomcat_rules import (
            TOMCAT_SECURITY_RULES,
            TOMCAT_RULE_COUNT,
        )
        self.rules = TOMCAT_SECURITY_RULES
        self.count = TOMCAT_RULE_COUNT

    def test_rule_count(self):
        """规则数量"""
        assert self.count >= 35

    def test_all_patterns_compile(self):
        """正则可编译"""
        for rule in self.rules:
            if rule.code_pattern:
                assert _compile_ok(rule.code_pattern)

    def test_ajp_rules_exist(self):
        """AJP 幽灵猫规则存在"""
        ajp_rules = [r for r in self.rules if r.category == "AJP_GHOSTCAT"]
        assert len(ajp_rules) >= 3

    def test_ssl_rules_exist(self):
        """SSL 配置规则存在"""
        ssl_rules = [r for r in self.rules if r.category == "SSL_TLS_MISCONFIG"]
        assert len(ssl_rules) >= 4

    def test_all_have_rule_id(self):
        for rule in self.rules:
            assert rule.rule_id.startswith("tomcat.")


# ─────────────────────── Vue 规则测试 ───────────────────────

class TestVueRules:
    """Vue.js 规则库测试"""

    def setup_method(self):
        from fp_sentinel.rules.js.vue_rules import (
            VUE_SECURITY_RULES,
            VUE_RULE_COUNT,
        )
        self.rules = VUE_SECURITY_RULES
        self.count = VUE_RULE_COUNT

    def test_rule_count(self):
        assert self.count >= 35

    def test_all_patterns_compile(self):
        for rule in self.rules:
            if rule.code_pattern:
                assert _compile_ok(rule.code_pattern)

    def test_ssr_rules_exist(self):
        """SSR 规则存在"""
        ssr = [r for r in self.rules if r.category == "VUE_SSR"]
        assert len(ssr) >= 3

    def test_router_rules_bypass_exist(self):
        """路由绕过规则存在"""
        routing = [r for r in self.rules if r.category == "VUE_ROUTING"]
        assert len(routing) >= 4


# ─────────────────────── Openfire 规则测试 ───────────────────────

class TestOpenfireRules:
    """Openfire 规则库测试"""

    def setup_method(self):
        from fp_sentinel.rules.java.openfire_rules import (
            OPENFIRE_SECURITY_RULES,
            OPENFIRE_RULE_COUNT,
        )
        self.rules = OPENFIRE_SECURITY_RULES
        self.count = OPENFIRE_RULE_COUNT

    def test_rule_count(self):
        assert self.count >= 35

    def test_all_patterns_compile(self):
        for rule in self.rules:
            if rule.code_pattern:
                assert _compile_ok(rule.code_pattern)

    def test_db_rules_exist(self):
        """数据库配置规则"""
        db = [r for r in self.rules if r.category == "OPENFIRE_DB"]
        assert len(db) >= 3

    def test_ldap_rules_exist(self):
        """LDAP 规则"""
        ldap = [r for r in self.rules if r.category == "OPENFIRE_LDAP"]
        assert len(ldap) >= 4


# ─────────────────────── Python Web 规则测试 ───────────────────────

class TestPythonWebRules:
    """Python Web 框架规则库测试"""

    def setup_method(self):
        from fp_sentinel.rules.python.web_framework_rules import (
            PYWEB_SECURITY_RULES,
            PYWEB_RULE_COUNT,
        )
        self.rules = PYWEB_SECURITY_RULES
        self.count = PYWEB_RULE_COUNT

    def test_rule_count(self):
        assert self.count >= 45

    def test_all_patterns_compile(self):
        for rule in self.rules:
            if rule.code_pattern:
                assert _compile_ok(rule.code_pattern)

    def test_django_rules(self):
        django = [r for r in self.rules if r.category == "DJANGO_SECURITY"]
        assert len(django) >= 8

    def test_flask_rules(self):
        flask = [r for r in self.rules if r.category == "FLASK_SECURITY"]
        assert len(flask) >= 8

    def test_fastapi_rules(self):
        fastapi = [r for r in self.rules if r.category == "FASTAPI_SECURITY"]
        assert len(fastapi) >= 6


# ─────────────────────── 全量总数验证 ───────────────────────

class TestTotalRuleCount:
    """验证全量规则总数 300+"""

    def test_total_over_300(self):
        """跨所有规则库总数超过300（含基础语言规则）"""
        from fp_sentinel.rules.java.springboot_rules import SPRINGBOOT_RULE_COUNT
        from fp_sentinel.rules.java.tomcat_rules import TOMCAT_RULE_COUNT
        from fp_sentinel.rules.java.openfire_rules import OPENFIRE_RULE_COUNT
        from fp_sentinel.rules.js.vue_rules import VUE_RULE_COUNT
        from fp_sentinel.rules.python.web_framework_rules import PYWEB_RULE_COUNT
        from fp_sentinel.rules.python.rules import PYTHON_SECURITY_RULES
        from fp_sentinel.rules.go.rules import GO_SECURITY_RULES
        from fp_sentinel.rules.js.rules import JS_SECURITY_RULES

        total = (
            SPRINGBOOT_RULE_COUNT
            + TOMCAT_RULE_COUNT
            + OPENFIRE_RULE_COUNT
            + VUE_RULE_COUNT
            + PYWEB_RULE_COUNT
            + len(PYTHON_SECURITY_RULES)
            + len(GO_SECURITY_RULES)
            + len(JS_SECURITY_RULES)
        )
        assert total >= 300, f"Total {total} < 300"
