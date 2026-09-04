"""
A1. PoC 模板库测试

验收（计划表 A 验收标准 2）：
- 模板 20+ 种齐全（计划表枚举 22 种全覆盖）
- generate(target="http://evil.com") 必须抛 UnsafeTargetError（S1 红线）
- JWT 伪造为本地 crypto（模式 B），stdlib 实现
"""

import re

import pytest

from fp_sentinel.attack.poc_templates import (
    DEFAULT_TARGET,
    POC_TEMPLATES,
    EXPECTED_VULN_TYPES,
    PocTemplate,
    UnsafeTargetError,
    assert_local,
    forge_jwt_token,
    generate_all_pocs,
    generate_poc,
    list_vuln_types,
)


class TestTemplateCompleteness:
    """模板齐全性断言"""

    def test_template_count_at_least_20(self):
        assert len(POC_TEMPLATES) >= 20

    def test_all_planned_vuln_types_present(self):
        """计划表枚举的 22 种全部存在"""
        missing = EXPECTED_VULN_TYPES - set(POC_TEMPLATES.keys())
        assert not missing, f"缺失漏洞类型: {missing}"

    def test_template_fields_complete(self):
        for vt, t in POC_TEMPLATES.items():
            assert isinstance(t, PocTemplate), vt
            assert t.cwe.startswith("CWE-"), f"{vt} 缺 CWE"
            assert t.payload_template, f"{vt} 缺 payload_template"
            assert t.safe_explanation, f"{vt} 缺 safe_explanation"
            assert t.reference_cve, f"{vt} 缺 reference_cve"

    def test_reference_cve_format(self):
        """CVE 编号格式合法（llm-prompt-injection 为 AIGC 类型允许 OWASP 引用）"""
        for vt, t in POC_TEMPLATES.items():
            if vt == "llm-prompt-injection":
                assert t.reference_cve.startswith("OWASP-")
            else:
                assert re.fullmatch(r"CVE-\d{4}-\d{4,7}", t.reference_cve), vt

    def test_textbook_payloads_only(self):
        """不含真实基础设施地址（S4）"""
        forbidden = ["http://10.", "http://192.168.", "evil.com", "attacker.cn"]
        for t in POC_TEMPLATES.values():
            text = t.payload_template + t.safe_explanation
            for f in forbidden:
                assert f not in text, f"{t.vuln_type} 含可疑地址 {f}"


class TestUnsafeTargetGuard:
    """S1 守卫：非本地目标必须被拦截"""

    @pytest.mark.parametrize("target", [
        "http://evil.com",
        "http://192.168.1.1",
        "http://10.0.0.5:8080",
        "https://example.com/api",
        "http://172.16.0.1",
        "",
    ])
    def test_external_target_raises(self, target):
        with pytest.raises(UnsafeTargetError):
            generate_poc("sqli-union", target=target)

    def test_guard_error_message(self):
        with pytest.raises(UnsafeTargetError) as exc_info:
            assert_local("http://evil.com")
        assert "S1" in str(exc_info.value)

    @pytest.mark.parametrize("target", [
        "http://127.0.0.1:3000/x",
        "http://localhost:8080",
        "http://127.0.0.1",
    ])
    def test_local_target_allowed(self, target):
        assert assert_local(target) == target

    def test_generate_all_pocs_guarded(self):
        with pytest.raises(UnsafeTargetError):
            generate_all_pocs(target="http://evil.com")


class TestPocGeneration:
    """模板填充"""

    def test_variables_filled(self):
        poc = generate_poc(
            "sqli-union",
            target="http://127.0.0.1:5000/api",
            param="id",
        )
        assert "http://127.0.0.1:5000/api" in poc.rendered
        assert "{target_url}" not in poc.rendered
        assert "{param}" not in poc.rendered

    def test_default_textbook_payload(self):
        poc = generate_poc("xss-reflected")
        assert "<script>alert(1)</script>" in poc.rendered

    def test_jwt_weak_local_crypto(self):
        poc = generate_poc("jwt-weak")
        token = forge_jwt_token("weak123")
        # JWT 三段结构
        assert len(token.split(".")) == 3
        assert token in poc.rendered
        assert poc.mode == "crypto"

    def test_forge_jwt_deterministic(self):
        t1 = forge_jwt_token("weak123")
        t2 = forge_jwt_token("weak123")
        assert t1 == t2
        t3 = forge_jwt_token("another-secret")
        assert t1 != t3

    def test_unknown_vuln_type(self):
        with pytest.raises(KeyError):
            generate_poc("no-such-type")

    def test_list_vuln_types(self):
        types = list_vuln_types()
        assert len(types) >= 20
        assert "sqli-union" in types and "llm-prompt-injection" in types
