"""
组件漏洞库测试 v3.2.0
"""


import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))


class TestComponentVulns:

    def setup_method(self):
        from fp_sentinel.vuln_db.component_vulns import (
            ALL_COMPONENT_VULNS,
            COMPONENT_VULN_COUNT,
            COMPONENT_COUNT,
            get_vulns_by_component,
            get_vuln_by_cve,
            get_db_stats,
        )
        self.vulns = ALL_COMPONENT_VULNS
        self.count = COMPONENT_VULN_COUNT
        self.components = COMPONENT_COUNT
        self.get_by_comp = get_vulns_by_component
        self.get_by_cve = get_vuln_by_cve
        self.stats = get_db_stats

    def test_over_30_cves(self):
        """CVE 总数超过 30"""
        assert self.count >= 30

    def test_over_10_components(self):
        """覆盖 10+ 组件"""
        assert self.components >= 10

    def test_spring_vulns(self):
        """Spring 漏洞至少在库中"""
        spring = self.get_by_comp("Spring")
        assert len(spring) >= 4

    def test_log4j_present(self):
        """log4shell CVE-2021-44228 存在"""
        v = self.get_by_cve("CVE-2021-44228")
        assert v is not None

    def test_struts2_present(self):
        """Struts2 S2-045"""
        v = self.get_by_cve("CVE-2017-5638")
        assert v is not None

    def test_fastjson_present(self):
        """Fastjson CVE-2017-18349"""
        v = self.get_by_cve("CVE-2017-18349")
        assert v is not None

    def test_shiro_present(self):
        """Shiro CVE-2016-4437"""
        v = self.get_by_cve("CVE-2016-4437")
        assert v is not None

    def test_tomcat_ajp_present(self):
        """Tomcat Ghostcat CVE-2020-1938"""
        v = self.get_by_cve("CVE-2020-1938")
        assert v is not None

    def test_all_vulns_have_cve_id(self):
        """所有漏洞都有 CVE ID"""
        for v in self.vulns:
            assert v.cve_id and len(v.cve_id) > 3

    def test_all_vulns_have_component(self):
        for v in self.vulns:
            assert v.component and len(v.component) > 1

    def test_all_have_severity(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for v in self.vulns:
            assert v.severity in valid

    def test_db_stats(self):
        s = self.stats()
        assert s["total_cves"] >= 30
        assert s["components"] >= 10
        assert s["critical"] >= 10


class TestPayloadVariants:

    def setup_method(self):
        from fp_sentinel.attack.payload_variants import (
            count_payloads,
            count_by_category,
            ALL_PAYLOAD_VARIANTS,
        )
        self.count = count_payloads()
        self.by_cat = count_by_category()
        self.variants = ALL_PAYLOAD_VARIANTS

    def test_over_250_variants(self):
        """变异 payload 超过 250 条"""
        assert self.count >= 250

    def test_over_10_categories(self):
        """超过 10 个分类"""
        assert len(self.variants) >= 10

    def test_sqli_has_40_plus(self):
        assert self.by_cat.get("sqli_waf_bypass", 0) >= 40

    def test_xss_has_30_plus(self):
        assert self.by_cat.get("xss_waf_bypass", 0) >= 30

    def test_rce_has_25_plus(self):
        assert self.by_cat.get("rce_waf_bypass", 0) >= 25

    def test_ssrf_has_15_plus(self):
        assert self.by_cat.get("ssrf_bypass", 0) >= 15

    def test_auth_bypass_has_15_plus(self):
        assert self.by_cat.get("auth_bypass", 0) >= 15

    def test_logic_has_15_plus(self):
        assert self.by_cat.get("logic_bypass", 0) >= 15

    def test_all_have_name(self):
        for cat, items in self.variants.items():
            for item in items:
                assert "name" in item, f"Missing name in {cat}"
                assert "payload" in item or "Payload" in item
