"""
Tests for the V3.1 Industry-Specific Vertical Rules

Tests: Video Surveillance (9), Instant Messaging (8), IoT (9) = 26 rules
Coverage target: >= 95%
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


class TestVerticalRulesLoaded(unittest.TestCase):
    def test_all_industries_present(self):
        from fp_sentinel.industry_rules.vertical_rules import (
            VERTICAL_RULES, list_vertical_industries,
        )
        industries = list_vertical_industries()
        self.assertIn("video_surveillance", industries)
        self.assertIn("instant_messaging", industries)
        self.assertIn("iot", industries)
        self.assertEqual(len(industries), 3)

    def test_video_surveillance_9_rules(self):
        from fp_sentinel.industry_rules.vertical_rules import VERTICAL_RULES
        rules = VERTICAL_RULES["video_surveillance"]
        self.assertEqual(len(rules), 9)

    def test_instant_messaging_8_rules(self):
        from fp_sentinel.industry_rules.vertical_rules import VERTICAL_RULES
        rules = VERTICAL_RULES["instant_messaging"]
        self.assertEqual(len(rules), 8)

    def test_iot_9_rules(self):
        from fp_sentinel.industry_rules.vertical_rules import VERTICAL_RULES
        rules = VERTICAL_RULES["iot"]
        self.assertEqual(len(rules), 9)

    def test_total_26_rules(self):
        from fp_sentinel.industry_rules.vertical_rules import count_vertical_rules
        total = count_vertical_rules()
        self.assertEqual(total, 26)


class TestVerticalRuleIds(unittest.TestCase):
    def test_video_rule_ids(self):
        from fp_sentinel.industry_rules.vertical_rules import VERTICAL_RULES
        rule_ids = [r.rule_id for r in VERTICAL_RULES["video_surveillance"]]
        self.assertIn("VS-ONVIF-AUTH-001", rule_ids)
        self.assertIn("VS-RTSP-STREAM-001", rule_ids)
        self.assertIn("VS-FIRMWARE-001", rule_ids)
        self.assertIn("VS-EDGE-GATEWAY-001", rule_ids)

    def test_im_rule_ids(self):
        from fp_sentinel.industry_rules.vertical_rules import VERTICAL_RULES
        rule_ids = [r.rule_id for r in VERTICAL_RULES["instant_messaging"]]
        self.assertIn("IM-E2E-CRYPTO-001", rule_ids)
        self.assertIn("IM-MEDIA-SANDBOX-001", rule_ids)
        self.assertIn("IM-BOT-WEBHOOK-001", rule_ids)

    def test_iot_rule_ids(self):
        from fp_sentinel.industry_rules.vertical_rules import VERTICAL_RULES
        rule_ids = [r.rule_id for r in VERTICAL_RULES["iot"]]
        self.assertIn("IOT-MQTT-AUTH-001", rule_ids)
        self.assertIn("IOT-OTA-SIGN-001", rule_ids)
        self.assertIn("IOT-ZIGBEE-SEC-001", rule_ids)


class TestVerticalRuleMandatoryFields(unittest.TestCase):
    def test_all_rules_have_severity(self):
        from fp_sentinel.industry_rules.vertical_rules import VERTICAL_RULES
        for industry, rules in VERTICAL_RULES.items():
            for rule in rules:
                self.assertIn(rule.severity, ("CRITICAL", "HIGH", "MEDIUM", "LOW"),
                              f"Rule {rule.rule_id} has invalid severity: {rule.severity}")

    def test_all_rules_have_rule_id(self):
        from fp_sentinel.industry_rules.vertical_rules import VERTICAL_RULES
        for industry, rules in VERTICAL_RULES.items():
            for rule in rules:
                self.assertTrue(len(rule.rule_id) > 0,
                                f"Rule in {industry} missing rule_id")

    def test_all_rules_have_cwe(self):
        from fp_sentinel.industry_rules.vertical_rules import VERTICAL_RULES
        for industry, rules in VERTICAL_RULES.items():
            for rule in rules:
                self.assertIsNotNone(rule.cwe,
                                     f"Rule {rule.rule_id} missing CWE")
                self.assertTrue(rule.cwe.startswith("CWE-"),
                                f"Rule {rule.rule_id} CWE format invalid: {rule.cwe}")

    def test_all_rules_have_compliance_refs(self):
        from fp_sentinel.industry_rules.vertical_rules import VERTICAL_RULES
        for industry, rules in VERTICAL_RULES.items():
            for rule in rules:
                self.assertTrue(len(rule.compliance_refs) > 0,
                                f"Rule {rule.rule_id} missing compliance_refs")

    def test_all_rules_have_tech_targets(self):
        from fp_sentinel.industry_rules.vertical_rules import VERTICAL_RULES
        for industry, rules in VERTICAL_RULES.items():
            for rule in rules:
                self.assertTrue(len(rule.tech_targets) > 0,
                                f"Rule {rule.rule_id} missing tech_targets")


class TestVerticalRuleEngine(unittest.TestCase):
    def test_get_vertical_rules(self):
        from fp_sentinel.industry_rules.vertical_rules import get_vertical_rules
        rs = get_vertical_rules("video_surveillance")
        self.assertEqual(len(rs.rules), 9)
        self.assertEqual(rs.industry, "video_surveillance")
        self.assertEqual(rs.version, "3.1.0")

    def test_get_vertical_rules_empty(self):
        from fp_sentinel.industry_rules.vertical_rules import get_vertical_rules
        rs = get_vertical_rules("nonexistent")
        self.assertEqual(len(rs.rules), 0)

    def test_get_rules_by_industry_filter(self):
        from fp_sentinel.industry_rules.vertical_rules import get_rules_by_industry
        critical_rules = get_rules_by_industry("video_surveillance", "CRITICAL")
        self.assertTrue(len(critical_rules) >= 3)
        for r in critical_rules:
            self.assertEqual(r.severity, "CRITICAL")

    def test_get_rules_by_industry_none_filter(self):
        from fp_sentinel.industry_rules.vertical_rules import get_rules_by_industry
        all_rules = get_rules_by_industry("iot")
        self.assertEqual(len(all_rules), 9)

    def test_enabled_rules_filter(self):
        from fp_sentinel.industry_rules.vertical_rules import get_vertical_rules
        rs = get_vertical_rules("iot")
        self.assertEqual(len(rs.enabled_rules), 9)

    def test_critical_high_count(self):
        from fp_sentinel.industry_rules.vertical_rules import get_vertical_rules
        rs = get_vertical_rules("video_surveillance")
        self.assertGreaterEqual(rs.critical_count, 3)
        self.assertGreaterEqual(rs.high_count, 3)


class TestVerticalRuleCategories(unittest.TestCase):
    def test_video_categories(self):
        from fp_sentinel.industry_rules.vertical_rules import VERTICAL_RULES
        categories = {r.category for r in VERTICAL_RULES["video_surveillance"]}
        self.assertIn("AUTH_BYPASS", categories)
        self.assertIn("DATA_EXPOSURE", categories)
        self.assertIn("CRYPTO_FAILURE", categories)

    def test_im_categories(self):
        from fp_sentinel.industry_rules.vertical_rules import VERTICAL_RULES
        categories = {r.category for r in VERTICAL_RULES["instant_messaging"]}
        self.assertIn("CRYPTO_FAILURE", categories)
        self.assertIn("SSRF", categories)

    def test_iot_categories(self):
        from fp_sentinel.industry_rules.vertical_rules import VERTICAL_RULES
        categories = {r.category for r in VERTICAL_RULES["iot"]}
        self.assertIn("AUTH_BYPASS", categories)
        self.assertIn("CRYPTO_FAILURE", categories)


class TestIndustryEnum(unittest.TestCase):
    def test_new_industries_in_enum(self):
        from fp_sentinel.industry_benchmark.models import Industry
        self.assertEqual(Industry.VIDEO_SURVEILLANCE.value, "video_surveillance")
        self.assertEqual(Industry.INSTANT_MESSAGING.value, "instant_messaging")
        self.assertEqual(Industry.IOT.value, "iot")

    def test_total_14_industries(self):
        from fp_sentinel.industry_benchmark.models import Industry
        self.assertEqual(len(Industry), 14)


if __name__ == "__main__":
    unittest.main()
