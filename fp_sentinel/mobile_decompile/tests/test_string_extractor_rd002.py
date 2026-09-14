# -*- coding: utf-8 -*-
"""RD-002 回归测试 —— 字符串提取对孤立 DEX 字面量的启发式覆盖。

覆盖:
- 确认级（confirmed）: key=value 结构化形态仍走 PATTERNS;
- 候选级（candidate）: 32-hex AES key / JWT / PEM / sk- 前缀 / 密码字面量 /
  base64 token 等孤立字面量能被启发式命中（Round 1 的结构性失效点）;
- 误报控制: URL / 类型描述符 / 普通词不被提取;
- --pattern 正则过滤作用于提取值（CLI 行为）;
- InsecureBankv2 实测: 敏感字符串 >= 5。
"""

from __future__ import annotations

import pytest

from fp_sentinel.mobile_decompile.output.string_extractor import (
    StringCategory,
    StringExtractor,
)

from . import INSECURE_BANK_APK, requires_insecure_bank


@pytest.fixture(scope="module")
def extractor() -> StringExtractor:
    return StringExtractor()


class TestConfirmedLevel:
    def test_key_value_password(self, extractor):
        hit = extractor.classify('password = "Sup3rS3cret!"')
        assert hit is not None
        assert hit.evidence_level == "confirmed"

    def test_key_value_api_key(self, extractor):
        hit = extractor.classify("api_key=AbCdEf123456")
        assert hit is not None and hit.evidence_level == "confirmed"

    def test_to_dict_contains_evidence_level(self, extractor):
        hit = extractor.classify('token = "abcdef123456"')
        assert hit is not None
        d = hit.to_dict()
        assert d["evidence_level"] == "confirmed"


class TestCandidateLiterals:
    """孤立字面量（DEX 字符串池形态，无赋值上下文）。"""

    @pytest.mark.parametrize("literal,category", [
        ("a3f8d21e90b74c568d1e77f0a2b4c9d1", StringCategory.AES_KEY),   # 32 hex
        ("5f1b3c9a2d7e4806b1f4a8c2d6e0937415fa2b8c", StringCategory.SECRET),  # 40 hex
        ("sk-live-9f8e7d6c5b4a3210fedcba9876543210", StringCategory.API_KEY),
        ("ghp_16C7e42F292c6912E7710c838347Ae178B4a", StringCategory.API_KEY),
        ("AIzaSyD-9tJqS2xK8pQv3mN0wL5hG1cZ4bX6yE", StringCategory.API_KEY),
    ])
    def test_known_forms(self, extractor, literal, category):
        hit = extractor.classify(literal)
        assert hit is not None, f"孤立字面量未命中: {literal}"
        assert hit.category is category
        assert hit.evidence_level == "candidate"

    def test_jwt(self, extractor):
        jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
               ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
               ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")
        hit = extractor.classify(jwt)
        assert hit is not None
        assert hit.category is StringCategory.JWT

    def test_pem_block(self, extractor):
        pem = ("-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA7\\n"
               "-----END RSA PRIVATE KEY-----")
        hit = extractor.classify(pem)
        assert hit is not None and hit.evidence_level == "candidate"

    def test_password_root_literal(self, extractor):
        hit = extractor.classify("Password@SuperSecure123")
        assert hit is not None
        assert hit.category is StringCategory.SECRET

    def test_sensitive_strings_on_real_apk(self):
        """InsecureBankv2 实测: 敏感字符串 >= 5（验收标准）。"""
        if INSECURE_BANK_APK is None:
            pytest.skip("InsecureBankv2.apk 不在测试靶场")
        from fp_sentinel.mobile_decompile.parsers.dex_parser import get_dex_parser

        parser = get_dex_parser(str(INSECURE_BANK_APK))
        ext = StringExtractor(source=str(INSECURE_BANK_APK))
        results = ext.extract(parser.strings())
        sensitive = [r for r in StringExtractor.sensitive_only(results)]
        assert len(sensitive) >= 5, f"敏感字符串仅 {len(sensitive)} 条"
        assert any(r.evidence_level == "candidate" for r in sensitive)


class TestFalsePositiveControl:
    _CREDENTIAL_CATEGORIES = {
        StringCategory.TOKEN, StringCategory.SECRET, StringCategory.API_KEY,
        StringCategory.AES_KEY, StringCategory.JWT,
    }

    @pytest.mark.parametrize("benign", [
        "https://api.example.com/v1/login",       # URL/ENDPOINT 可提取, 但不是凭证
        "Ljava/util/zip/CRC32;",                  # 类型描述符
        "com.android.insecurebankv2.MainActivity",  # 包名可提取, 但不是凭证
        "just a plain sentence",
    ])
    def test_benign_not_credential(self, extractor, benign):
        hit = extractor.classify(benign)
        if hit is not None:
            assert hit.category not in self._CREDENTIAL_CATEGORIES, (
                f"{benign} 被误判为凭证: {hit.category}")

    def test_short_and_plain_skipped(self, extractor):
        assert extractor.classify("ok") is None
        assert extractor.classify("ab") is None


class TestPatternFilter:
    def test_extract_then_filter_by_regex(self):
        ext = StringExtractor()
        import re

        values = [
            "password=Secret123",
            "a3f8d21e90b74c568d1e77f0a2b4c9d1",
            "https://api.example.com",
        ]
        results = ext.extract(values)
        rx = re.compile(r"password|api_key", re.IGNORECASE)
        matched = [r for r in results if rx.search(r.value)]
        assert matched and all("password" in r.value.lower() for r in matched)
