# -*- coding: utf-8 -*-
"""关键字搜索引擎单元测试。"""

from __future__ import annotations

import pytest

from fp_sentinel.mobile_hook.core.keyword_engine import (
    FRAMEWORK_PREFIXES,
    GOAL_KEYWORDS,
    KeywordEngine,
)


# ────────────────────────── 规则库 ──────────────────────────

def test_goal_rules_complete():
    for goal in ("encrypt-trace", "request-plaintext", "signature-bypass",
                 "root-detection", "generic"):
        assert goal in GOAL_KEYWORDS
        rules = GOAL_KEYWORDS[goal]
        assert {"strings", "methods", "invokes"} <= set(rules)


def test_unknown_goal_falls_back():
    engine = KeywordEngine(goal="no-such-goal")
    assert engine.goal == "generic"


def test_extra_keywords_dedup():
    engine = KeywordEngine(goal="generic", extra_keywords=["myapi", "myapi", ""])
    assert engine.string_keywords.count("myapi") == 1
    assert "encrypt" in [k.lower() for k in engine.string_keywords]


# ────────────────────────── 匹配 ──────────────────────────

def test_match_string_keyword():
    engine = KeywordEngine(goal="encrypt-trace")
    assert engine.match_string_keyword("uses AES/CBC cipher") == "AES"
    assert engine.match_string_keyword("nothing here") is None


def test_match_method_feature():
    engine = KeywordEngine(goal="encrypt-trace")
    assert engine.match_method_feature("doFinalAndSave") == "doFinal"
    assert engine.match_method_feature("computeLayout") is None


def test_match_string_keyword_case_insensitive():
    engine = KeywordEngine(goal="signature-bypass")
    assert engine.match_string_keyword("AppSign") == "sign"


# ────────────────────────── 检索 ──────────────────────────

def test_search_returns_ranked_candidates(sample_context):
    engine = KeywordEngine(goal="encrypt-trace")
    candidates = engine.search(sample_context)
    assert candidates
    # 命中证据最多的排最前
    def evidence(c):
        return len(c.matched_keywords) + len(c.matched_method_features) + len(c.matched_invokes)
    evidences = [evidence(c) for c in candidates]
    assert evidences == sorted(evidences, reverse=True)
    # 证据结构
    crypto = [c for c in candidates if c.method.class_name == "com.demo.bank.CryptoUtil"]
    assert crypto
    assert crypto[0].matched_keywords or crypto[0].matched_method_features
    assert crypto[0].class_name == "com.demo.bank.CryptoUtil"


def test_search_filters_framework_classes(sample_context):
    engine = KeywordEngine(goal="generic")
    candidates = engine.search(sample_context, package_filter=True)
    assert all(not c.class_name.startswith(FRAMEWORK_PREFIXES) for c in candidates)
    # 不过滤时能包含框架类
    candidates_all = engine.search(sample_context, package_filter=False)
    assert any(c.class_name.startswith("android.") for c in candidates_all)


def test_search_limit(sample_context):
    engine = KeywordEngine(goal="generic")
    candidates = engine.search(sample_context, limit=1)
    assert len(candidates) <= 1


def test_search_no_match():
    from fp_sentinel.mobile_hook.core.apk_context import StaticApkContext

    ctx = StaticApkContext({
        "package_name": "com.clean.app",
        "entry_points": [],
        "classes": [{
            "name": "com.clean.app.Foo",
            "methods": [{"name": "bar", "descriptor": "()V",
                         "strings": ["hello"], "invokes": []}],
        }],
    })
    engine = KeywordEngine(goal="encrypt-trace")
    assert engine.search(ctx) == []


# ────────────────────────── 包名相关性 ──────────────────────────

def test_package_relevance_exact_prefix():
    assert KeywordEngine.package_relevance("com.demo.app.Crypto", "com.demo.app") == 1.0


def test_package_relevance_segment_match():
    score = KeywordEngine.package_relevance("net.other.demo.lib", "com.demo.app")
    assert score == 0.6


def test_package_relevance_no_match():
    assert KeywordEngine.package_relevance("org.foo.Bar", "com.demo.app") == 0.1


def test_package_relevance_empty_package():
    assert KeywordEngine.package_relevance("org.foo.Bar", "") == 0.1


def test_invoke_targets_property():
    engine = KeywordEngine(goal="encrypt-trace")
    assert ("javax.crypto.Cipher", "doFinal") in engine.invoke_targets


def test_is_framework_class():
    assert KeywordEngine.is_framework_class("okhttp3.OkHttpClient")
    assert not KeywordEngine.is_framework_class("com.company.app.Main")
