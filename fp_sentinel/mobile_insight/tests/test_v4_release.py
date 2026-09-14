"""v4.0 发布收尾回归测试 —— C1 前缀清单 + C2 凭证排除规则。

对应终验报告（docs/round3_expert_final_report.md）发布条件:
- C1: androidx 纳入 framework 降级名单; okhttp3./okio. 等入库前缀白名单;
      框架/库落点不得以 HIGH+ 呈现（HIGH+ 库/框架落点 = 0）;
- C2: 凭证分级器排除 UI 资源描述符、抽象名词字段、开发占位符与纯技术标识;
      superSecurePassword 基准用例不回退。
"""

from __future__ import annotations

import pytest

from fp_sentinel.mobile_insight.core.context import (
    AnalysisContext,
    classify_class,
    is_framework_class,
)
from fp_sentinel.mobile_insight.core.engine import InsightEngine
from fp_sentinel.mobile_insight.models.insight import Severity
from fp_sentinel.mobile_insight.rules.context_filters import (
    classify_credential,
    is_credential_excluded,
)
from fp_sentinel.mobile_insight.rules.storage_rules import RULES as ST


# ============================================================ C1: 前缀清单
class TestV4PrefixLists:
    def test_androidx_is_framework_tier(self):
        """androidx.* 与 android.support.* 同级 —— classify_class 返回 framework。"""
        assert classify_class("androidx.core.graphics.TypefaceCompatUtil") == "framework"
        assert classify_class("androidx.core.content.ContextCompat") == "framework"
        assert is_framework_class("androidx.core.app.ActivityCompat")

    def test_library_prefix_whitelist(self):
        """okhttp3/okio 及其他常见三方库前缀 → classify_class 返回 library。"""
        for cls in (
            "okhttp3.internal.platform.AndroidPlatform",
            "okhttp3.internal.tls.OkHostnameVerifier",
            "okio.Buffer",
            "retrofit2.Retrofit",
            "gson.JsonParser",
            "com.google.gson.Gson",
            "com.google.gson.internal.bind.TypeAdapters",
            "io.reactivex.internal.operators.ObservableObserveOn",
            "rx.internal.operators.OnSubscribeMap",
            "org.jetbrains.annotations.NotNull",
            "com.bumptech.glide.Glide",
            "com.squareup.okhttp.OkHttpClient",
            "org.chromium.base.BuildInfo",
            "com.facebook.stetho.Stetho",
            "com.tencent.bugly.BugStrategy",
            "com.umeng.analytics.MobclickAgent",
        ):
            assert classify_class(cls) == "library", cls
            assert is_framework_class(cls), cls
        # kotlin/kotlinx 属 framework 分层（同在白名单, 落点同样降级）
        assert classify_class("kotlin.jvm.internal.Intrinsics") == "framework"
        assert classify_class("kotlinx.coroutines.Dispatchers") == "framework"

    def test_business_class_not_swallowed(self):
        """业务包前缀优先, 不会被库前缀误吞。"""
        pkg = "com.android.insecurebankv2"
        assert classify_class("com.android.insecurebankv2.DoLogin", pkg) == "business"
        # com.tencent.* 非 bugly 部分不在白名单, 仍按业务/混淆判定
        assert classify_class("com.tencent.mm.ui.Foo") == "business"

    def test_library_landing_never_high_plus(self):
        """终验验收: 库落点（如 okhttp3 内部）不得以 HIGH+ 呈现。"""
        ctx = AnalysisContext(package_name="com.ovaa")
        ctx.add_strings(["superSecurePassword"])
        ctx.attribution_index = type("Idx", (), {
            "method_count": 1,
            "locate_kv": staticmethod(
                lambda ev, pkg="": ("okhttp3.internal.platform.AndroidPlatform",
                                    "api24IsCleartextTrafficPermitted")),
        })()
        ctx.attribution_available = True
        report = InsightEngine().run(ctx, target="demo")
        st007 = next(i for i in report.insights if i.rule_id == "ST-007")
        assert st007.severity.value < Severity.HIGH.value
        assert st007.classification == "library"
        assert st007.code_reference.class_name == \
            "okhttp3.internal.platform.AndroidPlatform"  # 真实落点保留


# ============================================================ C2: 凭证排除
class TestV4CredentialExclusions:
    @pytest.mark.parametrize("value", [
        # ① UI 资源描述符（终验假凭证实测样本）
        "TextInputLayout_passwordToggleContentDescription",
        "login_hint",
        "password_label",
        "btn_title",
        "my_field_text",
        "forgot_password_desc",
        "password_contentDescription",
        "passwordContentDescription",
        # ② 抽象名词字段名（终验假凭证实测样本）
        "encodedPassword",
        "hashedPassword",
        "encryptedPassword",
        "passwordHash",
        "passwordSalt",
        "passwordToggle",
        "passwordStrength",
        # ④ 纯技术标识
        "passwordAuth",
        "passwordPolicy",
        "passwordField",
        "passwordType",
        "passwordValidator",
        "passwordColonOffset",   # okhttp Headers 内部字段名（终验 OVAA 残留样本）
        "passwordOffset",
        # support 库 TextInputLayout_passwordToggle* 系列资源名（指纹demo 残留样本）
        "TextInputLayout_passwordToggleDrawable",
        "TextInputLayout_passwordToggleEnabled",
        "TextInputLayout_passwordToggleTint",
        "TextInputLayout_passwordToggleTintMode",
        "confirm_device_credential_password",
    ])
    def test_excluded_field_names_are_level0(self, value):
        assert classify_credential(value) == 0, value
        assert is_credential_excluded(value), value

    @pytest.mark.parametrize("value", [
        # ③ 开发占位符
        "<password>",
        "%s",
        "${password}",
        "{password}",
        "{{}}",
        "password=%s",
        "password=<password>",
    ])
    def test_placeholders_are_level0(self, value):
        assert classify_credential(value) == 0, value

    def test_real_credential_baseline_not_backsliding(self):
        """C2 排除规则不得误杀真实凭证（终验基准 superSecurePassword）。"""
        assert classify_credential("superSecurePassword") == 3
        assert classify_credential("password=SuperSecret123") == 3
        assert classify_credential("my_db_passwd=Abc123!@#") == 3
        assert classify_credential("mySuperSecretApiKey123") == 2
        assert classify_credential("dXNlcjpwYXNzd29yZDEyMw==") == 2
        assert not is_credential_excluded("superSecurePassword")
        # 非技术词段的修饰词组合仍是候选凭证
        assert classify_credential("Password123") == 0  # 占位符样本值
        # 非技术词段的修饰词组合仍是候选（不被复合标识符规则误杀）
        assert not is_credential_excluded("correct-horse-battery")
        assert not is_credential_excluded("verySecurePassword")
        assert classify_credential("verySecurePassword") == 3

    def test_st007_no_false_credential_on_field_names(self):
        """终验场景: 仅含资源名/字段名的上下文, ST-007 不得以 HIGH+ 触发。"""
        ctx = AnalysisContext(package_name="com.app")
        ctx.add_strings([
            "TextInputLayout_passwordToggleContentDescription",
            "encodedPassword",
            "passwordPolicy",
        ])
        rule = next(r for r in ST if r.id == "ST-007")
        evidence = rule.match(ctx)
        for ev in evidence or []:
            assert "[LEVEL3]" not in ev and "[LEVEL2]" not in ev, ev

    def test_mixed_context_real_credential_survives(self):
        """混合上下文: 假凭证被排除, 真凭证仍进入证据并保持 L3。"""
        ctx = AnalysisContext(package_name="com.app")
        ctx.add_strings([
            "TextInputLayout_passwordToggleContentDescription",
            "encodedPassword",
            "superSecurePassword",
        ])
        rule = next(r for r in ST if r.id == "ST-007")
        evidence = rule.match(ctx)
        assert evidence and "[LEVEL3]" in evidence[0]
        assert "superSecurePassword" in evidence[0]
        assert all("encodedPassword" not in e for e in evidence)
        assert all("passwordToggleContentDescription" not in e for e in evidence)
