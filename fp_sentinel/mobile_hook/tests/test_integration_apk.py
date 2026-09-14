# -*- coding: utf-8 -*-
"""真实 APK 集成测试（InsecureBankv2）。

默认跳过，设置环境变量后运行::

    FP_SENTINEL_INTEGRATION_APK=path/to/InsecureBankv2.apk pytest \\
        fp_sentinel/mobile_hook/tests/test_integration_apk.py
"""

from __future__ import annotations

import os

import pytest

from fp_sentinel.mobile_hook.core.apk_context import ApkContext

APK_PATH = os.environ.get(
    "FP_SENTINEL_INTEGRATION_APK",
    r"C:\Users\lenovo\xuanjian-ai\test_apps"
    r"\2023移动安全培训：资料\3、第三阶段app漏洞"
    r"\8.Android APP组件安全之Broadcast Receiver常见风险\InsecureBankv2.apk",
)

pytestmark = pytest.mark.skipif(
    not os.path.exists(APK_PATH), reason="集成 APK 不存在，跳过真实 APK 验证"
)


@pytest.fixture(scope="module")
def real_context():
    return ApkContext.from_apk(APK_PATH)


def test_real_apk_context(real_context):
    summary = real_context.summary()
    assert summary["package_name"].startswith("com.android.insecurebank")
    assert summary["classes"] > 100


def test_real_apk_recommend(real_context):
    from fp_sentinel.mobile_hook.core.base import HookLocator

    locator = HookLocator(goal="encrypt-trace", context=real_context)
    rec = locator.recommend(top_n=10)
    assert rec.hook_points
    assert rec.package_name.startswith("com.android.insecurebank")
    table = rec.format_table(10)
    assert "com.android.insecurebank" in table
    # 加密相关类应出现在推荐中
    assert any("Crypto" in p.class_name or "encrypt" in p.method_name.lower()
               for p in rec.hook_points)


def test_real_apk_single_technique_base64(real_context):
    from fp_sentinel.mobile_hook.core.base import HookLocator

    locator = HookLocator(context=real_context)
    result = locator.execute_technique("base64")
    assert result.success
    assert result.count > 0
    script = locator._build_technique("base64").generate_frida_script(result.ranked(5))
    assert "Java.perform" in script
