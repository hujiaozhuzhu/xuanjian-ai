# -*- coding: utf-8 -*-
"""mobile_hook 测试共享 fixtures。

测试全部基于 StaticApkContext（纯数据上下文），不依赖真实 APK 与设备；
真实 APK（InsecureBankv2）的集成验证由 test_integration_apk.py 承担，
仅当设置环境变量 FP_SENTINEL_INTEGRATION_APK 时运行。
"""

from __future__ import annotations

import pytest

from fp_sentinel.mobile_hook.core.apk_context import StaticApkContext

# ────────────────────────── 合成样本数据 ──────────────────────────

PKG = "com.demo.bank"

SAMPLE_CONTEXT_DATA = {
    "apk_path": "fake/demo-bank.apk",
    "package_name": PKG,
    "entry_points": [
        f"{PKG}.MainActivity",
        f"{PKG}.LoginReceiver",
    ],
    "classes": [
        {
            "name": f"{PKG}.MainActivity",
            "superclass": "android.app.Activity",
            "methods": [
                {
                    "name": "onCreate",
                    "descriptor": "(Landroid/os/Bundle;)V",
                    "strings": ["登录", "http://api.demo.bank/login"],
                    "invokes": [
                        [f"{PKG}.CryptoUtil", "encrypt"],
                        ["android.widget.Toast", "makeText"],
                    ],
                },
            ],
        },
        {
            "name": f"{PKG}.CryptoUtil",
            "methods": [
                {
                    "name": "encrypt",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
                    "strings": ["AES/CBC/PKCS5Padding", "SECRET_KEY_123"],
                    "invokes": [
                        ["javax.crypto.Cipher", "doFinal"],
                        ["java.lang.String", "getBytes"],
                        ["android.util.Base64", "encode"],
                    ],
                },
                {
                    "name": "decrypt",
                    "descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
                    "strings": ["AES/CBC/PKCS5Padding"],
                    "invokes": [
                        ["javax.crypto.Cipher", "doFinal"],
                        ["android.util.Base64", "decode"],
                    ],
                },
            ],
        },
        {
            "name": f"{PKG}.RequestBuilder",
            "methods": [
                {
                    "name": "buildParams",
                    "descriptor": "(Ljava/util/Map;)Ljava/lang/String;",
                    "strings": ["token", "username"],
                    "invokes": [
                        ["java.util.HashMap", "put"],
                        ["org.json.JSONObject", "toString"],
                    ],
                },
                {
                    "name": "debugDump",
                    "descriptor": "()V",
                    "strings": ["password=", "session_token="],
                    "invokes": [["android.util.Log", "d"]],
                },
            ],
        },
        {
            "name": f"{PKG}.LoginReceiver",
            "methods": [
                {
                    "name": "onReceive",
                    "descriptor": "(Landroid/content/Context;Landroid/content/Intent;)V",
                    "strings": ["登录成功"],
                    "invokes": [
                        ["android.widget.Toast", "show"],
                        [f"{PKG}.CryptoUtil", "decrypt"],
                    ],
                },
            ],
        },
        {
            "name": f"{PKG}.Orphan",  # 无入口可达的孤立类
            "methods": [
                {
                    "name": "hiddenEncrypt",
                    "descriptor": "([B)[B",
                    "strings": ["DES"],
                    "invokes": [["javax.crypto.Cipher", "doFinal"]],
                },
            ],
        },
        # 框架类（应被包名过滤掉）
        {
            "name": "android.support.Fake",
            "methods": [
                {"name": "encrypt", "descriptor": "()V", "strings": ["AES"],
                 "invokes": []},
            ],
        },
    ],
}


@pytest.fixture()
def sample_context() -> StaticApkContext:
    return StaticApkContext(SAMPLE_CONTEXT_DATA)


@pytest.fixture()
def locator(sample_context):
    from fp_sentinel.mobile_hook.core.base import HookLocator

    return HookLocator(goal="encrypt-trace", context=sample_context)
