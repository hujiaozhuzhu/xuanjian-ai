# -*- coding: utf-8 -*-
"""KeywordEngine —— 关键字搜索引擎。

职责（对应规划文档 2.3.3 步骤 1-2）：
1. 静态预分析：按分析目标（goal）展开关键字规则库；
2. 关键字粗筛：在 ApkContext 中检索方法体字符串常量与方法调用特征，
   输出带初始证据（命中关键字、字符串特征、方法特征）的候选方法列表。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .apk_context import ApkContext, MethodInfo

# ────────────────────────── 目标关键字规则库 ──────────────────────────
# 每个 goal 对应一组规则：字符串特征 / 方法名特征 / 调用目标特征
GOAL_KEYWORDS: Dict[str, Dict[str, List[str]]] = {
    "encrypt-trace": {
        "strings": [
            "AES", "DES", "RSA", "Cipher", "SecretKey", "IvParameterSpec",
            "PBKDF2", "SHA", "MD5", "encrypt", "decrypt", "/PKCS5",
            "PKCS5Padding", "ECB", "CBC", "BASE64",
        ],
        "methods": [
            "encrypt", "decrypt", "doFinal", "init", "generateKey",
            "getBytes", "encode", "decode",
        ],
        "invokes": [
            ("javax.crypto.Cipher", "doFinal"),
            ("javax.crypto.Cipher", "getInstance"),
            ("javax.crypto.spec.SecretKeySpec", "<init>"),
        ],
    },
    "request-plaintext": {
        "strings": [
            "http://", "https://", "POST", "GET", "api/", "token", "password",
            "username", "Content-Type", "application/json", "params",
        ],
        "methods": ["intercept", "execute", "post", "get", "send", "build"],
        "invokes": [
            ("java.util.HashMap", "put"),
            ("org.json.JSONObject", "<init>"),
        ],
    },
    "signature-bypass": {
        "strings": ["sign", "signature", "md5", "sha1", "sha256", "appkey", "secret"],
        "methods": ["sign", "getSign", "verify", "checkSign", "digest", "hash"],
        "invokes": [
            ("java.security.MessageDigest", "digest"),
            ("javax.crypto.Mac", "doFinal"),
        ],
    },
    "root-detection": {
        "strings": [
            "/system/bin/su", "/system/xbin/su", "superuser", "busybox",
            "magisk", "Superuser.apk", "test-keys",
        ],
        "methods": ["isRoot", "checkRoot", "detect", "exists"],
        "invokes": [("java.io.File", "exists")],
    },
    "generic": {
        "strings": ["encrypt", "decrypt", "password", "token", "key", "login"],
        "methods": ["encrypt", "decrypt", "login", "verify", "check"],
        "invokes": [],
    },
}

# 高价值通用方法特征（critical_scorer 也会复用）
HIGH_VALUE_METHOD_PATTERNS = [
    "encrypt", "decrypt", "dofinal", "getbytes", "encode", "decode",
    "sign", "digest", "verify", "token", "secret", "init",
]

# 系统库 / 框架包前缀：候选点位应尽量落在应用自有包里
FRAMEWORK_PREFIXES = (
    "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.",
    "com.google.android.", "org.apache.http.", "okhttp3.", "okio.",
    "retrofit2.", "com.android.", "dalvik.", "libcore.",
)


@dataclass
class KeywordCandidate:
    """关键字粗筛产出的候选点位（尚未评分）。"""

    method: MethodInfo
    matched_keywords: List[str] = field(default_factory=list)     # 命中的字符串关键字
    matched_method_features: List[str] = field(default_factory=list)  # 方法名特征
    matched_invokes: List[Tuple[str, str]] = field(default_factory=list)
    strings_matched: List[str] = field(default_factory=list)      # 命中的原始字符串常量

    @property
    def class_name(self) -> str:
        return self.method.class_name


class KeywordEngine:
    """关键字搜索引擎。"""

    def __init__(self, goal: str = "generic", extra_keywords: Optional[List[str]] = None):
        self.goal = goal if goal in GOAL_KEYWORDS else "generic"
        self.extra_keywords = [k for k in (extra_keywords or []) if k]
        self._cache: Dict[str, KeywordCandidate] = {}

    # ────────────────────────── 规则访问 ──────────────────────────

    @property
    def rules(self) -> Dict[str, List[str]]:
        return GOAL_KEYWORDS[self.goal]

    @property
    def string_keywords(self) -> List[str]:
        kws = list(self.rules["strings"]) + self.extra_keywords
        # 去重保序
        return list(dict.fromkeys(kws))

    @property
    def method_keywords(self) -> List[str]:
        return list(dict.fromkeys(self.rules["methods"]))

    @property
    def invoke_targets(self) -> List[Tuple[str, str]]:
        return [(c, m) for c, m in self.rules["invokes"]]

    def match_string_keyword(self, text: str) -> Optional[str]:
        """返回 text 命中的第一个字符串关键字（大小写不敏感）。"""
        low = text.lower()
        for kw in self.string_keywords:
            if kw.lower() in low:
                return kw
        return None

    def match_method_feature(self, method_name: str) -> Optional[str]:
        """返回方法名命中的方法特征关键字。"""
        low = (method_name or "").lower()
        for kw in self.method_keywords:
            if kw.lower() in low:
                return kw
        return None

    # ────────────────────────── 检索 ──────────────────────────

    def search(
        self,
        context: ApkContext,
        package_filter: bool = True,
        limit: int = 200,
    ) -> List[KeywordCandidate]:
        """在上下文中做关键字粗筛，返回候选（按证据数量降序）。

        参数:
            context: ApkContext
            package_filter: 仅保留应用自有包的类（过滤框架库）
            limit: 候选上限（防止超大 APK 输出爆炸）
        """
        candidates: Dict[str, KeywordCandidate] = {}
        strings_set = [kw.lower() for kw in self.string_keywords]

        classes = context.classes if not package_filter else context.app_classes()
        for cls in classes.values():
            if package_filter and self.is_framework_class(cls.name):
                continue
            for m in cls.methods:
                cand = self._evaluate_method(m, strings_set)
                if cand is not None:
                    candidates[m.qualified] = cand

        ranked = sorted(
            candidates.values(),
            key=lambda c: -(
                len(c.matched_keywords)
                + len(c.matched_method_features)
                + len(c.matched_invokes)
            ),
        )
        return ranked[:limit]

    def _evaluate_method(self, m: MethodInfo, strings_set: List[str]) -> Optional[KeywordCandidate]:
        matched_kw: List[str] = []
        strings_matched: List[str] = []
        for s in m.strings:
            low = s.lower()
            for kw in strings_set:
                if kw and kw in low:
                    matched_kw.append(kw)
                    strings_matched.append(s)
        method_feature = self.match_method_feature(m.name)
        matched_invokes = [
            (c, n) for (c, n) in m.invokes if (c, n) in self.invoke_targets
        ]
        if not (matched_kw or method_feature or matched_invokes):
            return None
        return KeywordCandidate(
            method=m,
            matched_keywords=sorted(set(matched_kw)),
            matched_method_features=[method_feature] if method_feature else [],
            matched_invokes=matched_invokes,
            strings_matched=list(dict.fromkeys(strings_matched)),
        )

    # ────────────────────────── 辅助 ──────────────────────────

    @staticmethod
    def is_framework_class(class_name: str) -> bool:
        return class_name.startswith(FRAMEWORK_PREFIXES)

    @staticmethod
    def package_relevance(class_name: str, package_name: str) -> float:
        """包名相关性 0.0 ~ 1.0（critical_scorer 的包名维度基础分）。

        - 应用主包前缀完全匹配: 1.0
        - 包含主包任一包段（如 com.example）: 0.6
        - 其它: 0.1
        """
        if not package_name:
            return 0.1
        if class_name.startswith(package_name):
            return 1.0
        pkg_segments = [s for s in package_name.split(".") if s]
        for seg in pkg_segments:
            if re.search(rf"(^|\.)({re.escape(seg)})(\.|$)", class_name):
                return 0.6
        return 0.1
