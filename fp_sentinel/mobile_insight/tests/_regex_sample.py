"""从规则正则自动生成最小命中样本(测试辅助)。

用 re._parser 解析规则 pattern, 沿语法树生成一个必然匹配的短字符串,
使 63 条规则都能在"泛化测试"中获得触发输入。
"""

from __future__ import annotations

import re

try:  # Python 3.11+ 推荐入口
    from re import _parser as _sre
    _parse = _sre.parse
except ImportError:  # pragma: no cover - 旧版本回退
    import sre_parse as _sre  # type: ignore

    _parse = _sre.parse

try:
    from re import _constants as _sre_c
except ImportError:  # pragma: no cover
    import sre_constants as _sre_c  # type: ignore


def sample_for_pattern(pattern: str) -> str:
    """生成一个匹配 pattern 的最小样本; 无法生成时抛 ValueError。"""
    tree = _parse(pattern, 0)
    out: list = _emit(tree)
    return "".join(out)


def _emit(node) -> list:
    tokens: list = []
    for op, av in node:
        tokens.extend(_emit_op(op, av))
    return tokens


def _emit_op(op, av) -> list:
    K = _sre_c
    if op is K.LITERAL:
        return [chr(av)]
    if op is K.NOT_LITERAL:
        return ["x" if av != ord("x") else "y"]
    if op is K.ANY:
        return ["a"]
    if op is K.IN:
        return [_emit_in(av)]
    if op is K.RANGE:
        return [chr(av[0])]
    if op is K.CATEGORY:
        name = str(av)
        if "CATEGORY_SPACE" in name:
            return [" "]
        if "CATEGORY_DIGIT" in name:
            return ["1"]
        if "CATEGORY_NOT_SPACE" in name:
            return ["a"]
        if "CATEGORY_NOT_WORD" in name:
            return ["-"]
        return ["a"]
    if op is K.MAX_REPEAT or op is K.MIN_REPEAT:
        lo, _hi, sub = av
        inner: list = []
        for _ in range(lo):
            inner.extend(_emit(sub))
        return inner
    if op is K.SUBPATTERN:
        return _emit(av[-1])
    if op is K.BRANCH:
        _none, branches = av
        return _emit(branches[0])
    if op is K.AT:
        return []          # ^ $ 等锚点不产生字符
    if op is K.ASSERT or op is K.ASSERT_NOT:
        return _emit(av[1])
    if op is K.GROUPREF:
        return ["a"]
    raise ValueError(f"unsupported regex op: {op}")


def _emit_in(items) -> str:
    K = _sre_c
    negated = bool(items) and items[0][0] is K.NEGATE
    if negated:
        return "x"        # 负集取常规字符
    for op, av in items:
        if op is K.LITERAL:
            return chr(av)
        if op is K.RANGE:
            return chr(av[0])
        if op is K.CATEGORY:
            return _emit_op(K.CATEGORY, av)[0]
    return "a"


def sample_for_rule(rule) -> list:
    """为规则的全部 pattern 生成命中样本列表。"""
    samples: list = []
    for pattern in rule.patterns:
        try:
            samples.append(sample_for_pattern(pattern))
        except (ValueError, re.error):
            continue
    return samples


# check 型规则所需的"伴随关键词"通用语料
SUSPECT_KIT = [
    "password", "passwd", "pwd", "token", "secret", "key", "nonce",
    "session_id", "sessionid", "http://api.example.com/path",
    "IV", "0123456789abcdef", "su", "../etc/passwd", "getExternalStorage",
    "success login", "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS", "android.permission.READ_SMS",
    "android.permission.ACCESS_FINE_LOCATION",
    'key="Abcd1234EfgH5678"', 'IV="0123456789abcdef"',
    'intent.putExtra("token", "abc123")', "putExtra",
    # ── Round 2 (RD-005): 新增规则的伴随素材 ──
    "password=SuperSecret123",          # ST-007 KV 形态
    "rawQuery", "execSQL",              # ST-009 SQL 注入 API
    "SELECT * FROM users WHERE name=",  # ST-009 SQL 关键字
    "Log.d", "android.util.Log.d",      # ST-005 日志 API
    "AES", "javax.crypto.Cipher",       # CR-007 AES 上下文
    "sendTextMessage",                  # PV-009 短信外发
    "getPackageInfo",                   # AA-006 签名校验伴随
]

# 良性语料（RD-003 误报回归样例：框架类名 / XML 命名空间 / 孤立常见词）
BENIGN_STRINGS = [
    "hello world", "com.example.app.MainActivity", "ok",
    "android.view.ActionProvider",                       # 框架类（专家误报样例）
    "xmlns:tools=http://schemas.android.com/tools",      # XML 命名空间
    "http://schemas.android.com/apk/res/android",        # 资源命名空间 URL
    "@+id/textView1",                                    # 资源 id 标记
    "signatures", "CRC32", "java.util.zip.CRC32;",       # 孤立常见词
    "tools:ignore=UnusedAttribute",                      # tools: 标记
]
