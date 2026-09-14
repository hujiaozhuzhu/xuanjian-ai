"""规则级证据提取辅助（RD-003/RD-005 + Round 3 NEW-01 凭证分级）。

从信号池中提取"可归因"的凭证/密钥字面量证据:
- key=value 形态（确认级，源码/资源文本场景）;
- 孤立字面量形态（候选级，DEX 字符串池场景 —— DEX 中每个字符串都是
  孤立字面量，不存在赋值上下文）。

Round 3（NEW-01 凭证证据分级）: ST-007 的 CRITICAL 必须引用真实凭证，
HTTP 头名/常量名/URL 路径一律排除。``classify_credential`` 对每条候选
字符串给出证据等级:

- LEVEL 3 (CRITICAL): 口令词根（password/passwd/pwd）的 key=value 赋值
  （值需为明文且非占位符），或含口令词根的非排除形态字面量
  （如 ``superSecurePassword``）;
- LEVEL 2 (HIGH): Base64 解码后含 password/secret/token 关键词的结果;
- LEVEL 1 (MEDIUM): 已知密钥前缀（sk-、pk_、ghp_、AIza、Bearer、eyJ…）;
- LEVEL 0: 其他 —— 不触发 CRITICAL，也不进入证据。

排除规则（NEW-01.3）: HTTP 方法名、HTTP 头名（X-*/Content-*/Authorization…）、
URL 路径片段、单个单词、纯大写常量、CRC/MD5/SHA 等哈希常量、包名/类型描述符。
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import List, Optional, Tuple

# ── CR-007 硬编码加密密钥判定素材 ──
# key/secret 赋值形态（确认级）
_KV_KEY_MATERIAL_RE = re.compile(
    r"(?i)\b(key|secret|aes[_-]?key)\b[^\n]{0,40}[\"'][A-Za-z0-9+/=_-]{12,}[\"']"
)
# Cipher 变换串 / Padding 指示 AES 上下文
_AES_CONTEXT_RE = re.compile(r"AES/|PKCS5|PKCS7", re.IGNORECASE)
# 16/24/32 字节 base64 形态密钥 / 32 位 hex
_B64_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{16,44}={0,2}$")
_HEX_KEY_RE = re.compile(r"^[0-9a-fA-F]{32}$")

# key=value 形态（确认级）
_KV_CRED_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b\s*[:=]\s*"
    r"[\"']?([A-Za-z0-9_@#$%!?*+=./-]{4,64})"
)
# 口令词根（仅口令族给 LEVEL 3; token/key 词根噪声更大）
_PWD_ROOT_RE = re.compile(r"(?i)(password|passwd|pwd)")
# 方法名/动作动词风格的驼峰标识符（resetPassword/getToken/updateSecret/
# verifyCredentials…）—— 是动作不是凭证。注意 superSecurePassword 不以
# 任何动词开头, 不受此守卫影响。
_METHOD_NAME_NOISE_RE = re.compile(
    r"^(?:get|set|is|has|do|on|reset|change|verify|check|validate|update"
    r"|save|clear|remove|enter|confirm|encrypt|decrypt|hash|show|hide|send"
    r"|repeat|type|compare|load|store|read|write|prompt|require|forgot)[A-Z]"
)

# ---------------------------------------------------------------------------
# NEW-01: 排除规则 —— 这些形态永不作为凭证证据
# ---------------------------------------------------------------------------
_HTTP_METHODS = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE",
    "CONNECT",
}
# HTTP 头名: X-* / Content-* / Authorization / Accept-* / User-Agent …
_HTTP_HEADER_RE = re.compile(
    r"^(?:X-[A-Za-z-]+|Content-[A-Za-z-]+|Accept(?:-[A-Za-z-]+)*"
    r"|Authorization|User-Agent|Cookie|Set-Cookie|Cache-Control|Referer|Origin"
    r"|Host|If-[A-Za-z-]+|Last-Modified|ETag)$",
    re.IGNORECASE,
)
# URL 路径片段 / 完整 URL
_URL_PATH_RE = re.compile(r"^/|^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
# 纯大写常量名（CREDENTIALS_API / MAX_PASSWORD_LENGTH）
_UPPER_CONST_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
# 哈希/摘要算法常量（CRC32 / MD5 / SHA-256 / SHA256 / HMAC-SHA1 …）
_HASH_CONST_RE = re.compile(
    r"^(?:[A-Za-z]*[-_]?)?(?:CRC-?\d*|MD[456]|SHA-?\d+(?:\.\d+)?|HMAC(?:-?SHA-?\d+)?"
    r"|BLAKE2[bs]\d*|RIPEMD\d*|Keccak-?\d*|checksum|digest)$",
    re.IGNORECASE,
)
# 包名 / java 类名 / 类型描述符
_PACKAGE_LIKE_RE = re.compile(
    r"^(?:L?[a-z][a-z0-9_]*(?:\.[A-Za-z0-9_$]+)+;?|L[a-zA-Z0-9_$/]+;)$"
)
# R3.1 NEW-01 补课: DEX 描述符变体 —— 斜杠形态无分号结尾
# （Lcom/google/.../zzd）、数组前缀（[Landroid/.../Token;）、泛型
# （Lcom/.../BatchResultToken<TR;>;）。含 "/" 或以 "L"+";" 结尾的
# 无空格串即视为类型描述符，不参与凭证判定。
_DEX_DESCRIPTOR_RE = re.compile(
    r"^(?:\[+L|L)[A-Za-z0-9_$/<>;,()]+\[*$"
)
# R3.1 NEW-01 补课: 源码/资源文件名（ChangePassword.java / strings.xml）
_FILE_NAME_RE = re.compile(
    r"^[^\s]+\.(?:java|kt|kts|class|xml|so|jar|aar|json|js|ts|php|py|gradle"
    r"|properties|html|cpp|c|h|cs|swift|rb|go|rs|dex|yml|yaml|ini|cfg|md|txt)$",
    re.IGNORECASE,
)
# R3.1 NEW-01 补课: 多驼峰 PascalCase 类名（RequestChangePasswordTask /
# CredentialsApi）。≥2 个驼峰段 —— 单驼峰真凭证（Password123）不受影响。
_PASCAL_CLASS_RE = re.compile(r"^[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+\d*$")
# R3.1 NEW-01 补课: 下划线蛇形标识符（Password_Text / password_text）。
# 限定全字母段+短长度，避免误杀含 '_' 的 URL-safe Base64 令牌。
_SNAKE_IDENT_RE = re.compile(r"^[A-Za-z]+(?:_[A-Za-z]+)+$")
# R3.1 NEW-01 补课: 点分大写常量引用（Auth.CREDENTIALS_API）
_DOTTED_CONST_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Z][A-Z0-9_]*)+$")

# ---------------------------------------------------------------------------
# v4.0 C2（终验报告 §3.3/§6.2）: 凭证分级器补课 —— 资源名/字段名/占位符形态
# 的假凭证（TextInputLayout_passwordToggleContentDescription、encodedPassword
# 等）降为 LEVEL 0 或不触发。
# ---------------------------------------------------------------------------
# ① UI 资源描述符后缀: *_contentDescription/*_hint/*_label/*_title/*_text/*_desc
#    （要求下划线/连字符边界, 避免误杀含空格的散文或普通词尾）
_UI_RESOURCE_SUFFIX_RE = re.compile(
    r"(?:^|[_-])(?:content_?description|hint|label|title|text|desc|description)$",
    re.IGNORECASE,
)
# ② 口令词根家族（复合标识符判定用）
_PWD_FAMILY = frozenset({"password", "passwd", "pwd"})
# ③ 复合标识符中的技术/抽象词段 —— 口令词根 + 技术词段 = 字段名/资源名, 不是凭证。
#    注意: "super"/"secure"/"strong" 等修饰词不在表内, 真实口令
#    （superSecurePassword）不受影响。
_CRED_TECH_TOKENS = frozenset({
    # UI/资源结构
    "field", "input", "edittext", "edit", "view", "layout", "widget",
    "text", "label", "title", "hint", "prompt", "desc", "description",
    "content", "contentdescription", "icon", "tooltip", "message", "error",
    # 存储/密码学抽象
    "hash", "hashed", "salt", "salted", "encoded", "encrypted", "decrypted",
    "obfuscated", "plain", "plaintext", "digest", "key",
    # 认证/校验技术标识
    "toggle", "strength", "policy", "auth", "type", "mask", "masked",
    "visibility", "visible", "match", "mismatch", "confirm", "confirmation",
    "rule", "rules", "pattern", "regex", "length", "min", "max",
    "minlength", "maxlength",
    # 工程/配置标识
    "config", "option", "options", "param", "params", "attribute", "attr",
    "prop", "props", "manager", "helper", "handler", "provider", "service",
    "util", "utils", "checker", "check", "validator", "validation",
    "validate", "generator", "encoder", "decoder", "value", "resource",
    "string",
    # 协议/编码/索引类技术词（okhttp Headers.passwordColonOffset 等）
    "colon", "offset", "prefix", "suffix", "separator", "index", "count",
    "size", "start", "end", "name", "header", "url", "host", "port", "path",
    "scheme", "charset", "byte", "bytes", "char", "chars", "limit", "buffer",
    "stream", "reader", "writer", "encode", "decode", "base64", "utf",
    "ascii", "hex", "binary", "json", "xml", "http", "https", "domain",
    "timestamp", "nonce", "version",
    # UI 属性/资源词（support 库 TextInputLayout_passwordToggle* 系列等）
    "drawable", "enabled", "disabled", "tint", "mode", "background",
    "foreground", "color", "colors", "style", "theme", "anim", "animation",
    # 认证上下文词（confirm_device_credential_password 等 Android 常量）
    "device", "credential", "credentials", "login", "signin",
    "supports", "support",
})


def _compound_tech_identifier(v: str) -> bool:
    """v4.0 C2: 驼峰/蛇形复合标识符判定。

    形如 ``encodedPassword`` / ``passwordHash`` / ``passwordPolicy`` /
    ``TextInputLayout_passwordToggleContentDescription`` 的字符串是字段名
    或资源名, 不是凭证值。判定: 全串为标识符形态（无空格/无赋值符号）,
    按驼峰/蛇形切分后至少一段为口令词根, 且其余段全部是技术/抽象词。
    """
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", v):
        return False
    segs = [
        s.lower()
        for s in re.split(
            r"[_\-]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", v
        )
        if s
    ]
    if not any(s in _PWD_FAMILY for s in segs):
        return False
    others = [s for s in segs if s not in _PWD_FAMILY]
    return bool(others) and all(s in _CRED_TECH_TOKENS for s in others)

# 通用单词（含单复数/变体）——单独出现不是凭证
_GENERIC_WORDS = {
    "password", "passwords", "passwd", "pwd", "secret", "secrets", "token",
    "tokens", "credential", "credentials", "apikey", "api_key", "api-key",
    "key", "keys", "auth", "login", "username", "user", "pass",
}
# 占位符值（明文占位不算真实凭证）
_PLACEHOLDER_VALUE_RE = re.compile(
    r"^(?:\$\{[^}]*\}|<[a-z_ -]+>|\*+|x+|\.+|_+"
    # v4.0 C2: 开发占位符 —— %s/%d 等格式化符、{...}/{{}} 模板占位
    r"|%[a-z]|\{+[^{}]*\}+"
    r"|(?:change|fix|replace|your|my|enter|new|old|default|dummy|fake|sample|test)[-_ ]?"
    r"(?:me|it|this)?[-_ ]?(?:me|it|this)?"
    r"|changeme|change_me|todo|fixme|placeholder|example|password123|123456"
    r"|qwerty|letmein|admin|nimda|toor|root|test|abcd{2,}|-+)$",
    re.IGNORECASE,
)
# v4.0 C2: 赋值右侧为开发占位符的 key=value 形态（含 <4 字符短占位如 %s）
_KV_PLACEHOLDER_TAIL_RE = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|token|credential|api[_-]?key)\b\s*[:=]\s*"
    r"(?:%[a-z]|\$\{[^}]*\}|\{+[^{}]*\}+|<[a-z_ -]+>|\*+|_+)\s*$"
)
# 已知密钥/令牌前缀（LEVEL 1）
_KNOWN_PREFIXES: Tuple[Tuple[str, int], ...] = (
    ("sk-", 1), ("pk_", 1), ("pk_live_", 1), ("rk_live_", 1),
    ("ghp_", 1), ("gho_", 1), ("ghu_", 1), ("ghs_", 1), ("github_pat_", 1),
    ("AIza", 1), ("AKIA", 1),
    ("xoxb-", 1), ("xoxp-", 1), ("xoxa-", 1),
    ("glpat-", 1), ("shpat_", 1), ("dop_v1_", 1), ("sq0atp-", 1),
    ("ya29.", 1), ("AGPA", 1), ("Bearer ", 1), ("eyJ", 1),
)

# Base64 形态（供 LEVEL 2 解码判定）
_B64_STRICT_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
_B64URL_STRICT_RE = re.compile(r"^[A-Za-z0-9_-]{16,}={0,2}$")
_B64_KEYWORD_RE = re.compile(r"(?i)(password|passwd|pwd|secret|token|credential)")


def is_credential_excluded(value: str) -> bool:
    """NEW-01 排除规则: True 表示该字符串永不作为凭证证据。"""
    v = value.strip().strip("\"'")
    if not v or len(v) > 512:
        return True
    if v.upper() in _HTTP_METHODS:
        return True
    if _HTTP_HEADER_RE.match(v):
        return True
    if _URL_PATH_RE.match(v):
        return True
    if _UPPER_CONST_RE.match(v):
        return True
    if _FILE_NAME_RE.match(v):
        return True
    if _PASCAL_CLASS_RE.match(v):
        return True
    if _SNAKE_IDENT_RE.match(v) and len(v) <= 32 and "=" not in v:
        return True
    if _DOTTED_CONST_RE.match(v):
        return True
    if _HASH_CONST_RE.match(v):
        return True
    if _PACKAGE_LIKE_RE.match(v):
        return True
    if _DEX_DESCRIPTOR_RE.match(v) and "/" in v:
        return True
    if v.lower() in _GENERIC_WORDS:
        return True
    # v4.0 C2: UI 资源描述符 / 复合技术标识符（字段名/资源名, 非凭证值）
    if " " not in v and _UI_RESOURCE_SUFFIX_RE.search(v):
        return True
    if _compound_tech_identifier(v):
        return True
    return False


def _b64_decode(value: str) -> Optional[str]:
    try:
        pad = value + "=" * (-len(value) % 4)
        raw = base64.b64decode(pad, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or sum(1 for c in text if c.isprintable()) / len(text) < 0.9:
        return None
    return text


def classify_credential(value: str) -> int:
    """NEW-01 凭证证据分级: 返回 LEVEL 3/2/1/0。"""
    v = value.strip().strip("\"'")
    if not v or len(v) > 512:
        return 0
    if is_credential_excluded(v):
        return 0
    if _PLACEHOLDER_VALUE_RE.match(v):
        return 0
    # v4.0 C2: 赋值右侧为开发占位符（含短占位 %s/{{...}}）→ 不算真实凭证
    if _KV_PLACEHOLDER_TAIL_RE.search(v):
        return 0

    # 1) key=value 赋值形态优先（源码行/资源文本可含空格）:
    #    口令词根 → L3; 其他敏感词根 → L2; 占位符值 → L0
    m = _KV_CRED_RE.search(v)
    if m:
        value_part = m.group(2)
        if _PLACEHOLDER_VALUE_RE.match(value_part):
            return 0
        level = 3 if _PWD_ROOT_RE.search(m.group(1)) else 2
        # 值形态合理性: 纯小写字母词（无数字/符号/驼峰）降一级（NEW-01.③）
        if value_part.isalpha() and value_part.lower() == value_part:
            level = max(level - 1, 1)
        return level

    # 2) 已知密钥前缀 → L1（须在散文/空格排除之前: "Bearer xxx" 含空格但是真凭证）
    for prefix, level in _KNOWN_PREFIXES:
        if v.startswith(prefix) and len(v) > len(prefix) + 4:
            return level

    # 散文/句子（含空格）不是孤立凭证字面量（KV/已知前缀形态除外）
    if " " in v:
        return 0

    # 3) 含口令词根的孤立字面量（如 superSecurePassword）→ L3;
    #    token/secret 词根 → L2。要求: 无空格、6~64 长度、非纯小写单词
    #    （排除散文与普通标识符），且非驼峰 getter/属性风格。
    if 6 <= len(v) <= 64:
        # 方法名/动作动词风格（resetPassword/getToken/updateSecret）不是凭证
        if _METHOD_NAME_NOISE_RE.match(v):
            return 0
        if _PWD_ROOT_RE.search(v):
            return 3
        if re.search(r"(?i)(secret|credential|token|api[_-]?key)", v):
            return 2

    # 4) Base64 解码后含敏感关键词 → L2
    if (_B64_STRICT_RE.match(v) or _B64URL_STRICT_RE.match(v)) and len(v) >= 20:
        decoded = _b64_decode(v)
        if decoded and _B64_KEYWORD_RE.search(decoded):
            return 2

    return 0


_LEVEL_LABELS = {3: "LEVEL3", 2: "LEVEL2", 1: "LEVEL1"}


def find_password_literals(ctx, limit: int = 5) -> List[str]:
    """提取硬编码凭证证据（NEW-01: 分级排序, LEVEL 0 不进入证据）。

    返回的每条证据带 ``[LEVELn]`` 前缀标注证据等级, 引擎据此动态调整
    ST-007 的 severity（L3→CRITICAL / L2→HIGH / L1→MEDIUM）。
    """
    scored: List[Tuple[int, str]] = []
    seen: set = set()
    # R3.1 确定性: ctx.strings 为 set，迭代序随 PYTHONHASHSEED 漂移;
    # 提前 break 会使"先遇到哪些凭证串"不可复现 —— 按字典序遍历。
    for raw in sorted(ctx.strings):
        s = str(raw).strip().strip("\"'")
        if not s or s in seen:
            continue
        seen.add(s)
        level = classify_credential(s)
        if level >= 1:
            scored.append((level, s[:160]))
    # 全序排序: 同级内按文本字典序（稳定排序的次级键不能依赖收集顺序）
    scored.sort(key=lambda t: (-t[0], t[1]))
    out = [f"[{_LEVEL_LABELS[lv]}] {text}" for lv, text in scored]
    return out[:limit]


def has_crypto_key_material(ctx) -> bool:
    """判断上下文是否存在疑似硬编码密钥素材（供 CR-007 二次确认）。

    命中任一即可:
    - key/secret 赋值形态的常量字符串（确认级）;
    - AES 变换串/Padding 存在 且 存在 16/24/32 字节 base64 或 32-hex 素材。
    """
    for raw in ctx.strings:
        s = str(raw).strip()
        if not s:
            continue
        if _KV_KEY_MATERIAL_RE.search(s):
            return True
        core = s.strip().strip("\"'")
        if _AES_CONTEXT_RE.search(s) and (_B64_KEY_RE.match(core) or _HEX_KEY_RE.match(core)):
            return True
    # 上下文同时出现 AES 变换串与裸密钥素材（两条字符串）
    has_aes_ctx = any(_AES_CONTEXT_RE.search(str(x)) for x in ctx.strings)
    if has_aes_ctx:
        for raw in ctx.strings:
            core = str(raw).strip().strip("\"'")
            if core and (_B64_KEY_RE.match(core) or _HEX_KEY_RE.match(core)):
                return True
    return False
