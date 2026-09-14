"""敏感字符串提取。

从字符串表 / 源码中提取 URL、API endpoint、Token、密钥、包名、
手机号、邮箱等高价值情报，为硬编码检测（能力⑥-D）与
API 端点画像（能力⑥-J）提供底座。

Round 2（RD-002 修复）：DEX 字符串池是孤立字面量，不存在 ``key=value``
上下文，原有的赋值类正则（TOKEN/API_KEY/AES_KEY）在 APK/DEX 场景下
永远不可能命中。现增加两层机制：

1. ``PATTERNS``（确认级 confirmed）：原 key=value 正则，仅用于源码/资源
   文本模式，命中即高置信。
2. ``LITERAL_HEURISTICS``（候选级 candidate）：面向孤立字面量的启发式
   评分 —— 32/40 位 hex、JWT、PEM、已知密钥前缀（sk-/pk_/ghp_/AIza…）、
   Base64 高熵串、敏感关键词词根等，confidence 明显低于确认级，
   并在 ``evidence_level`` 字段中标注证据等级。
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, List, Optional, Pattern


class StringCategory(str, Enum):
    """字符串情报分类。"""

    URL = "URL"
    API_ENDPOINT = "API_ENDPOINT"
    TOKEN = "TOKEN"
    API_KEY = "API_KEY"
    SECRET = "SECRET"
    AES_KEY = "AES_KEY"
    JWT = "JWT"
    PACKAGE_NAME = "PACKAGE_NAME"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    IP = "IP"
    DB_CONN = "DB_CONN"
    PLAIN = "PLAIN"


@dataclass
class ExtractedString:
    """单条提取结果。"""

    value: str
    category: StringCategory
    confidence: float  # 0-1
    source: Optional[str] = None  # 来源文件/表
    # 证据等级: confirmed=确证（key=value 等结构化形态）/
    #          candidate=候选（孤立字面量启发式，需人工确认）
    evidence_level: str = "confirmed"
    # NEW-04: 代码归因位置（"class#method" 形态）; 未归因为 None
    location: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "value": self.value,
            "category": self.category.value,
            "confidence": self.confidence,
            "source": self.source,
            "evidence_level": self.evidence_level,
            "location": self.location,
        }


def _c(pattern: str, flags: int = 0) -> Pattern:
    return re.compile(pattern, flags)


# 各分类的正则与置信度（顺序即优先级：先命中先归类）
PATTERNS: List[tuple] = [
    # JWT: 三段 base64url
    (StringCategory.JWT, _c(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0.95),
    # AWS Access Key
    (StringCategory.API_KEY, _c(r"\bAKIA[0-9A-Z]{16}\b"), 0.95),
    # 数据库连接串
    (StringCategory.DB_CONN, _c(r"\b(jdbc:(mysql|postgresql|sqlite|oracle)[^\s'\"<>]+|mongodb(\+srv)?://[^\s'\"<>]+)"), 0.9),
    # URL
    (StringCategory.URL, _c(r"\bhttps?://[^\s\"'<>\\]{4,}", re.IGNORECASE), 0.85),
    # API endpoint 路径
    (StringCategory.API_ENDPOINT, _c(r"(?:^|[\s\"'])(/(?:api|v\d|rest|service)s?/[A-Za-z0-9_./-]{2,})"), 0.7),
    # 邮箱
    (StringCategory.EMAIL, _c(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0.9),
    # 中国大陆手机号
    (StringCategory.PHONE, _c(r"\b1[3-9]\d{9}\b"), 0.85),
    # IPv4
    (StringCategory.IP, _c(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), 0.6),
    # 赋值形式的 token/secret/password
    (StringCategory.TOKEN, _c(r"(?i)\b(api[_-]?token|access[_-]?token|auth[_-]?token|token)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{10,})"), 0.8),
    (StringCategory.SECRET, _c(r"(?i)\b(app[_-]?secret|client[_-]?secret|secret[_-]?key|secret)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{8,})"), 0.8),
    (StringCategory.API_KEY, _c(r"(?i)\b(api[_-]?key|apikey|app[_-]?key)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{8,})"), 0.8),
    (StringCategory.AES_KEY, _c(r"(?i)\b(aes[_-]?key|encrypt[_-]?key|des[_-]?key|private[_-]?key)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{8,})"), 0.85),
    # 口令赋值（确认级; RD-002: key=value 结构化形态保持 confirmed 证据等级）
    (StringCategory.SECRET, _c(r"(?i)\b(pass[_-]?word|pass[_-]?wd|pwd)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=@#$%!?*]{6,})"), 0.85),
    # Java 包名（至少两段，全小写）。
    # 使用占有优先量词（Python 3.11+）防止长点分字符串上的灾难性回溯。
    (StringCategory.PACKAGE_NAME, _c(r"\b([a-z][a-z0-9_]*+(?:\.[a-z][a-z0-9_]*+){2,}+)\b"), 0.5),
]

# classify 输入长度上限：超长字符串截断后再匹配（防回溯/性能护栏）
_MAX_MATCH_LEN = 1024

# ---------------------------------------------------------------------------
# 候选级启发式（RD-002）：孤立字面量没有 key=value 上下文，按形态/词根打分。
# 每项: (说明, 判定函数, 分类, confidence)；顺序即优先级，先命中先归类。
# ---------------------------------------------------------------------------

# 已知密钥/令牌前缀（高置信候选）
_KNOWN_KEY_PREFIXES: tuple = (
    ("sk-", 0.9), ("sk_live_", 0.95), ("pk_live_", 0.9), ("rk_live_", 0.9),
    ("ghp_", 0.95), ("gho_", 0.9), ("ghu_", 0.9), ("ghs_", 0.9),
    ("github_pat_", 0.95), ("AIza", 0.95), ("AKIA", 0.95),
    ("xoxb-", 0.95), ("xoxp-", 0.95), ("xoxa-", 0.95),
    ("glpat-", 0.95), ("shpat_", 0.95), ("dop_v1_", 0.9),
    ("sq0atp-", 0.9), ("ya29.", 0.8), ("AGPA", 0.85),
)

_PEM_RE = _c(r"-----BEGIN [A-Z0-9 ]*KEY-----")
_HEX64_RE = _c(r"\A[0-9a-fA-F]{32}\Z")          # 32 字节 hex → AES-128 候选
_HEX40_RE = _c(r"\A[0-9a-fA-F]{40}\Z")          # 40 字节 hex → SHA1 摘要/密钥
_HEX32_RE = _c(r"\A[0-9a-fA-F]{16}\Z")          # 16 字节 hex → 短密钥/IV 候选
_B64_RE = _c(r"\A[A-Za-z0-9+/]{20,}={0,2}\Z")
_B64URL_RE = _c(r"\A[A-Za-z0-9_-]{20,}={0,2}\Z")
_JWT_RE = _c(r"\AeyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\Z")

# 敏感词根（孤立字面量中出现即候选证据）
_KEYWORD_GROUPS: tuple = (
    (_c(r"(?i)password|passwd|pwd"), StringCategory.SECRET, 0.6),
    (_c(r"(?i)secret|credential"), StringCategory.SECRET, 0.6),
    (_c(r"(?i)token"), StringCategory.TOKEN, 0.55),
    (_c(r"(?i)api[_-]?key|apikey"), StringCategory.API_KEY, 0.65),
    (_c(r"(?i)aes[_-]?key|encrypt[_-]?key|des[_-]?key"), StringCategory.AES_KEY, 0.65),
    (_c(r"(?i)authorization|bearer\s"), StringCategory.TOKEN, 0.55),
)

# 排除：纯键名/常见词本身不应被当成密钥候选
_EXACT_KEYWORDS = {
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
    "passwords", "secrets", "tokens", "Password", "PASSWORD", "Token",
    "Secret", "TOKEN",
}

# 明显无密钥价值的形态: 包名 / URL / 路径 / 含空格自然语句
_PACKAGE_RE = _c(r"\A[a-z][a-z0-9_]*(\.[a-zA-Z0-9_$]+){2,}\Z")
_URL_RE = _c(r"https?://", re.IGNORECASE)
# "像值的字符串"需含数字/符号（排除 password is: / , token= 等散文片段）
_VALUE_SYMBOL_RE = _c(r"[0-9@#$%!?*+./-]")
# Base64 候选需含数字/+//=（排除纯字母 CamelCase 类名, 如 AccessibilityDelegateBridge）
_BASE64_HINT_RE = _c(r"[0-9+/=]")
# 标识符形态（类名/常量名/文件名）: 不作凭证候选
_IDENTIFIER_RE = _c(r"\A[A-Za-z_$][A-Za-z0-9_$.]*\Z")
# 连续两个以上驼峰单词开头（AccessibilityNodeInfoApi21Impl）: 类名形态
_CAMEL_HEAD_RE = _c(r"\A(?:[A-Z][a-z]+){2,}")
# DEX 内部类路径形态（Landroid/support/v4/...）
_INTERNAL_PATH_RE = _c(r"\AL[a-z]+(?:/[A-Za-z0-9_$]+)+\Z")


def _shannon_entropy(value: str) -> float:
    """字符级 Shannon 熵（bit/char）。"""
    if not value:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _b64_decode_bytes(value: str) -> Optional[bytes]:
    """严格 Base64 解码（validate=True）；失败返回 None（不像 Base64）。"""
    try:
        pad = value + "=" * (-len(value) % 4)
        raw = base64.b64decode(pad, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw or None


def _b64_decode_printable(value: str) -> bool:
    """Base64 解码后是否为可读文本（用于 Token 候选判定）。"""
    raw = _b64_decode_bytes(value)
    if raw is None:
        return False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable())
    return printable / len(text) >= 0.9


def _literal_hit(value: str) -> Optional[ExtractedString]:
    """对孤立字面量做候选级启发式评分（RD-002）。"""
    stripped = value.strip().strip("'\"")
    if not stripped or len(stripped) < 4:
        return None
    v = stripped
    # DEX 类型描述符（Lcom/pkg/Cls; / [L...; 或去分号的内部类路径）不是业务字符串
    bare = v.lstrip("[")
    if (bare.startswith("L") and bare.endswith(";")) \
            or _INTERNAL_PATH_RE.match(v) or _INTERNAL_PATH_RE.match(bare):
        return None

    # 1) 已知前缀 → API_KEY
    for prefix, conf in _KNOWN_KEY_PREFIXES:
        if v.startswith(prefix) and len(v) > len(prefix) + 4:
            return ExtractedString(v, StringCategory.API_KEY, conf, None, "candidate")

    # 2) JWT 三段式
    if _JWT_RE.match(v):
        return ExtractedString(v, StringCategory.JWT, 0.9, None, "candidate")

    # 3) PEM 密钥块
    if _PEM_RE.search(v):
        return ExtractedString(v, StringCategory.SECRET, 0.9, None, "candidate")

    # 4) 形态 hex：32 字节 → AES 密钥候选；40 字节 → SHA1/密钥；16 → 短密钥/IV
    if _HEX64_RE.match(v):
        return ExtractedString(v, StringCategory.AES_KEY, 0.7, None, "candidate")
    if _HEX40_RE.match(v):
        return ExtractedString(v, StringCategory.SECRET, 0.6, None, "candidate")
    if _HEX32_RE.match(v) and _shannon_entropy(v) > 3.0:
        return ExtractedString(v, StringCategory.AES_KEY, 0.5, None, "candidate")

    # 5) 敏感词根（password/token/secret/api_key/…）——字面量本身即证据。
    #    误报控制: 纯散文/路径片段（无数字符号、以 ':'/'=' 结尾、以 '/' 开头）不算。
    _core = v.rstrip(":=\t ").rstrip()
    if v.lower() not in _EXACT_KEYWORDS and not _PACKAGE_RE.match(v) and not _URL_RE.match(v) \
            and _core and not _core.startswith("/") and " " not in _core \
            and not _IDENTIFIER_RE.fullmatch(_core) \
            and _VALUE_SYMBOL_RE.search(_core):
        for rx, category, conf in _KEYWORD_GROUPS:
            if rx.search(v) and len(v) >= 6:
                return ExtractedString(v, category, conf, None, "candidate")

    # 6) Base64 形态：必须能严格解码（非 Base64 字母表/坏 padding 直接跳过,
    #    避免框架常量名/标识符被当密钥）；解码可读 → Token，二进制 → 密钥候选。
    if (_B64_RE.match(v) or _B64URL_RE.match(v)) and not _PACKAGE_RE.match(v) \
            and _BASE64_HINT_RE.search(v) and not _CAMEL_HEAD_RE.match(v):
        if len(v) >= 24 and _shannon_entropy(v) > 3.5:
            raw = _b64_decode_bytes(v)
            if raw is None:
                return None
            if _b64_decode_printable(v):
                return ExtractedString(v, StringCategory.TOKEN, 0.6, None, "candidate")
            # 二进制解码 + 含 base64 特征符号(+//=) 才算密钥候选
            if any(c in v for c in "+/="):
                return ExtractedString(v, StringCategory.AES_KEY, 0.5, None, "candidate")
            return None

    return None


class StringExtractor:
    """字符串情报提取器。"""

    def __init__(self, source: Optional[str] = None) -> None:
        self.source = source

    def classify(self, value: str) -> Optional[ExtractedString]:
        """对单条字符串归类；无情报价值返回 None。

        优先走确认级 PATTERNS（key=value 结构化形态），未命中时回退到
        候选级孤立字面量启发式（RD-002），证据等级标注为 candidate。
        """
        if not value or len(value) < 4:
            return None
        trimmed = value if len(value) <= _MAX_MATCH_LEN else value[:_MAX_MATCH_LEN]
        for category, pattern, confidence in PATTERNS:
            m = pattern.search(trimmed)
            if not m:
                continue
            if m.groups():
                # 赋值类模式（token/password=xxx）: 保留 key=value 全文,
                # 便于 --pattern 按键名过滤; 其余取命中片段本身。
                if "[:=]" in pattern.pattern:
                    matched = m.group(0).strip()
                else:
                    matched = m.group(m.lastindex).strip().strip("'\"")
            else:
                matched = m.group(0)
            return ExtractedString(
                value=matched, category=category, confidence=confidence, source=self.source,
                evidence_level="confirmed",
            )
        hit = _literal_hit(trimmed)
        if hit is not None:
            hit.source = self.source
            return hit
        return None

    def extract(self, values: Iterable[str]) -> List[ExtractedString]:
        """批量提取（去重）。"""
        out: List[ExtractedString] = []
        seen = set()
        for v in values:
            hit = self.classify(v)
            if hit is None:
                continue
            key = (hit.category.value, hit.value)
            if key in seen:
                continue
            seen.add(key)
            out.append(hit)
        return out

    def extract_from_source(self, text: str) -> List[ExtractedString]:
        """从源码文本中提取（按行 + 带引号字符串字面量）。"""
        candidates: List[str] = []
        # 字符串字面量优先
        for m in _c(r"[\"']([^\"'\n]{4,300})[\"']").finditer(text):
            candidates.append(m.group(1))
        candidates.extend(text.splitlines())
        return self.extract(candidates)

    @staticmethod
    def sensitive_only(results: List[ExtractedString]) -> List[ExtractedString]:
        """过滤出凭证/密钥类高敏结果。"""
        sensitive = {
            StringCategory.TOKEN,
            StringCategory.API_KEY,
            StringCategory.SECRET,
            StringCategory.AES_KEY,
            StringCategory.JWT,
            StringCategory.DB_CONN,
        }
        return [r for r in results if r.category in sensitive]
