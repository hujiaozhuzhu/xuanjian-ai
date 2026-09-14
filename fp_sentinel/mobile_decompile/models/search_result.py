"""搜索结果与关键性评分模型。

玄鉴 v4.0 能力② 反编译引擎 —— 关键字搜索（逆向核心）。
对应规划文档 2.2.3 节 SearchResult 定义，含 critical_score 关键性评分。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

# 关键性评分权重（对应规划文档 2.3.3 评分模型在反编译搜索上的落地）
W_PACKAGE = 0.30        # 包名/类名/方法名与关键字的相关性
W_METHOD_FEATURE = 0.25  # 方法/类名是否命中加密/网络等敏感特征词
W_CALL_CHAIN = 0.15    # 调用链热度（被调用次数）
W_STRING_FEATURE = 0.20  # 上下文片段中的敏感字符串特征
W_BASE = 0.10          # 基础分（历史经验项，取固定 0.5）

CRYPTO_KEYWORDS = {
    "encrypt", "decrypt", "cipher", "aes", "des", "rsa", "md5", "sha1", "sha256",
    "sha", "hmac", "sign", "base64", "secret", "crypt", "digest", "keystore",
}
NETWORK_KEYWORDS = {
    "http", "https", "url", "token", "login", "auth", "request", "response",
    "okhttp", "retrofit", "session", "cookie", "password", "passwd", "api",
    "upload", "download",
}
FEATURE_KEYWORDS = CRYPTO_KEYWORDS | NETWORK_KEYWORDS


class MatchType(str, Enum):
    """搜索匹配类型：文本 / 字符串常量 / 方法调用 / 交叉引用。"""

    TEXT = "TEXT"
    STRING = "STRING"
    CALL = "CALL"
    XREF = "XREF"


def compute_critical_score(
    keyword: str,
    class_name: str = "",
    method_name: str = "",
    code_snippet: str = "",
    call_count: int = 0,
) -> float:
    """计算搜索结果的关键性评分（0-1，越高越关键）。

    权重：包名相关性 30% + 方法特征 25% + 调用链 15% + 字符串特征 20% + 基础 10%。
    """
    k = (keyword or "").lower()
    cls = (class_name or "").lower()
    meth = (method_name or "").lower()
    snip = (code_snippet or "").lower()

    # 1. 包名/类名/方法名相关性（30%）
    if k and (k in cls or k in meth):
        pkg = 1.0
    elif k and k in snip:
        pkg = 0.6
    else:
        pkg = 0.0
    score = W_PACKAGE * pkg

    # 2. 方法/类名敏感特征（25%）
    hits = sum(1 for kw in FEATURE_KEYWORDS if kw in meth or kw in cls)
    score += W_METHOD_FEATURE * min(1.0, hits / 2.0)

    # 3. 调用链热度（15%）
    score += W_CALL_CHAIN * min(1.0, max(0, call_count) / 5.0)

    # 4. 上下文字符串特征（20%）
    if k and k in snip:
        sfeat = 1.0
    elif any(kw in snip for kw in ("http", "key", "token", "password", "secret")):
        sfeat = 0.5
    else:
        sfeat = 0.0
    score += W_STRING_FEATURE * sfeat

    # 5. 基础分（10% * 固定 0.5）
    score += W_BASE * 0.5

    return round(min(1.0, max(0.0, score)), 4)


@dataclass
class SearchResult:
    """关键字搜索结果 —— 关键代码定位的基础。"""

    keyword: str
    file_path: str
    class_name: str
    method_name: str
    line_number: int = 0
    code_snippet: str = ""
    context_before: str = ""    # 上文（向前约 20 行）
    context_after: str = ""     # 下文（向后约 20 行）
    match_type: MatchType = MatchType.TEXT
    relevance_score: float = 0.0
    critical_score: float = 0.0  # 0-1，越高越关键

    def to_dict(self) -> Dict[str, object]:
        return {
            "keyword": self.keyword,
            "file_path": self.file_path,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "context_before": self.context_before,
            "context_after": self.context_after,
            "match_type": self.match_type.value,
            "relevance_score": self.relevance_score,
            "critical_score": self.critical_score,
        }


@dataclass
class SearchOptions:
    """搜索选项。"""

    match_types: List[MatchType] = field(
        default_factory=lambda: list(MatchType)
    )
    scope: Optional[str] = None  # 类名前缀过滤，如 com.android.insecurebankv2
    limit: int = 200
    context_lines: int = 20
    case_sensitive: bool = False

    def allows(self, match_type: MatchType) -> bool:
        return match_type in self.match_types

    def in_scope(self, class_name: str) -> bool:
        if not self.scope:
            return True
        java = class_name.lstrip("L").rstrip(";").replace("/", ".")
        return java.startswith(self.scope) or class_name.startswith(self.scope)
