"""端点敏感度分级（关键词启发式）。

根据路径及参数中的关键词对 API 端点进行敏感度分类，
输出分类维度与风险等级供下游报告与越权探测器使用。
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Tuple

from .endpoints_models import ApiEndpoint

logger = logging.getLogger(__name__)

__all__ = ["classify", "SENSITIVITY_RULES"]

#: 敏感性等级数值（越高越敏感）
_SENSITIVITY_RANK: Dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
}

# ---------------------------------------------------------------------------
# 数据驱动分类规则：category -> list[(keyword, sensitivity)]
# 命中多条时取最高敏感度
# ---------------------------------------------------------------------------
SENSITIVITY_RULES: Dict[str, List[Tuple[str, str]]] = {
    "auth": [
        ("login", "high"),
        ("logout", "high"),
        ("token", "high"),
        ("password", "high"),
        ("passwd", "high"),
        ("pwd", "high"),
        ("auth", "medium"),
        ("oauth", "high"),
        ("session", "high"),
        ("refresh_token", "high"),
        ("access_token", "high"),
        ("jwt", "high"),
        ("signin", "high"),
        ("signup", "medium"),
        ("register", "medium"),
    ],
    "user": [
        ("user", "medium"),
        ("users", "medium"),
        ("profile", "medium"),
        ("account", "medium"),
        ("member", "medium"),
        ("personal", "high"),
        ("info", "low"),
        ("avatar", "low"),
        ("nickname", "low"),
    ],
    "finance": [
        ("payment", "high"),
        ("pay", "medium"),
        ("order", "medium"),
        ("orders", "medium"),
        ("amount", "high"),
        ("balance", "high"),
        ("price", "medium"),
        ("transaction", "high"),
        ("refund", "high"),
        ("wallet", "high"),
        ("bill", "medium"),
        ("invoice", "high"),
        ("money", "high"),
        ("credit", "high"),
        ("bank", "high"),
    ],
    "admin": [
        ("admin", "high"),
        ("config", "high"),
        ("settings", "medium"),
        ("permission", "high"),
        ("role", "high"),
        ("audit", "medium"),
        ("moderate", "medium"),
        ("ban", "high"),
        ("grant", "high"),
        ("revoke", "high"),
        ("management", "medium"),
    ],
    "upload": [
        ("upload", "medium"),
        ("file", "low"),
        ("attachment", "medium"),
        ("image", "low"),
        ("media", "low"),
        ("import", "medium"),
        ("export", "medium"),
    ],
    "sensitive_data": [
        ("idcard", "high"),
        ("id_number", "high"),
        ("identity", "high"),
        ("phone", "high"),
        ("mobile", "high"),
        ("tel", "medium"),
        ("email", "medium"),
        ("secret", "high"),
        ("apikey", "high"),
        ("api_key", "high"),
        ("private_key", "high"),
    ],
}

# 高危模式：路径或参数含 token/secret/pwd/password、个人证件号、银行卡、手机号
_PATTERNS_HIGH: List[Tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?:^|[^a-zA-Z0-9])(?:token|secret|pwd|password|passwd)s?"
            r"(?:[^a-zA-Z0-9]|$)",
            re.IGNORECASE,
        ),
        "凭证关键词",
    ),
    (re.compile(r"\b\d{17}[\dXx]\b"), "证件号模式"),
    (re.compile(r"\b\d{16,19}\b"), "银行卡号模式"),
    (re.compile(r"\b1[3-9]\d{9}\b"), "手机号模式"),
]


def classify(endpoint: ApiEndpoint) -> Dict[str, object]:
    """对 API 端点进行敏感度分类。

    依据路径与 URL 中的关键词启发式规则（:data:`SENSITIVITY_RULES`）
    和 :data:`_PATTERNS_HIGH` 正则高危模式综合判定。命中多条规则时
    取最高敏感度。

    Args:
        endpoint: 待分类的 API 端点。

    Returns:
        dict: 三个键值::

            {
                "category": str,       # 匹配的最高风险分类标签
                "sensitivity": str,    # "high" / "medium" / "low"
                "reasons": list[str]   # 命中原因描述
            }
    """
    haystack: str = f"{endpoint.path} {endpoint.url}".lower()
    if not haystack.strip():
        return {"category": "unknown", "sensitivity": "low", "reasons": ["无路径信息"]}
    best_rank = 0
    best_category = "generic"
    best_reasons: List[str] = []

    # 逐规则命中
    for category, rules in SENSITIVITY_RULES.items():
        for keyword, level in rules:
            if keyword.lower() in haystack:
                rank = _SENSITIVITY_RANK.get(level, 1)
                reason = f"命中规则 [{category}] 关键词 '{keyword}' -> {level}"
                if rank > best_rank:
                    best_rank = rank
                    best_category = category
                    best_reasons = [reason]
                elif rank == best_rank and reason not in best_reasons:
                    best_reasons.append(reason)

    # 高危正则模式
    for pattern, label in _PATTERNS_HIGH:
        if pattern.search(haystack):
            reason = f"命中高危模式: {label}"
            if _SENSITIVITY_RANK["high"] > best_rank:
                best_rank = _SENSITIVITY_RANK["high"]
                best_category = "sensitive_data"
                best_reasons = [reason]
            elif _SENSITIVITY_RANK["high"] == best_rank:
                best_reasons.append(reason)
            break  # 只要命中任一高危模式即标记

    if best_rank == 0:
        return {
            "category": "generic",
            "sensitivity": "low",
            "reasons": ["未命中任何敏感规则，视为通用端点"],
        }
    sensitivity = (
        "high"
        if best_rank >= _SENSITIVITY_RANK["high"]
        else "medium"
        if best_rank >= _SENSITIVITY_RANK["medium"]
        else "low"
    )
    result = {
        "category": best_category,
        "sensitivity": sensitivity,
        "reasons": best_reasons,
    }
    logger.debug(
        "分类 %s %s -> %s (%s)", endpoint.method, endpoint.path, sensitivity, best_category
    )
    return result
