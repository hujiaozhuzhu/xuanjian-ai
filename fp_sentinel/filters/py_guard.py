"""
Python 侧上下文窗口 guard（与 JS 侧 _suppressed_by_guard 同构，py_ 前缀独立实现避免并行冲突）

命中危险行后，取前后 PY_GUARD_WINDOW 行窗口文本，按规则 category 匹配 guard 模式；
窗口内出现安全守卫（realpath/白名单/参数化占位符等）则抑制该 finding。
"""

import re
from typing import List, Optional

# 窗口大小：命中行前后各 6 行
PY_GUARD_WINDOW = 6

# category -> guard 正则列表
PY_GUARD_PATTERNS = {
    "COMMAND_INJECTION": [
        r"\ballowed\b",
        r"\bwhitelist\b",
        r"\ballowlist\b",
        r"\bnot\s+in\b",
        r"\.split\s*\(",
        r"shlex\.quote",
        r"shell\s*=\s*False",
    ],
    "SQL_INJECTION": [
        r"%s",
        r"%d",
        r"\?\s*[,)\]]",
        r":\w+",
        r"parameterized",
        r"prepared",
        r"sqlalchemy",
    ],
    "PATH_TRAVERSAL": [
        r"os\.path\.realpath",
        r"os\.path\.abspath",
        r"\.resolve\s*\(",
        r"\.startswith\s*\(",
        r"secure_filename",
        r"path\.normalize",
    ],
    "SSRF": [
        r"\ballowed\b",
        r"\bwhitelist\b",
        r"\ballowlist\b",
        r"validate_url",
        r"\.startswith\s*\(",
    ],
    # 确定性高危：无 guard，一律放行（如 yaml.load 无 SafeLoader）
    "DESERIALIZATION": [],
}

# 确定性高危规则：即使窗口内出现疑似 guard 也不抑制
PY_DETERMINISTIC_RULES = {
    "py.deserialization.yaml",
    "py.deserialization.pickle",
}

_compiled_cache = {
    cat: [re.compile(p, re.IGNORECASE) for p in patterns]
    for cat, patterns in PY_GUARD_PATTERNS.items()
}


def py_window_text(lines: List[str], line_idx: int, window: int = PY_GUARD_WINDOW) -> str:
    """取 line_idx（0-based）前后 window 行的窗口文本"""
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window + 1)
    return "\n".join(lines[start:end])


def py_suppressed_by_guard(
    lines: List[str],
    line_idx: int,
    category: Optional[str],
    rule_id: str = "",
) -> bool:
    """
    判断命中行是否应被窗口 guard 抑制。

    Args:
        lines: 整个文件的行列表
        line_idx: 命中行索引（0-based）
        category: 规则类别（如 PATH_TRAVERSAL）
        rule_id: 规则 ID（确定性高危规则永不抑制）

    Returns:
        True 表示窗口内存在安全守卫，应抑制该 finding
    """
    if rule_id in PY_DETERMINISTIC_RULES:
        return False
    patterns = _compiled_cache.get(category or "")
    if not patterns:
        return False
    window_text = py_window_text(lines, line_idx)
    for p in patterns:
        if p.search(window_text):
            return True
    return False
