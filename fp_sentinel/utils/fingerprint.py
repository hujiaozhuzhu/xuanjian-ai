"""
统一指纹计算工具

三层过滤器共用的指纹算法，确保一致性。
格式: {tool}:{rule_id}:{file}:{normalized_code[:100]}
精确匹配可追加行号。
"""

import hashlib
import re
from typing import Optional


def compute_fingerprint(
    tool: str,
    rule_id: str,
    file: str,
    code: str,
    line: Optional[int] = None,
) -> str:
    """
    计算统一指纹。

    参数:
        tool: 扫描工具名称
        rule_id: 规则ID
        file: 文件路径
        code: 代码片段
        line: 行号（可选，仅用于精确匹配）

    返回:
        MD5 指纹字符串

    格式:
        无行号: {tool}:{rule_id}:{file}:{normalized_code}
        有行号: {tool}:{rule_id}:{file}:{line}:{normalized_code}
    """
    normalized_code = re.sub(r'\s+', ' ', code.strip())[:100]

    if line is not None:
        raw = f"{tool}:{rule_id}:{file}:{line}:{normalized_code}"
    else:
        raw = f"{tool}:{rule_id}:{file}:{normalized_code}"

    return hashlib.md5(raw.encode()).hexdigest()
