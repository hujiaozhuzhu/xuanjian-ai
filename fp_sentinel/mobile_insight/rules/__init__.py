"""mobile_insight.rules —— 67 条内置规则(6 类)。

目录对齐规划文档 2.4.2:
- crypto_rules        15 条
- network_rules       10 条
- storage_rules       11 条 (Round 2: ST-009; Round 3: ST-010/ST-011)
- component_rules     12 条
- anti_analysis_rules 10 条
- privacy_rules        9 条 (Round 2: 新增 PV-009 短信外发)
"""

from __future__ import annotations

from typing import List

from ..core.engine import Rule

__all__ = ["Rule", "get_all_rules", "RULE_COUNT"]


def get_all_rules() -> List[Rule]:
    """聚合全部内置规则。"""
    from . import (
        anti_analysis_rules,
        component_rules,
        crypto_rules,
        network_rules,
        privacy_rules,
        storage_rules,
    )

    packs = (
        crypto_rules.RULES,
        network_rules.RULES,
        storage_rules.RULES,
        component_rules.RULES,
        anti_analysis_rules.RULES,
        privacy_rules.RULES,
    )
    rules: List[Rule] = []
    for pack in packs:
        rules.extend(pack)
    return rules


RULE_COUNT = 67
