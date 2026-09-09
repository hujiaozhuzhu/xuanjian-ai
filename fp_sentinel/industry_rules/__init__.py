"""
Xuanjian v3.1 - Industry-Specific Vulnerability Rules

Contains 25+ industry-specific detection rules for 3 new verticals:
- Video Surveillance (9 rules)
- Instant Messaging (8 rules)
- IoT / Internet of Things (9 rules)
"""

from .vertical_rules import (
    VERTICAL_RULES,
    get_vertical_rules,
    get_rules_by_industry,
    list_vertical_industries,
    count_vertical_rules,
    VerticalRule,
    VerticalRuleSet,
    VerticalIndustry,
)

__all__ = [
    "VERTICAL_RULES",
    "get_vertical_rules",
    "get_rules_by_industry",
    "list_vertical_industries",
    "count_vertical_rules",
    "VerticalRule",
    "VerticalRuleSet",
    "VerticalIndustry",
]
