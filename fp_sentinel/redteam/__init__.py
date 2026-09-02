"""
红队模块

提供自动化攻击用例生成、绕过策略、对抗验证等功能
"""

from .generator import RedTeamGenerator, BypassCase, MutationStrategy, GenerationResult
from .strategies import MUTATION_STRATEGIES
from .adversarial_loop import (
    AdversarialLoop,
    AdversarialResult,
    RoundResult,
    ConvergenceCriteria,
    ScanSimulator,
)

__all__ = [
    "RedTeamGenerator",
    "BypassCase",
    "MutationStrategy",
    "GenerationResult",
    "MUTATION_STRATEGIES",
    "AdversarialLoop",
    "AdversarialResult",
    "RoundResult",
    "ConvergenceCriteria",
    "ScanSimulator",
]
