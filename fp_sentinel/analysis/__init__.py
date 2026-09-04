"""
分析模块

提供攻击链发现、漏洞关联分析、风险评分等功能
"""

from .chain_discovery import (
    AttackChainDiscovery,
    AttackChain,
    AttackStep,
    VulnerabilityGraph,
    NodeType,
    EdgeType,
    SinkType,
)

# 攻击链评分（v2.0）
try:
    from .chain_scorer import ChainRiskScorer, RiskScore, AssetContext
except ImportError:
    ChainRiskScorer = None
    RiskScore = None
    AssetContext = None

__all__ = [
    "AttackChainDiscovery",
    "AttackChain",
    "AttackStep",
    "VulnerabilityGraph",
    "NodeType",
    "EdgeType",
    "SinkType",
    "ChainRiskScorer",
    "RiskScore",
    "AssetContext",
]
