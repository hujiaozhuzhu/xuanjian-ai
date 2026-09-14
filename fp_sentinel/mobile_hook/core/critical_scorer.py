# -*- coding: utf-8 -*-
"""CriticalScorer —— 关键性评分引擎。

五维加权评分（规划文档 2.3.3 步骤 4）::

    包名相关 30% + 方法特征 25% + 调用链 15% + 字符串特征 20% + 历史经验 10%

子分均为 0.0 ~ 1.0，总分 0.0 ~ 1.0，并输出明细（score_breakdown），
便于 CLI / 报告解释"为什么推荐这个点位"。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .apk_context import ApkContext
from .call_chain_analyzer import CallChainAnalyzer
from .keyword_engine import HIGH_VALUE_METHOD_PATTERNS, KeywordEngine

# 权重（总和必须为 1.0）
WEIGHTS: Dict[str, float] = {
    "package": 0.30,       # 包名相关 30%
    "method": 0.25,        # 方法特征 25%
    "call_chain": 0.15,    # 调用链 15%
    "string": 0.20,        # 字符串特征 20%
    "experience": 0.10,    # 历史经验 10%
}

# 历史经验先验：技法 -> 成功率先验（来自培训/实战沉淀，可由 learn() 持续更新）
EXPERIENCE_PRIOR: Dict[str, float] = {
    "keyword": 0.85,
    "collection": 0.80,
    "toast": 0.75,
    "log": 0.70,
    "json": 0.75,
    "string": 0.80,
    "base64": 0.85,
}

DEFAULT_EXPERIENCE = 0.5


class CriticalScorer:
    """关键性评分引擎。"""

    def __init__(
        self,
        context: ApkContext,
        call_chain_analyzer: Optional[CallChainAnalyzer] = None,
        experience_file: Optional[str] = None,
    ):
        self.context = context
        self.chain_analyzer = call_chain_analyzer or CallChainAnalyzer(context)
        self.experience_file = experience_file
        self._experience: Optional[Dict[str, float]] = None

    # ────────────────────────── 各维度子分 ──────────────────────────

    def package_score(self, class_name: str) -> float:
        """包名相关性（30%）：应用主包 > 包段命中 > 框架库。"""
        return KeywordEngine.package_relevance(class_name, self.context.package_name)

    def method_score(self, method_name: str) -> float:
        """方法特征（25%）：命中高价值方法名模式的数量/密度。"""
        low = (method_name or "").lower()
        hits = sum(1 for p in HIGH_VALUE_METHOD_PATTERNS if p in low)
        if hits == 0:
            return 0.2  # 通用方法名保底
        return min(1.0, 0.5 + 0.25 * hits)

    def call_chain_score(self, class_name: str, method_name: str) -> Tuple[float, List[str], bool]:
        """调用链维度（15%）：入口可达性 + 链长。"""
        return self.chain_analyzer.chain_score(class_name, method_name)

    def string_score(self, strings: List[str]) -> float:
        """字符串特征（20%）：方法内命中敏感/加密特征字符串。"""
        if not strings:
            return 0.1
        sensitive = ("encrypt", "decrypt", "aes", "des", "rsa", "token",
                     "password", "secret", "sign", "key", "base64")
        hits = 0
        for s in strings:
            low = s.lower()
            if any(k in low for k in sensitive):
                hits += 1
        if hits == 0:
            return 0.2
        return min(1.0, 0.4 + 0.2 * hits)

    def experience_score(self, technique: str) -> float:
        """历史经验（10%）：技法先验 + 本地经验文件更新。"""
        exp = self._load_experience()
        return exp.get(technique, EXPERIENCE_PRIOR.get(technique, DEFAULT_EXPERIENCE))

    def _load_experience(self) -> Dict[str, float]:
        if self._experience is not None:
            return self._experience
        self._experience = dict(EXPERIENCE_PRIOR)
        if self.experience_file:
            try:
                data = json.loads(Path(self.experience_file).read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    for k, v in data.items():
                        if isinstance(v, (int, float)):
                            self._experience[str(k)] = max(0.0, min(1.0, float(v)))
            except (OSError, ValueError):
                pass  # 经验文件缺失/损坏时静默使用先验
        return self._experience

    def learn(self, technique: str, success: bool) -> None:
        """反馈学习：成功 +0.05 / 失败 -0.05，并可选持久化。"""
        exp = self._load_experience()
        cur = exp.get(technique, EXPERIENCE_PRIOR.get(technique, DEFAULT_EXPERIENCE))
        exp[technique] = max(0.0, min(1.0, cur + (0.05 if success else -0.05)))
        if self.experience_file:
            try:
                Path(self.experience_file).write_text(
                    json.dumps(exp, ensure_ascii=False, indent=2), encoding="utf-8"
                )
            except OSError:
                pass

    # ────────────────────────── 总分 ──────────────────────────

    def score(
        self,
        class_name: str,
        method_name: str,
        technique: str,
        strings: Optional[List[str]] = None,
    ) -> Tuple[float, Dict[str, float], List[str], bool]:
        """计算关键性总分。

        返回: (总分, 明细 breakdown, 代表调用链, 入口可达)
        """
        chain_score, chain_nodes, reachable = self.call_chain_score(class_name, method_name)
        breakdown = {
            "package": round(self.package_score(class_name), 4),
            "method": round(self.method_score(method_name), 4),
            "call_chain": round(chain_score, 4),
            "string": round(self.string_score(strings or []), 4),
            "experience": round(self.experience_score(technique), 4),
        }
        total = sum(breakdown[k] * WEIGHTS[k] for k in WEIGHTS)
        return round(min(1.0, max(0.0, total)), 4), breakdown, chain_nodes, reachable

    @staticmethod
    def verify_weights() -> bool:
        """校验权重配置总和为 1.0（自检用）。"""
        return abs(sum(WEIGHTS.values()) - 1.0) < 1e-9
