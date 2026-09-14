# -*- coding: utf-8 -*-
"""技法 1：关键字搜索定位。

原理：对反编译结果做全文检索，搜索请求接口名 / 参数名 / encrypt 等
关键字，智能筛选后给出明文数据包相关的 Hook 点位。

自动化方式：基于 KeywordEngine 的 goal 规则库在 ApkContext 中粗筛，
命中字符串常量或方法名特征的应用方法即为候选 Hook 点位。
"""

from __future__ import annotations

from typing import List

from ..core.apk_context import ApkContext
from ..core.keyword_engine import KeywordEngine
from ..models import HookPoint, TechniqueResult
from .base import Technique, register_technique


@register_technique
class KeywordSearchTechnique(Technique):
    name = "keyword"
    description = "关键字搜索定位：检索接口名/参数名/encrypt 等关键字（明文数据包定位）"

    def analyze(self, context: ApkContext, **kwargs) -> TechniqueResult:
        result = self._new_result()
        engine = KeywordEngine(
            goal=kwargs.get("goal", self.goal),
            extra_keywords=kwargs.get("extra_keywords"),
        )
        limit = kwargs.get("limit", 50)
        candidates = engine.search(context, limit=limit)

        hook_points: List[HookPoint] = []
        for cand in candidates:
            m = cand.method
            # 初步置信度：字符串命中与方法特征各占一半证据
            evidence = len(cand.matched_keywords) + len(cand.matched_method_features)
            confidence = min(0.95, 0.4 + 0.1 * evidence)
            hook_points.append(
                self.make_hook_point(
                    class_name=m.class_name,
                    method_name=m.name,
                    param_signature=m.descriptor,
                    confidence=round(confidence, 4),
                    strings_matched=cand.strings_matched[:10],
                    reason=(
                        f"关键字命中 {cand.matched_keywords}，"
                        f"方法特征 {cand.matched_method_features}，"
                        f"调用特征 {cand.matched_invokes}"
                    ),
                    matched_keywords=cand.matched_keywords,
                )
            )
        return self._finish(result, hook_points, engine_goal=engine.goal, candidates=len(candidates))

    def system_hook_points(self) -> List[dict]:
        return []
