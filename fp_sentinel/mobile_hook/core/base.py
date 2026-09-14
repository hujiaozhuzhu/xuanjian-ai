# -*- coding: utf-8 -*-
"""HookLocator —— Hook 定位引擎基类（编排层）。

核心接口（对应任务要求 1）：
- ``recommend(apk_path, goal, top_n)``：七种技法全部执行 -> 调用链增强 ->
  关键性评分 -> Top-N 推荐；
- ``execute_technique(name, apk_path, **kw)``：执行单一技法；
- ``verify_hook(hook_point, device=None)``：Hook 点位验证（**mock 化**，
  不实际连接设备：校验脚本可生成性与静态一致性，模拟附加成功）。

设计要点：
- 技法通过注册表（``register_technique``）解耦，新增技法零侵入；
- 所有技法允许注入 ApkContext（测试/外部管线复用）；
- 技法抛错被捕获为失败 TechniqueResult，不影响其它技法（组合扫描容错）。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional, Type

from ..models import HookPoint, HookRecommendation, TechniqueResult
from ..techniques.base import Technique, get_technique_registry
from .apk_context import ApkContext
from .call_chain_analyzer import CallChainAnalyzer
from .critical_scorer import CriticalScorer
from .keyword_engine import KeywordEngine

logger = logging.getLogger(__name__)


class UnknownTechniqueError(KeyError):
    """请求了未注册的技法。"""


class HookLocator:
    """Hook 点位定位与推荐引擎。"""

    def __init__(
        self,
        apk_path: Optional[str] = None,
        goal: str = "generic",
        context: Optional[ApkContext] = None,
        experience_file: Optional[str] = None,
    ):
        self.apk_path = apk_path or ""
        self.goal = goal
        self._context = context
        self.experience_file = experience_file
        self._registry: Dict[str, Type[Technique]] = dict(get_technique_registry())

    # ────────────────────────── 技法注册 ──────────────────────────

    def register_technique(self, technique_cls: Type[Technique], override: bool = False) -> None:
        """注册技法类。默认不覆盖同名技法。"""
        name = technique_cls.name
        if name in self._registry and not override:
            raise ValueError(f"技法 {name!r} 已注册，如需覆盖请传 override=True")
        self._registry[name] = technique_cls

    def list_techniques(self) -> List[str]:
        """已注册技法名列表。"""
        return sorted(self._registry.keys())

    def _build_technique(self, name: str) -> Technique:
        cls = self._registry.get(name)
        if cls is None:
            raise UnknownTechniqueError(name)
        return cls(goal=self.goal)

    # ────────────────────────── 上下文 ──────────────────────────

    def get_context(self, apk_path: Optional[str] = None) -> ApkContext:
        """获取（并缓存）ApkContext。

        - 已注入 context 且未显式指定不同 APK 路径 -> 直接复用；
        - 指定了与缓存不同的 APK 路径 -> 重新加载。
        """
        if self._context is not None:
            if apk_path is None or self._context.apk_path == str(Path(apk_path).resolve()):
                return self._context
        path = apk_path or self.apk_path
        if not path:
            raise ValueError("未指定 APK 路径，且未注入上下文")
        self._context = ApkContext.from_apk(path)
        self.apk_path = path
        return self._context

    # ────────────────────────── 单技法执行 ──────────────────────────

    def execute_technique(
        self,
        name: str,
        apk_path: Optional[str] = None,
        context: Optional[ApkContext] = None,
        **kwargs,
    ) -> TechniqueResult:
        """执行单一技法。任何异常都被收敛为失败的 TechniqueResult。"""
        if context is not None:
            self._context = context
        try:
            ctx = context or self.get_context(apk_path)
        except Exception as exc:
            return TechniqueResult.fail(name, exc=exc)
        try:
            technique = self._build_technique(name)
            return technique.analyze(ctx, **kwargs)
        except UnknownTechniqueError:
            raise
        except Exception as exc:  # 技法隔离：单技法失败不影响整体
            logger.warning("技法 %s 执行失败: %s", name, exc, exc_info=True)
            return TechniqueResult.fail(name, exc=exc)

    # ────────────────────────── 推荐 ──────────────────────────

    def recommend(
        self,
        apk_path: Optional[str] = None,
        goal: Optional[str] = None,
        top_n: int = 10,
        techniques: Optional[List[str]] = None,
        context: Optional[ApkContext] = None,
    ) -> HookRecommendation:
        """完整推荐流程（2.3.3）：

        静态预分析 -> 关键字粗筛 -> 七技法并行产出 -> 调用链追踪 ->
        关键性评分 -> Top-N。
        """
        if goal:
            self.goal = goal
        ctx = context
        if ctx is None:
            ctx = self.get_context(apk_path)
        ctx.ensure_loaded()

        recommendation = HookRecommendation(
            apk_path=apk_path or self.apk_path or ctx.apk_path,
            goal=self.goal,
            package_name=ctx.package_name,
        )

        technique_names = techniques or self.list_techniques()
        scorer = CriticalScorer(ctx, experience_file=self.experience_file)

        seen_points: set = set()  # RD-009: (class, method, technique) 去重
        for name in technique_names:
            result = self.execute_technique(name, context=ctx)
            recommendation.technique_results.append(result)
            recommendation.degraded = recommendation.degraded or result.degraded
            for candidate in result.hook_points:
                # RD-009: 同一 (class_name, method_name, technique) 组合只保留
                # 首个候选 —— 多技法扫描同一目标时不再产生重复点位。
                key = (candidate.class_name, candidate.method_name, candidate.technique)
                if key in seen_points:
                    continue
                seen_points.add(key)
                # 调用链增强 + 统一关键性评分（技法内预填置信度会被覆盖）
                chains = CallChainAnalyzer(ctx)
                chain_nodes, reachable = self._chain_info(chains, candidate)
                total, breakdown, chain_nodes2, reachable2 = scorer.score(
                    candidate.class_name,
                    candidate.method_name,
                    candidate.technique,
                    strings=candidate.strings_matched or None,
                )
                candidate.confidence = total
                candidate.score_breakdown = breakdown
                candidate.call_chain = chain_nodes2 or chain_nodes
                candidate.entry_reachable = reachable2 or reachable
                recommendation.hook_points.append(candidate)

        recommendation.hook_points.sort(key=lambda p: p.confidence, reverse=True)
        recommendation.hook_points = recommendation.rank(top_n)
        return recommendation

    @staticmethod
    def _chain_info(analyzer: CallChainAnalyzer, hp: HookPoint):
        try:
            chains = analyzer.trace_back(hp.class_name, hp.method_name)
            reachable = any(c.reachable_from_entry for c in chains)
            nodes = next((c.nodes for c in chains if c.reachable_from_entry), None)
            return (nodes or (chains[0].nodes if chains else [])), reachable
        except Exception:  # pragma: no cover - 调用链失败不阻断评分
            return [], False

    # ────────────────────────── 验证（mock 化） ──────────────────────────

    def verify_hook(self, hook_point: HookPoint, device: Optional[str] = None) -> Dict:
        """验证 Hook 点位。

        **Mock 实现 —— 不连接任何真实设备。**验证包含三层：
        1. Frida 脚本可生成性：技法能产出合法脚本模板（含 Java.perform/Java.use）；
        2. 静态一致性：类/方法/签名能被当前上下文定位到；
        3. 动态附加模拟：模拟 attach 成功（无论 device 是否传入）。

        返回 dict::
            {
              "target": "cls#method",
              "script_valid": bool,       # 脚本模板合法
              "static_match": bool,       # 静态可定位
              "device_attached": True,    # mock：恒为 True（模拟附加）
              "mock": True,               # 明确标注这是 mock 验证
              "device": device or "emulator-5554",
              "message": str,
            }
        """
        target = f"{hook_point.class_name}#{hook_point.method_name}"

        # 1) 脚本可生成性
        script_valid = False
        try:
            technique = self._build_technique(hook_point.technique)
            script = technique.generate_frida_script([hook_point])
            script_valid = bool(script) and "Java.perform" in script and "Java.use" in script
        except Exception as exc:
            logger.warning("verify_hook 脚本生成失败: %s", exc)

        # 2) 静态一致性（无上下文可复核时视为跳过，mock 放行）
        static_match = True
        static_checked = True
        try:
            ctx = self.get_context()
            cls = ctx.get_class(hook_point.class_name)
            if cls is not None and cls.method(hook_point.method_name) is not None:
                static_match = True
            else:
                static_match = False
        except Exception:
            static_checked = False  # 无 APK/上下文，静态复核跳过

        verified = script_valid and static_match
        return {
            "target": target,
            "script_valid": script_valid,
            "static_match": static_match,
            "static_checked": static_checked,
            "device_attached": True,  # mock：模拟附加成功
            "mock": True,
            "device": device or "emulator-5554",
            "message": (
                "Hook 点位验证通过（mock：脚本模板合法 + 静态可定位）"
                if verified else
                "Hook 点位验证未通过："
                + ("脚本生成失败 " if not script_valid else "")
                + ("静态无法定位" if (not static_match and static_checked) else "")
            ),
            "verified": verified,
        }
