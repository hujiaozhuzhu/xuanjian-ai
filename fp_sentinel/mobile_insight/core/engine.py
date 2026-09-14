"""提示规则引擎 —— 规则注册、匹配、TechnicalInsight 生成与去重。"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from ..models.insight import (
    CodeLocation,
    DifficultyLevel,
    InsightCategory,
    InsightReport,
    Severity,
    TechnicalInsight,
)
from .context import AnalysisContext, classify_class
from .priority import filter_insights, sort_insights

__all__ = ["Rule", "InsightEngine", "get_all_rules"]


@dataclass
class Rule:
    """单条技术提示规则。

    匹配语义: ``patterns`` 中任一正则在上下文信号池命中即触发;
    若提供 ``check`` 则以 check(ctx) 的返回(证据列表, 空列表=未命中)为准。

    RD-003 二次确认机制: ``confirm_patterns`` 非空时，patterns 命中之外
    还要求每个 confirm 正则都在上下文中命中（类名+字符串双证据），
    任一缺失则不触发 —— 用于消除"单词命中即报告"的误报。
    """

    id: str
    title: str
    category: InsightCategory
    severity: Severity
    confidence: float
    patterns: List[str]
    description: str
    technical_context: str
    suggested_technique: str
    next_steps: List[str]
    cwe_ids: List[str] = field(default_factory=list)
    masvs_refs: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    estimated_difficulty: DifficultyLevel = DifficultyLevel.MEDIUM
    auto_fixable: bool = False
    fix_hint: Optional[str] = None
    affected_component: str = ""
    confirm_patterns: List[str] = field(default_factory=list)
    check: Optional[Callable[[AnalysisContext], List[str]]] = None
    # NEW-01: 依据证据内容动态定级（如 ST-007 依据 [LEVELn] 前缀）; None = 静态 severity
    dynamic_severity: Optional[Callable[[List[str]], Optional[Severity]]] = None
    # NEW-02: 证据是否来自代码级（const-string/类名）——True 时未归因命中会降一级;
    # manifest/flag 类规则置 False（没有代码位置可归因）。
    code_level: bool = True

    def match(self, ctx: AnalysisContext) -> List[str]:
        """返回证据列表(非空即命中)。"""
        if self.check is not None:
            return list(self.check(ctx) or [])
        for pattern in self.patterns:
            if ctx.has_signal(pattern):
                # RD-003: 二次确认 —— 全部 confirm 正则须同时命中
                if all(ctx.has_signal(cp) for cp in self.confirm_patterns):
                    return ctx.find_evidence(pattern)
                return []
        return []


class InsightEngine:
    """提示规则引擎。

    用法::

        engine = InsightEngine()          # 默认注册全部 63 条内置规则
        report = engine.run(ctx, target="app.apk")
        report.to_dict()
    """

    def __init__(self, rules: Optional[Sequence[Rule]] = None,
                 auto_sort: bool = True) -> None:
        self.rules: List[Rule] = []
        self.auto_sort = auto_sort
        if rules is not None:
            for rule in rules:
                self.register(rule)
        else:
            from ..rules import get_all_rules

            for rule in get_all_rules():
                self.register(rule)

    def register(self, rule: Rule) -> None:
        if not rule.patterns and rule.check is None:
            raise ValueError(f"rule {rule.id!r} needs patterns or check")
        if any(r.id == rule.id for r in self.rules):
            raise ValueError(f"duplicate rule id: {rule.id!r}")
        self.rules.append(rule)

    def run(
        self,
        ctx: AnalysisContext,
        target: str = "",
        category: Optional[InsightCategory] = None,
        min_severity: Optional[Severity] = None,
    ) -> InsightReport:
        """执行全部规则并输出提示报告。

        category / min_severity 为 None 时不过滤(返回全部命中)。
        """
        started = time.perf_counter()
        insights: List[TechnicalInsight] = []
        matched = 0

        for rule in self.rules:
            evidence = rule.match(ctx)
            if not evidence:
                continue
            matched += 1
            insights.append(self._to_insight(rule, evidence, ctx))

        if self.auto_sort:
            insights = sort_insights(insights)
        if category is not None or min_severity is not None:
            insights = filter_insights(insights, category=category,
                                       min_severity=min_severity)

        return InsightReport(
            target=target,
            insights=insights,
            rules_total=len(self.rules),
            rules_matched=matched,
            duration_sec=time.perf_counter() - started,
        )

    @staticmethod
    def _downgrade(sev: Severity) -> Severity:
        """NEW-02: 归因失败时严重级别降一档（不低于 INFO）。"""
        return Severity(max(sev.value - 1, Severity.INFO.value))

    def _to_insight(
        self, rule: Rule, evidence: List[str], ctx: Optional[AnalysisContext] = None
    ) -> TechnicalInsight:
        hint_id = f"INS-{rule.id}"
        severity = rule.severity
        # NEW-01: 证据驱动的动态定级
        if rule.dynamic_severity is not None:
            dyn = rule.dynamic_severity(evidence)
            if dyn is not None:
                severity = dyn

        code_reference = CodeLocation(class_name=evidence[0]) if evidence else CodeLocation()
        # NEW-02: 代码级证据自动归因 —— 归因成功回填 class#method;
        # 归因不可用(索引缺失)保持原样; 归因可用但失败则降一级并标注未归因。
        # R3.1a 跨证据定位: 依次尝试全部证据，业务类命中优先 —— 单看
        # evidence[0] 会因证据顺序偶然落在库类（如 gms 内部实现）。
        # R3.1b framework 落点降级: 归因落点是 Android/JVM 框架命名空间
        # （android.*/androidx.*/java.* 等，support 兼容垫片内部实现）时，
        # 该调用不构成应用自身漏洞面 —— 保留真实落点但严重级别降一档。
        # v4.0 C1: 三方库 library 落点（okhttp3/okio/gms 等）同级处理，
        # 且框架/库落点最终不得以 HIGH+ 呈现（终验验收: HIGH+ 库/框架
        # 落点 = 0），静态 CRITICAL 经降级后仍为 HIGH 时继续降一档。
        unattributed = False
        framework_hit = False
        library_hit = False
        if ctx is not None and rule.code_level and evidence:
            if ctx.attribution_available:
                located: Optional[Tuple[str, str]] = None
                for ev in evidence:
                    loc = ctx.locate_evidence(ev)
                    if loc is None:
                        continue
                    if located is None:
                        located = loc
                    if classify_class(loc[0], ctx.package_name) == "business":
                        located = loc
                        break
                if located is not None:
                    cls, meth = located
                    code_reference = CodeLocation(
                        class_name=cls, method_name=meth,
                        file="classes.dex",
                    )
                    landing = classify_class(cls, ctx.package_name)
                    framework_hit = landing == "framework"
                    library_hit = landing == "library"
                else:
                    unattributed = True
        if unattributed:
            severity = self._downgrade(severity)
            code_reference = CodeLocation(class_name="DEX string pool (unattributed)")
        elif framework_hit:
            severity = self._downgrade(severity)
        elif library_hit:
            # v4.0 C1: 三方库内部落点（okhttp3/okio/gms 等）与框架落点同理，
            # 不是应用自身漏洞面 —— 至少降一档（终验验收: HIGH+ 库/框架落点 = 0）。
            severity = self._downgrade(severity)
        if (framework_hit or library_hit) and severity.value >= Severity.HIGH.value:
            # 静态 CRITICAL 经一档降级仍为 HIGH 时继续降，保证库/框架落点
            # 不以 HIGH+ 呈现（框架 CRITICAL → HIGH → MEDIUM）。
            severity = self._downgrade(severity)

        # NEW-06: 依据证据锚点(归因类名 > 证据原文)回填来源分类
        anchor = code_reference.class_name or (evidence[0] if evidence else "")
        classification = classify_class(anchor, ctx.package_name if ctx else "")
        if anchor == "DEX string pool (unattributed)":
            classification = "unattributed"

        return TechnicalInsight(
            id=hint_id,
            rule_id=rule.id,
            title=rule.title,
            category=rule.category,
            severity=severity,
            confidence=rule.confidence,
            description=rule.description,
            affected_component=rule.affected_component or (evidence[0] if evidence else ""),
            code_reference=code_reference,
            technical_context=rule.technical_context,
            suggested_technique=rule.suggested_technique,
            estimated_difficulty=rule.estimated_difficulty,
            next_steps=rule.next_steps,
            cwe_ids=rule.cwe_ids,
            masvs_refs=rule.masvs_refs,
            references=rule.references,
            auto_fixable=rule.auto_fixable,
            fix_hint=rule.fix_hint,
            evidence=evidence,
            classification=classification,
        )


def get_all_rules() -> List[Rule]:
    """聚合全部内置规则(延迟导入避免循环依赖)。"""
    from ..rules import crypto_rules, network_rules, storage_rules
    from ..rules import component_rules, anti_analysis_rules, privacy_rules

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
