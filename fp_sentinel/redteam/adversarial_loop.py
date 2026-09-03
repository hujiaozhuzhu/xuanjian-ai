"""
最小对抗循环

整合红队生成→蓝队修复→自动验证的最小可用闭环
支持自动迭代直至收敛或达到最大轮次
"""

import json
import logging
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

from .generator import RedTeamGenerator, BypassCase
from ..rules.js import JS_RULES_INDEX

logger = logging.getLogger(__name__)


class ConvergenceCriteria(BaseModel):
    """收敛条件"""
    detection_rate: float = Field(default=0.95, description="检出率要求")
    false_positive_rate: float = Field(default=0.10, description="误报率要求")
    bypass_rate_l3: float = Field(default=0.05, description="L3绕过率要求")
    bypass_rate_l4: float = Field(default=0.03, description="L4绕过率要求")
    stability_window: int = Field(default=2, description="连续稳定轮次")
    max_regression: float = Field(default=0.05, description="单轮最大退化")
    max_rounds: int = Field(default=10, description="最大迭代轮次")


class RoundResult(BaseModel):
    """单轮结果"""
    round_number: int
    detection_rate: float
    false_positive_rate: float
    bypass_cases_total: int
    bypass_cases_detected: int
    bypass_cases_missed: int
    by_difficulty: Dict[str, Dict[str, int]]
    failed_cases: List[BypassCase]
    fix_applied: bool = False
    fix_details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.now)


class AdversarialResult(BaseModel):
    """对抗循环最终结果"""
    rule_id: str
    total_rounds: int
    converged: bool
    final_detection_rate: float
    final_false_positive_rate: float
    rounds: List[RoundResult]
    gaps: List[str]
    recommendations: List[str]
    duration_seconds: float


class ScanSimulator:
    """扫描模拟器（用于验证规则检出能力）"""

    def __init__(self, rules_index: Dict[str, Any] = None):
        self.rules_index = rules_index or JS_RULES_INDEX

    async def evaluate_case(
        self, rule_id: str, bypass_case: BypassCase
    ) -> bool:
        """
        评估绕过用例是否被检出

        Returns:
            True 如果被检出，False 如果绕过成功
        """
        rule = self.rules_index.get(rule_id)
        if not rule:
            return False

        import re
        pattern = rule.code_pattern
        if not pattern:
            return False

        try:
            # 尝试匹配
            match = re.search(pattern, bypass_case.bypass_code, re.IGNORECASE)
            return match is not None
        except re.error:
            return False

    async def evaluate_cases(
        self, rule_id: str, cases: List[BypassCase]
    ) -> Dict[str, Any]:
        """批量评估绕过用例"""
        detected = 0
        missed = 0
        by_difficulty = {}

        for case in cases:
            is_detected = await self.evaluate_case(rule_id, case)

            if is_detected:
                detected += 1
            else:
                missed += 1

            # 按难度统计
            diff = case.difficulty.value
            if diff not in by_difficulty:
                by_difficulty[diff] = {"detected": 0, "missed": 0, "total": 0}
            by_difficulty[diff]["total"] += 1
            if is_detected:
                by_difficulty[diff]["detected"] += 1
            else:
                by_difficulty[diff]["missed"] += 1

        total = len(cases)
        return {
            "total": total,
            "detected": detected,
            "missed": missed,
            "detection_rate": detected / total if total > 0 else 0,
            "by_difficulty": by_difficulty,
        }


class AdversarialLoop:
    """
    最小对抗循环

    实现红队生成→蓝队修复→自动验证的闭环
    """

    def __init__(
        self,
        red_team: RedTeamGenerator = None,
        scan_simulator: ScanSimulator = None,
        criteria: ConvergenceCriteria = None,
        config: Dict[str, Any] = None,
    ):
        self.config = config or {}
        self.criteria = criteria or ConvergenceCriteria()
        self.red_team = red_team or RedTeamGenerator()
        self.scan_simulator = scan_simulator or ScanSimulator()
        self._results_history: List[RoundResult] = []

    async def run(
        self,
        rule_id: str,
        description: str = "",
        pattern: str = "",
        category: str = "",
        severity: str = "MEDIUM",
        language: str = "javascript",
        count_per_round: int = 20,
    ) -> AdversarialResult:
        """
        运行对抗循环

        Args:
            rule_id: 目标规则ID
            description: 规则描述
            pattern: 匹配模式
            category: 漏洞类别
            severity: 严重级别
            language: 目标语言
            count_per_round: 每轮生成的绕过用例数

        Returns:
            AdversarialResult: 对抗结果
        """
        start = time.time()

        # 获取规则信息
        rule = JS_RULES_INDEX.get(rule_id)
        if rule:
            description = description or rule.description
            pattern = pattern or rule.code_pattern
            category = category or rule.category
            severity = severity or rule.severity

        rounds = []
        converged = False
        gaps = []

        logger.info(f"Starting adversarial loop for rule: {rule_id}")
        logger.info(f"Criteria: detection>={self.criteria.detection_rate}, "
                    f"FP<={self.criteria.false_positive_rate}")

        for round_num in range(1, self.criteria.max_rounds + 1):
            logger.info(f"\n{'='*50}")
            logger.info(f"Round {round_num}")
            logger.info(f"{'='*50}")

            # 1. 红队生成绕过用例
            logger.info("Red Team: Generating bypass cases...")
            gen_result = await self.red_team.generate_bypasses(
                rule_id=rule_id,
                description=description,
                pattern=pattern,
                category=category,
                severity=severity,
                language=language,
                count=count_per_round,
            )

            # 2. 自动化验证
            logger.info("Evaluating bypass cases...")
            eval_result = await self.scan_simulator.evaluate_cases(
                rule_id, gen_result.cases
            )

            # 3. 构建本轮结果
            failed_cases = [
                case for case in gen_result.cases
                if not await self.scan_simulator.evaluate_case(rule_id, case)
            ]

            round_result = RoundResult(
                round_number=round_num,
                detection_rate=eval_result["detection_rate"],
                false_positive_rate=0.0,  # TODO: 需要误报基准集
                bypass_cases_total=eval_result["total"],
                bypass_cases_detected=eval_result["detected"],
                bypass_cases_missed=eval_result["missed"],
                by_difficulty=eval_result["by_difficulty"],
                failed_cases=failed_cases,
            )
            rounds.append(round_result)

            logger.info(f"Detection rate: {eval_result['detection_rate']:.1%}")
            logger.info(f"Detected: {eval_result['detected']}/{eval_result['total']}")
            for diff, stats in eval_result["by_difficulty"].items():
                logger.info(f"  {diff}: {stats['detected']}/{stats['total']} detected")

            # 4. 检查是否达标
            if self._check_convergence(rounds):
                converged = True
                logger.info(f"✅ Converged at round {round_num}!")
                break

            # 5. 如果未达标，蓝队分析修复
            if failed_cases:
                logger.info("Blue Team: Analyzing failures and generating fix...")
                fix = await self.red_team.analyze_and_fix(
                    rule_id=rule_id,
                    pattern=pattern,
                    description=description,
                    failed_cases=failed_cases,
                )
                round_result.fix_applied = True
                round_result.fix_details = fix

                # 记录差距
                gaps.extend([
                    f"Round {round_num}: {case.strategy.value} bypass - {case.description}"
                    for case in failed_cases
                ])

                logger.info(f"Fix strategy: {fix.get('fix_strategy', 'N/A')}")

        # 生成最终结果
        elapsed = time.time() - start
        final_detection = rounds[-1].detection_rate if rounds else 0
        final_fp = rounds[-1].false_positive_rate if rounds else 0

        recommendations = self._generate_recommendations(
            rule_id, rounds, converged
        )

        result = AdversarialResult(
            rule_id=rule_id,
            total_rounds=len(rounds),
            converged=converged,
            final_detection_rate=final_detection,
            final_false_positive_rate=final_fp,
            rounds=rounds,
            gaps=gaps,
            recommendations=recommendations,
            duration_seconds=round(elapsed, 2),
        )

        logger.info(f"\n{'='*50}")
        logger.info(f"Adversarial loop completed for {rule_id}")
        logger.info(f"Total rounds: {len(rounds)}")
        logger.info(f"Converged: {converged}")
        logger.info(f"Final detection rate: {final_detection:.1%}")
        logger.info(f"Duration: {elapsed:.1f}s")
        logger.info(f"{'='*50}")

        return result

    async def run_batch(
        self,
        rule_ids: List[str] = None,
        count_per_round: int = 20,
    ) -> Dict[str, AdversarialResult]:
        """批量运行对抗循环"""
        if rule_ids is None:
            rule_ids = list(JS_RULES_INDEX.keys())

        results = {}
        for rule_id in rule_ids:
            try:
                result = await self.run(
                    rule_id=rule_id,
                    count_per_round=count_per_round,
                )
                results[rule_id] = result
            except Exception as e:
                logger.error(f"Failed to run adversarial loop for {rule_id}: {e}")

        return results

    def _check_convergence(self, rounds: List[RoundResult]) -> bool:
        """检查是否收敛"""
        if len(rounds) < self.criteria.stability_window:
            return False

        # 检查最近N轮是否稳定达标
        recent = rounds[-self.criteria.stability_window:]
        for r in recent:
            if r.detection_rate < self.criteria.detection_rate:
                return False

        # 检查是否有退化
        if len(rounds) >= 2:
            prev = rounds[-2]
            curr = rounds[-1]
            regression = prev.detection_rate - curr.detection_rate
            if regression > self.criteria.max_regression:
                return False

        return True

    def _generate_recommendations(
        self,
        rule_id: str,
        rounds: List[RoundResult],
        converged: bool,
    ) -> List[str]:
        """生成建议"""
        recommendations = []

        if converged:
            recommendations.append(f"规则 {rule_id} 已通过对抗验证")
        else:
            recommendations.append(f"规则 {rule_id} 未收敛，需要进一步强化")

        # 分析最常被绕过的策略
        missed_strategies = {}
        for r in rounds:
            for case in r.failed_cases:
                s = case.strategy.value
                missed_strategies[s] = missed_strategies.get(s, 0) + 1

        if missed_strategies:
            top_strategies = sorted(
                missed_strategies.items(), key=lambda x: x[1], reverse=True
            )[:3]
            for strategy, count in top_strategies:
                recommendations.append(
                    f"策略 {strategy} 成功绕过 {count} 次，建议重点防御"
                )

        # 检测率趋势
        if len(rounds) >= 2:
            trend = rounds[-1].detection_rate - rounds[0].detection_rate
            if trend > 0:
                recommendations.append(f"检测率提升 {trend:.1%}")
            elif trend < 0:
                recommendations.append(f"检测率下降 {abs(trend):.1%}，需要检查修复是否引入问题")

        return recommendations

    def export_report(
        self, result: AdversarialResult, format: str = "json"
    ) -> str:
        """导出报告"""
        if format == "json":
            return json.dumps(
                result.model_dump(),
                ensure_ascii=False,
                indent=2,
                default=str,
            )
        elif format == "markdown":
            return self._to_markdown(result)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _to_markdown(self, result: AdversarialResult) -> str:
        """转换为 Markdown 格式"""
        lines = [
            f"# 对抗验证报告 - {result.rule_id}",
            "",
            f"- **总轮次**: {result.total_rounds}",
            f"- **是否收敛**: {'✅ 是' if result.converged else '❌ 否'}",
            f"- **最终检出率**: {result.final_detection_rate:.1%}",
            f"- **最终误报率**: {result.final_false_positive_rate:.1%}",
            f"- **耗时**: {result.duration_seconds:.1f}s",
            "",
            "## 轮次详情",
            "",
            "| 轮次 | 检出率 | 总用例 | 检出 | 绕过 | 修复 |",
            "|------|--------|--------|------|------|------|",
        ]

        for r in result.rounds:
            lines.append(
                f"| {r.round_number} | {r.detection_rate:.1%} | "
                f"{r.bypass_cases_total} | {r.bypass_cases_detected} | "
                f"{r.bypass_cases_missed} | {'✅' if r.fix_applied else '-'} |"
            )

        if result.gaps:
            lines.extend(["", "## 差距分析", ""])
            for gap in result.gaps[:10]:
                lines.append(f"- {gap}")

        if result.recommendations:
            lines.extend(["", "## 建议", ""])
            for rec in result.recommendations:
                lines.append(f"- {rec}")

        return "\n".join(lines)
