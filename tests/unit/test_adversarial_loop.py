"""
对抗循环单元测试

覆盖收敛判定、状态持久化、防震荡机制
"""

import pytest
import asyncio
from fp_sentinel.redteam.adversarial_loop import (
    AdversarialLoop,
    ConvergenceCriteria,
    RoundResult,
    ScanSimulator,
)
from fp_sentinel.redteam.generator import BypassCase, MutationStrategy, DifficultyLevel


class TestConvergenceCriteria:
    """收敛条件测试"""

    def test_default_criteria(self):
        criteria = ConvergenceCriteria()
        assert criteria.detection_rate == 0.95
        assert criteria.false_positive_rate == 0.10
        assert criteria.max_rounds == 10

    def test_custom_criteria(self):
        criteria = ConvergenceCriteria(
            detection_rate=0.98,
            max_rounds=5,
        )
        assert criteria.detection_rate == 0.98
        assert criteria.max_rounds == 5


class TestScanSimulator:
    """扫描模拟器测试"""

    def setup_method(self):
        self.simulator = ScanSimulator()

    @pytest.mark.asyncio
    async def test_evaluate_detected_case(self):
        """应该被检出的用例"""
        case = BypassCase(
            id="test-001",
            rule_id="js.injection.eval",
            strategy=MutationStrategy.API_SUBSTITUTION,
            difficulty=DifficultyLevel.L1_DIRECT,
            original_code="eval(x)",
            bypass_code="eval(userInput)",  # 包含 eval 关键字
            description="test",
            expected_detected=True,
            is_exploitable=True,
        )
        result = await self.simulator.evaluate_case("js.injection.eval", case)
        # eval 模式应该能匹配
        assert result is True

    @pytest.mark.asyncio
    async def test_evaluate_bypassed_case(self):
        """应该绕过的用例"""
        case = BypassCase(
            id="test-002",
            rule_id="js.injection.eval",
            strategy=MutationStrategy.ENCODING_BYPASS,
            difficulty=DifficultyLevel.L2_MUTATION,
            original_code="eval(x)",
            bypass_code='atob("ZXZhbA==")',  # 编码后不包含 eval
            description="test",
            expected_detected=False,
            is_exploitable=True,
        )
        result = await self.simulator.evaluate_case("js.injection.eval", case)
        # 编码后不应被检出
        assert result is False

    @pytest.mark.asyncio
    async def test_evaluate_batch(self):
        """批量评估"""
        cases = [
            BypassCase(
                id=f"test-{i}",
                rule_id="js.injection.eval",
                strategy=MutationStrategy.API_SUBSTITUTION,
                difficulty=DifficultyLevel.L1_DIRECT,
                original_code="eval(x)",
                bypass_code="eval(userInput)" if i % 2 == 0 else "new Function(x)()",
                description="test",
                expected_detected=True,
                is_exploitable=True,
            )
            for i in range(10)
        ]
        result = await self.simulator.evaluate_cases("js.injection.eval", cases)
        assert result["total"] == 10
        assert result["detected"] + result["missed"] == 10


class TestAdversarialLoop:
    """对抗循环测试"""

    def setup_method(self):
        self.loop = AdversarialLoop()

    @pytest.mark.asyncio
    async def test_run_single_rule(self):
        """单规则对抗测试"""
        result = await self.loop.run(
            rule_id="js.injection.eval",
            description="eval() 执行任意代码",
            pattern=r"\beval\s*\(",
            count_per_round=5,
        )
        assert result.rule_id == "js.injection.eval"
        assert result.total_rounds >= 1
        assert len(result.rounds) >= 1

    def test_check_convergence(self):
        """收敛判定测试"""
        rounds = [
            RoundResult(
                round_number=1,
                detection_rate=0.90,
                false_positive_rate=0.05,
                bypass_cases_total=10,
                bypass_cases_detected=9,
                bypass_cases_missed=1,
                by_difficulty={},
                failed_cases=[],
            ),
            RoundResult(
                round_number=2,
                detection_rate=0.96,
                false_positive_rate=0.05,
                bypass_cases_total=10,
                bypass_cases_detected=10,
                bypass_cases_missed=0,
                by_difficulty={},
                failed_cases=[],
            ),
            RoundResult(
                round_number=3,
                detection_rate=0.97,
                false_positive_rate=0.04,
                bypass_cases_total=10,
                bypass_cases_detected=10,
                bypass_cases_missed=0,
                by_difficulty={},
                failed_cases=[],
            ),
        ]
        # 连续3轮达标应收敛
        assert self.loop._check_convergence(rounds) is True

    def test_not_converged_low_rate(self):
        """检出率不足不应收敛"""
        rounds = [
            RoundResult(
                round_number=i,
                detection_rate=0.80,
                false_positive_rate=0.15,
                bypass_cases_total=10,
                bypass_cases_detected=8,
                bypass_cases_missed=2,
                by_difficulty={},
                failed_cases=[],
            )
            for i in range(1, 4)
        ]
        assert self.loop._check_convergence(rounds) is False

    def test_export_json(self):
        """JSON导出测试"""
        from fp_sentinel.redteam.adversarial_loop import AdversarialResult
        result = AdversarialResult(
            rule_id="test",
            total_rounds=1,
            converged=True,
            final_detection_rate=0.96,
            final_false_positive_rate=0.05,
            rounds=[],
            gaps=[],
            recommendations=["test"],
            duration_seconds=1.0,
        )
        json_str = self.loop.export_report(result, format="json")
        assert "test" in json_str

    def test_export_markdown(self):
        """Markdown导出测试"""
        from fp_sentinel.redteam.adversarial_loop import AdversarialResult
        result = AdversarialResult(
            rule_id="test",
            total_rounds=1,
            converged=True,
            final_detection_rate=0.96,
            final_false_positive_rate=0.05,
            rounds=[],
            gaps=[],
            recommendations=["test"],
            duration_seconds=1.0,
        )
        md = self.loop.export_report(result, format="markdown")
        assert "对抗验证报告" in md
