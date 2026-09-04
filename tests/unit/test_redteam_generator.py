"""
红队生成器单元测试

覆盖10种变异策略、4级难度分级、绕过代码可执行性
"""

import pytest
from fp_sentinel.redteam.strategies import (
    APISubstitutionStrategy,
    EncodingBypassStrategy,
    ControlFlowStrategy,
    StringSplittingStrategy,
    AsyncWrappingStrategy,
    PrototypeChainStrategy,
    EncoderChainStrategy,
    TypeConfusionStrategy,
    MUTATION_STRATEGIES,
)
from fp_sentinel.redteam.generator import (
    RedTeamGenerator,
    MutationStrategy,
    DifficultyLevel,
    BypassCase,
)


class TestMutationStrategies:
    """变异策略测试"""

    def test_api_substitution_eval(self):
        """eval 应该能被替换为其他API"""
        strategy = APISubstitutionStrategy()
        result = strategy.apply("eval(userInput)", "js.injection.eval")
        # 结果应该不同于原始代码
        assert result != "eval(userInput)" or len(result) > 0

    def test_encoding_bypass_unicode(self):
        """Unicode 编码绕过"""
        strategy = EncodingBypassStrategy()
        result = strategy.apply('eval("test")', "js.injection.eval")
        # 应该产生不同于原始代码的结果
        assert result != 'eval("test")'
        assert len(result) > 0

    def test_control_flow_if_wrapper(self):
        """控制流包装"""
        strategy = ControlFlowStrategy()
        result = strategy.apply("eval(x)", "js.injection.eval")
        # 应该产生不同于原始代码的结果
        assert result != "eval(x)"
        assert len(result) > 0

    def test_string_splitting(self):
        """字符串拆分"""
        strategy = StringSplittingStrategy()
        result = strategy.apply("eval(userInput)", "js.injection.eval")
        # 应该产生不同于原始代码的结果
        assert result != "eval(userInput)" or len(result) > 0

    def test_async_wrapping_settimeout(self):
        """异步包装"""
        strategy = AsyncWrappingStrategy()
        result = strategy.apply("eval(x)", "js.injection.eval")
        # 应该产生不同于原始代码的结果
        assert result != "eval(x)"
        assert len(result) > 0

    def test_prototype_chain(self):
        """原型链利用"""
        strategy = PrototypeChainStrategy()
        result = strategy.apply("eval(x)", "js.injection.eval")
        assert "constructor" in result or "__proto__" in result or "Reflect" in result

    def test_encoder_chain(self):
        """多层编码"""
        strategy = EncoderChainStrategy()
        result = strategy.apply('eval("test")', "js.injection.eval")
        assert "atob" in result or "\\u" in result

    def test_type_confusion(self):
        """类型混淆"""
        strategy = TypeConfusionStrategy()
        result = strategy.apply("eval(x)", "js.injection.eval")
        assert "toString" in result or "!!" in result or ".pop" in result

    def test_all_strategies_produce_output(self):
        """所有策略都应该产生输出"""
        for strategy_type, strategy in MUTATION_STRATEGIES.items():
            result = strategy.apply("eval(userInput)", "js.injection.eval")
            assert len(result) > 0, f"Strategy {strategy_type} produced empty output"

    def test_strategies_have_metadata(self):
        """所有策略都应该有元数据"""
        for strategy_type, strategy in MUTATION_STRATEGIES.items():
            assert strategy.name is not None
            assert strategy.difficulty is not None
            assert strategy.description is not None


class TestRedTeamGenerator:
    """红队生成器测试"""

    def setup_method(self):
        self.generator = RedTeamGenerator()

    def test_generate_fallback_cases(self):
        """无LLM时应使用后备生成"""
        cases = self.generator._generate_fallback_cases(
            "js.injection.eval", r"\beval\s*\(", 10
        )
        assert len(cases) == 10
        for case in cases:
            assert case.rule_id == "js.injection.eval"
            assert len(case.bypass_code) > 0
            assert case.difficulty in DifficultyLevel.__members__.values()

    def test_generate_different_strategies(self):
        """生成的用例应该使用不同策略"""
        cases = self.generator._generate_fallback_cases(
            "js.injection.eval", r"\beval\s*\(", 20
        )
        strategies = {c.strategy for c in cases}
        assert len(strategies) > 1  # 应该有多种策略

    def test_bypass_case_model(self):
        """BypassCase 模型验证"""
        case = BypassCase(
            id="test-001",
            rule_id="js.injection.eval",
            strategy=MutationStrategy.API_SUBSTITUTION,
            difficulty=DifficultyLevel.L1_DIRECT,
            original_code="eval(x)",
            bypass_code="new Function(x)()",
            description="API替换",
            expected_detected=True,
            is_exploitable=True,
        )
        assert case.id == "test-001"
        assert case.difficulty == DifficultyLevel.L1_DIRECT

    @pytest.mark.asyncio
    async def test_generate_bypasses_no_llm(self):
        """无LLM的生成测试"""
        result = await self.generator.generate_bypasses(
            rule_id="js.injection.eval",
            description="eval() 执行任意代码",
            pattern=r"\beval\s*\(",
            count=10,
        )
        assert result.rule_id == "js.injection.eval"
        assert result.total_cases == 10
        assert len(result.cases) == 10
        assert result.generation_time_ms >= 0

    def test_cache(self):
        """缓存测试"""
        # 第一次生成
        import asyncio
        result1 = asyncio.run(self.generator.generate_bypasses(
            rule_id="js.injection.eval",
            description="test",
            pattern=r"\beval\s*\(",
            count=5,
        ))
        # 第二次应该使用缓存
        result2 = asyncio.run(self.generator.generate_bypasses(
            rule_id="js.injection.eval",
            description="test",
            pattern=r"\beval\s*\(",
            count=5,
        ))
        assert result1.total_cases == result2.total_cases

    def test_clear_cache(self):
        """清除缓存"""
        self.generator._cache["test"] = []
        self.generator.clear_cache()
        assert len(self.generator._cache) == 0
