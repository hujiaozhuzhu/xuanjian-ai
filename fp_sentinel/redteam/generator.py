"""
红队攻击用例生成引擎

基于 LLM 和变异策略，自动生成绕过静态分析规则的测试用例
"""

import json
import logging
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class DifficultyLevel(str, Enum):
    """绕过难度等级"""
    L1_DIRECT = "L1"           # 直接替换，最容易
    L2_MUTATION = "L2"         # 语法变异
    L3_OBFUSCATION = "L3"      # 混淆绕过
    L4_COMPOSITION = "L4"      # 组合攻击，最难


class MutationStrategy(str, Enum):
    """变异策略"""
    API_SUBSTITUTION = "api_substitution"      # API 等价替换
    ENCODING_BYPASS = "encoding_bypass"         # 编码绕过
    CONTROL_FLOW = "control_flow"               # 控制流混淆
    STRING_SPLITTING = "string_splitting"       # 字符串拆分
    FRAMEWORK_ABUSE = "framework_abuse"         # 框架特性利用
    ASYNC_WRAPPING = "async_wrapping"           # 异步包装
    PROTOTYPE_CHAIN = "prototype_chain"         # 原型链利用
    ENCODER_CHAIN = "encoder_chain"             # 编码器链
    TYPE_CONFUSION = "type_confusion"           # 类型混淆
    TIMING_ATTACK = "timing_attack"             # 时序攻击


class BypassCase(BaseModel):
    """绕过用例"""
    id: str = Field(..., description="用例ID")
    rule_id: str = Field(..., description="目标规则ID")
    strategy: MutationStrategy = Field(..., description="变异策略")
    difficulty: DifficultyLevel = Field(..., description="难度等级")
    original_code: str = Field(..., description="原始漏洞代码")
    bypass_code: str = Field(..., description="绕过代码")
    description: str = Field(..., description="绕过说明")
    expected_detected: bool = Field(..., description="预期是否被检出")
    is_exploitable: bool = Field(..., description="是否仍可利用")
    exploit_scenario: Optional[str] = Field(None, description="利用场景描述")
    cwe: Optional[str] = Field(None, description="CWE编号")
    tags: List[str] = Field(default_factory=list, description="标签")
    created_at: datetime = Field(default_factory=datetime.now, description="创建时间")


class GenerationResult(BaseModel):
    """生成结果"""
    rule_id: str
    total_cases: int
    cases: List[BypassCase]
    strategies_used: List[str]
    difficulty_distribution: Dict[str, int]
    generation_time_ms: float


# ─────────────────────── Prompt 模板 ───────────────────────

BYPASS_GENERATION_PROMPT = """你是一个顶级安全研究员，擅长构造绕过静态分析规则的代码。

## 目标规则
- 规则ID: {rule_id}
- 规则描述: {description}
- 匹配模式: {pattern}
- 漏洞类型: {category}
- 严重级别: {severity}

## 任务
请生成 {count} 种语义等价但语法不同的绕过变体。

## 变异策略要求
{strategies_desc}

## 输出格式
返回 JSON 数组，每个元素包含:
```json
{{
    "strategy": "策略名称",
    "difficulty": "L1/L2/L3/L4",
    "bypass_code": "绕过后的代码",
    "description": "绕过原理说明",
    "expected_detected": true/false,
    "is_exploitable": true/false,
    "exploit_scenario": "利用场景描述"
}}
```

## 重要约束
1. 每种变体必须保持原始漏洞的可利用性（除非明确标注不可利用用于测试误报）
2. 变体应覆盖不同难度级别，从简单替换到复杂混淆
3. 代码必须是可运行的、语法正确的
4. 不要生成相同的变体
5. 考虑目标语言和框架的特性

## 当前语言/框架上下文
- 语言: {language}
- 框架: {framework}
- 文件类型: {file_type}
"""

ANALYSIS_PROMPT = """你是一个安全规则专家。以下规则被红队成功绕过，请分析根因并给出修复方案。

## 被绕过的规则
- 规则ID: {rule_id}
- 当前模式: {pattern}
- 规则描述: {description}

## 成功绕过的用例
{bypass_cases}

## 任务
1. 分析绕过的根本原因（模式遗漏？语义理解不足？上下文缺失？）
2. 给出修复方案（扩展模式？增加上下文检查？引入AST分析？）
3. 评估修复后是否可能引入新误报
4. 给出修复后的规则定义

## 输出格式
```json
{{
    "root_cause": "根因分析",
    "fix_strategy": "修复策略",
    "new_pattern": "扩展后的匹配模式",
    "additional_checks": ["额外检查项1", "额外检查项2"],
    "false_positive_risk": "新误报风险评估",
    "confidence": 0.0-1.0
}}
```
"""


class RedTeamGenerator:
    """红队攻击用例生成器"""

    def __init__(self, llm_client=None, config: Dict[str, Any] = None):
        """
        初始化生成器

        Args:
            llm_client: LLM 客户端（支持 OpenAI 兼容接口）
            config: 配置
        """
        self.llm_client = llm_client
        self.config = config or {}
        self.default_count = self.config.get("default_count", 20)
        self.max_retries = self.config.get("max_retries", 3)
        self._cache: Dict[str, List[BypassCase]] = {}

    async def generate_bypasses(
        self,
        rule_id: str,
        description: str,
        pattern: str,
        category: str = "",
        severity: str = "MEDIUM",
        language: str = "javascript",
        framework: str = "",
        count: int = None,
        strategies: List[MutationStrategy] = None,
        difficulty_levels: List[DifficultyLevel] = None,
    ) -> GenerationResult:
        """
        生成绕过用例

        Args:
            rule_id: 目标规则ID
            description: 规则描述
            pattern: 匹配模式
            category: 漏洞类别
            severity: 严重级别
            language: 目标语言
            framework: 目标框架
            count: 生成数量
            strategies: 指定策略列表
            difficulty_levels: 指定难度级别

        Returns:
            GenerationResult: 生成结果
        """
        import time
        start = time.time()

        count = count or self.default_count
        strategies = strategies or list(MutationStrategy)
        difficulty_levels = difficulty_levels or list(DifficultyLevel)

        # 检查缓存
        cache_key = f"{rule_id}:{count}"
        if cache_key in self._cache:
            logger.info(f"Using cached bypass cases for {rule_id}")
            cases = self._cache[cache_key]
        else:
            # 构建策略描述
            strategies_desc = self._build_strategies_desc(strategies, difficulty_levels)

            # 调用 LLM 生成
            cases = await self._call_llm_for_generation(
                rule_id=rule_id,
                description=description,
                pattern=pattern,
                category=category,
                severity=severity,
                language=language,
                framework=framework,
                count=count,
                strategies_desc=strategies_desc,
            )

            # 缓存结果
            self._cache[cache_key] = cases

        # 统计
        difficulty_dist = {}
        strategies_used = set()
        for case in cases:
            difficulty_dist[case.difficulty.value] = difficulty_dist.get(case.difficulty.value, 0) + 1
            strategies_used.add(case.strategy.value)

        elapsed = (time.time() - start) * 1000

        return GenerationResult(
            rule_id=rule_id,
            total_cases=len(cases),
            cases=cases,
            strategies_used=list(strategies_used),
            difficulty_distribution=difficulty_dist,
            generation_time_ms=round(elapsed, 2),
        )

    async def generate_for_rule_set(
        self,
        rules: List[Dict[str, Any]],
        count_per_rule: int = 20,
    ) -> Dict[str, GenerationResult]:
        """批量为规则集生成绕过用例"""
        results = {}
        for rule in rules:
            try:
                result = await self.generate_bypasses(
                    rule_id=rule["rule_id"],
                    description=rule.get("description", ""),
                    pattern=rule.get("code_pattern", ""),
                    category=rule.get("category", ""),
                    severity=rule.get("severity", "MEDIUM"),
                    count=count_per_rule,
                )
                results[rule["rule_id"]] = result
            except Exception as e:
                logger.error(f"Failed to generate bypasses for {rule['rule_id']}: {e}")
        return results

    async def analyze_and_fix(
        self,
        rule_id: str,
        pattern: str,
        description: str,
        failed_cases: List[BypassCase],
    ) -> Dict[str, Any]:
        """
        分析绕过原因并生成修复方案（蓝队视角）

        Args:
            rule_id: 规则ID
            pattern: 当前模式
            description: 规则描述
            failed_cases: 被绕过的用例

        Returns:
            修复方案
        """
        # 构建绕过用例描述
        bypass_cases_desc = "\n".join([
            f"- [{case.difficulty.value}] {case.strategy.value}: {case.bypass_code[:100]}..."
            for case in failed_cases[:10]  # 最多10个用例
        ])

        prompt = ANALYSIS_PROMPT.format(
            rule_id=rule_id,
            pattern=pattern,
            description=description,
            bypass_cases=bypass_cases_desc,
        )

        if self.llm_client:
            response = await self._call_llm(prompt)
            try:
                return json.loads(response)
            except json.JSONDecodeError:
                return {"root_cause": "analysis_failed", "fix_strategy": "manual_review"}
        else:
            # 无 LLM 时的默认分析
            return self._default_analysis(rule_id, failed_cases)

    async def _call_llm_for_generation(
        self,
        rule_id: str,
        description: str,
        pattern: str,
        category: str,
        severity: str,
        language: str,
        framework: str,
        count: int,
        strategies_desc: str,
    ) -> List[BypassCase]:
        """调用 LLM 生成绕过用例"""
        prompt = BYPASS_GENERATION_PROMPT.format(
            rule_id=rule_id,
            description=description,
            pattern=pattern,
            category=category,
            severity=severity,
            count=count,
            strategies_desc=strategies_desc,
            language=language,
            framework=framework,
            file_type=f".{language}" if language else ".js",
        )

        if self.llm_client:
            response = await self._call_llm(prompt)
            try:
                raw_cases = json.loads(response)
                return self._parse_cases(rule_id, raw_cases)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse LLM response: {e}")
                return self._generate_fallback_cases(rule_id, pattern, count)
        else:
            # 无 LLM 时使用规则引擎生成
            return self._generate_fallback_cases(rule_id, pattern, count)

    async def _call_llm(self, prompt: str) -> str:
        """调用 LLM"""
        try:
            if hasattr(self.llm_client, 'chat'):
                # OpenAI 兼容接口
                response = await self.llm_client.chat.completions.create(
                    model=self.config.get("model", "gpt-4"),
                    messages=[{"role": "user", "content": prompt}],
                    temperature=self.config.get("temperature", 0.7),
                    max_tokens=self.config.get("max_tokens", 4000),
                )
                return response.choices[0].message.content
            elif hasattr(self.llm_client, 'generate'):
                # 自定义接口
                response = await self.llm_client.generate(prompt)
                return response
            else:
                raise ValueError("Unsupported LLM client interface")
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            raise

    def _parse_cases(self, rule_id: str, raw_cases: List[Dict]) -> List[BypassCase]:
        """解析 LLM 返回的用例"""
        cases = []
        for i, raw in enumerate(raw_cases):
            try:
                case_id = hashlib.md5(
                    f"{rule_id}:{i}:{raw.get('bypass_code', '')}".encode()
                ).hexdigest()[:12]

                case = BypassCase(
                    id=case_id,
                    rule_id=rule_id,
                    strategy=MutationStrategy(raw.get("strategy", "api_substitution")),
                    difficulty=DifficultyLevel(raw.get("difficulty", "L2")),
                    original_code="",  # 由调用方填充
                    bypass_code=raw.get("bypass_code", ""),
                    description=raw.get("description", ""),
                    expected_detected=raw.get("expected_detected", True),
                    is_exploitable=raw.get("is_exploitable", True),
                    exploit_scenario=raw.get("exploit_scenario"),
                    cwe=raw.get("cwe"),
                    tags=[raw.get("strategy", ""), raw.get("difficulty", "")],
                )
                cases.append(case)
            except Exception as e:
                logger.warning(f"Failed to parse case {i}: {e}")
        return cases

    def _generate_fallback_cases(
        self, rule_id: str, pattern: str, count: int
    ) -> List[BypassCase]:
        """无 LLM 时的后备生成（基于规则引擎）"""
        from .strategies import MUTATION_STRATEGIES

        cases = []
        strategies = list(MUTATION_STRATEGIES.values())

        for i in range(count):
            strategy = strategies[i % len(strategies)]
            try:
                bypass_code = strategy.apply(pattern, rule_id)
                case_id = hashlib.md5(
                    f"{rule_id}:{i}:{bypass_code}".encode()
                ).hexdigest()[:12]

                case = BypassCase(
                    id=case_id,
                    rule_id=rule_id,
                    strategy=strategy.name,
                    difficulty=strategy.difficulty,
                    original_code=pattern,
                    bypass_code=bypass_code,
                    description=strategy.description,
                    expected_detected=strategy.expected_detected,
                    is_exploitable=strategy.is_exploitable,
                    tags=[strategy.name.value, strategy.difficulty.value],
                )
                cases.append(case)
            except Exception as e:
                logger.warning(f"Strategy {strategy.name} failed: {e}")

        return cases

    def _build_strategies_desc(
        self,
        strategies: List[MutationStrategy],
        difficulty_levels: List[DifficultyLevel],
    ) -> str:
        """构建策略描述"""
        from .strategies import MUTATION_STRATEGIES

        desc_parts = []
        for strategy in strategies:
            if strategy in MUTATION_STRATEGIES:
                s = MUTATION_STRATEGIES[strategy]
                if s.difficulty in difficulty_levels:
                    desc_parts.append(f"- **{strategy.value}** ({s.difficulty.value}): {s.description}")

        return "\n".join(desc_parts) if desc_parts else "使用所有可用策略"

    def _default_analysis(
        self, rule_id: str, failed_cases: List[BypassCase]
    ) -> Dict[str, Any]:
        """默认分析（无 LLM）"""
        strategies = set(case.strategy for case in failed_cases)
        return {
            "root_cause": f"规则 {rule_id} 被 {len(strategies)} 种策略绕过",
            "fix_strategy": "扩展匹配模式，增加上下文检查",
            "new_pattern": "",
            "additional_checks": ["增加 AST 分析", "增加数据流追踪"],
            "false_positive_risk": "中等",
            "confidence": 0.5,
        }

    def clear_cache(self):
        """清除缓存"""
        self._cache.clear()
