"""
四级降噪引擎

L1 语法降噪: 白名单注释、安全函数、常量表达式、测试文件 (< 5ms/file)
L2 语义降噪: 框架安全特性、MVC分层、安全装饰器 (< 50ms/file)
L3 统计降噪: 误报指纹、置信度评分、聚类去重 (< 100ms/100条)
L4 智能降噪: LLM边界判断 (仅边界案例，< 10次调用/扫描)
"""

import re
import hashlib
import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class FilterResult:
    """过滤结果"""
    passed: bool          # True=保留, False=过滤掉
    reason: str = ""
    confidence: float = 1.0
    filter_level: str = ""


# ─────────────────────── L1 语法降噪 ───────────────────────

class NoiseReducerL1:
    """基于语法特征的快速过滤 (< 5ms/file)"""

    # 白名单注释标记
    WHITELIST_COMMENTS = [
        r"#\s*nosec",
        r"#\s*noqa",
        r"#\s*fp-sentinel-ignore",
        r"//\s*NOSONAR",
        r"//\s*nosec",
        r"//\s*eslint-disable",
        r"@SuppressWarnings",
        r"@SuppressWarnings\(",
        r"/\*\s*safe\s*\*/",
        r"#\s*type:\s*ignore",
    ]

    # 安全函数调用
    SAFE_FUNCTIONS = [
        # Python
        r"django\.utils\.html\.escape",
        r"html\.escape",
        r"bleach\.clean",
        r"markupsafe\.escape",
        r"jinja2\.escape",
        r"yaml\.safe_load",
        r"yaml\.safe_load_all",
        r"json\.loads",  # JSON.parse 是安全的
        r"shlex\.quote",
        r"shlex\.split",
        r"subprocess\.list2cmdline",
        # JavaScript
        r"DOMPurify\.sanitize",
        r"textContent\s*=",
        r"innerText\s*=",
        r"createTextNode",
        r"createElement",
        r"JSON\.parse",
        r"encodeURIComponent",
        r"encodeURI",
        # Java
        r"PreparedStatement",
        r"parameterized",
        r"HtmlUtils\.htmlEscape",
        r"StringEscapeUtils\.escape",
    ]

    # 测试文件模式
    TEST_FILE_PATTERNS = [
        r"test_.*\.py$",
        r".*_test\.py$",
        r".*Test\.java$",
        r".*Tests\.java$",
        r".*\.test\.(js|ts|jsx|tsx)$",
        r".*\.spec\.(js|ts|jsx|tsx)$",
        r"__tests__/.*",
        r"test/.*",
        r"tests/.*",
        r"spec/.*",
        r".*/mock.*",
        r".*/fixture.*",
        r".*/stub.*",
    ]

    # 常量表达式模式
    CONSTANT_PATTERNS = [
        r'eval\s*\(\s*["\'][^"\']+["\']\s*\)',     # eval("1+1")
        r'exec\s*\(\s*["\'][^"\']+["\']\s*\)',     # exec("print(1)")
        r'os\.system\s*\(\s*["\'][^"\']+["\']\s*\)',  # os.system("ls")
        r'eval\s*\(\s*\d+',                          # eval(123)
    ]

    def filter(self, finding) -> FilterResult:
        """L1 过滤单条发现"""
        code = getattr(finding, 'code_snippet', '') or getattr(finding, 'code', '')
        file_path = getattr(finding, 'file_path', '') or getattr(finding, 'file', '')

        # 1. 白名单注释检查
        if self._has_whitelist_comment(code):
            return FilterResult(False, "白名单注释", 0.95, "L1")

        # 2. 测试文件检查
        if self._is_test_file(file_path):
            return FilterResult(False, "测试文件", 0.85, "L1")

        # 3. 常量表达式检查
        if self._is_constant_expression(code):
            return FilterResult(False, "常量表达式", 0.9, "L1")

        # 4. 安全函数检查
        if self._uses_safe_function(code):
            return FilterResult(False, "安全函数", 0.8, "L1")

        return FilterResult(True, "通过L1", 1.0, "L1")

    def _has_whitelist_comment(self, code: str) -> bool:
        for pattern in self.WHITELIST_COMMENTS:
            if re.search(pattern, code, re.IGNORECASE):
                return True
        return False

    def _is_test_file(self, file_path: str) -> bool:
        if not file_path:
            return False
        for pattern in self.TEST_FILE_PATTERNS:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False

    def _is_constant_expression(self, code: str) -> bool:
        for pattern in self.CONSTANT_PATTERNS:
            if re.search(pattern, code):
                return True
        return False

    def _uses_safe_function(self, code: str) -> bool:
        for pattern in self.SAFE_FUNCTIONS:
            if re.search(pattern, code):
                return True
        return False


# ─────────────────────── L2 语义降噪 ───────────────────────

class NoiseReducerL2:
    """基于AST上下文的安全语义分析 (< 50ms/file)"""

    # 框架安全装饰器/注解
    SECURITY_DECORATORS = [
        # Python
        r"@login_required",
        r"@require_auth",
        r"@csrf_protect",
        r"@csrf_exempt",  # 注意：这个可能是风险
        r"@permission_required",
        r"@staff_member_required",
        r"@user_passes_test",
        r"@method_decorator",
        # Java/Spring
        r"@PreAuthorize",
        r"@Secured",
        r"@RolesAllowed",
        r"@PreFilter",
        r"@PostAuthorize",
        # Node/Express
        r"requireAuth",
        r"authenticate",
        r"authorize",
        r"passport\.authenticate",
    ]

    # 安全框架特征
    SAFE_FRAMEWORK_PATTERNS = {
        "django_orm": [
            r"\.objects\.(filter|get|all|exclude|annotate)\(",
            r"\.objects\.create\(",
            r"Q\(.*\)",
            r"F\(.*\)",
        ],
        "sqlalchemy": [
            r"\.query\.(filter|filter_by|all|first)\(",
            r"select\(\[",
            r"session\.(add|commit|query)\(",
        ],
        "spring_data": [
            r"@Repository",
            r"JpaRepository",
            r"CrudRepository",
            r"@Query.*nativeQuery\s*=\s*false",
        ],
        "mybatis_hash": [
            r"#\{[^}]+\}",  # #{} 是安全的参数绑定
        ],
    }

    # 输入校验函数
    VALIDATION_FUNCTIONS = [
        r"(validate|check|verify|sanitize|escape|clean|purify)\s*\(",
        r"(isinstance|type)\s*\(",
        r"\.strip\s*\(",
        r"\.replace\s*\(",
        r"(re\.match|re\.search|re\.fullmatch)\s*\(",
        r"(int|float|str|bool)\s*\(",  # 类型转换
        r"(parseInt|parseFloat|Number|Boolean)\s*\(",
        r"Schema\(|validate\(|Joi\.",
    ]

    def filter(self, finding, context_lines: List[str] = None) -> FilterResult:
        """L2 过滤单条发现"""
        code = getattr(finding, 'code_snippet', '') or getattr(finding, 'code', '')
        rule_id = getattr(finding, 'rule_id', '')

        if context_lines is None:
            context_lines = [code]

        context_text = "\n".join(context_lines)

        # 1. 安全装饰器检查
        if self._has_security_decorator(context_text):
            return FilterResult(False, "安全装饰器", 0.75, "L2")

        # 2. 框架安全特性检查
        if self._uses_safe_framework(code, rule_id):
            return FilterResult(False, "框架安全特性", 0.8, "L2")

        # 3. 输入校验检查
        if self._has_input_validation(context_text):
            return FilterResult(False, "输入校验", 0.6, "L2")

        # 4. MVC分层检查
        if self._is_protected_by_mvc(context_text, rule_id):
            return FilterResult(False, "MVC分层保护", 0.7, "L2")

        return FilterResult(True, "通过L2", 1.0, "L2")

    def _has_security_decorator(self, context: str) -> bool:
        for pattern in self.SECURITY_DECORATORS:
            if re.search(pattern, context):
                return True
        return False

    def _uses_safe_framework(self, code: str, rule_id: str) -> bool:
        """检查是否使用了安全的框架特性"""
        if "sql" in rule_id.lower():
            for fw_patterns in self.SAFE_FRAMEWORK_PATTERNS.values():
                for pattern in fw_patterns:
                    if re.search(pattern, code):
                        return True
        return False

    def _has_input_validation(self, context: str) -> bool:
        for pattern in self.VALIDATION_FUNCTIONS:
            if re.search(pattern, context):
                return True
        return False

    def _is_protected_by_mvc(self, context: str, rule_id: str) -> bool:
        """检查是否在MVC保护层内"""
        # Controller层有@Valid注解
        if re.search(r"@Valid|@RequestBody|@PathVariable|@RequestParam", context):
            if "sql" in rule_id.lower() or "injection" in rule_id.lower():
                return True
        return False


# ─────────────────────── L3 统计降噪 ───────────────────────

class NoiseReducerL3:
    """基于历史数据的统计过滤 (< 100ms/100条)"""

    def __init__(self, db_path: str = None):
        self.fp_fingerprints: Set[str] = set()
        self.rule_stats: Dict[str, Dict[str, float]] = {}
        self._seen_fingerprints: Set[str] = set()

        if db_path:
            self._load_fingerprints(db_path)

    def _load_fingerprints(self, db_path: str):
        """加载历史误报指纹"""
        import sqlite3
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.execute("SELECT fingerprint FROM false_positives")
            for row in cursor:
                self.fp_fingerprints.add(row[0])
            conn.close()
        except Exception as e:
            logger.debug(f"Failed to load fingerprints: {e}")

    def filter(self, finding) -> FilterResult:
        """L3 过滤单条发现"""
        # 1. 误报指纹匹配
        fingerprint = self._compute_fingerprint(finding)
        if fingerprint in self.fp_fingerprints:
            return FilterResult(False, "历史误报指纹", 0.9, "L3")

        # 2. 重复检测去重
        if fingerprint in self._seen_fingerprints:
            return FilterResult(False, "重复检测", 0.95, "L3")
        self._seen_fingerprints.add(fingerprint)

        # 3. 规则置信度评分
        rule_id = getattr(finding, 'rule_id', '')
        confidence = self._get_rule_confidence(rule_id)
        if confidence < 0.3:
            return FilterResult(False, f"规则置信度过低({confidence:.2f})", confidence, "L3")

        return FilterResult(True, "通过L3", confidence, "L3")

    def _compute_fingerprint(self, finding) -> str:
        """计算发现的指纹"""
        file_path = getattr(finding, 'file_path', '') or getattr(finding, 'file', '')
        line = getattr(finding, 'line_start', 0) or getattr(finding, 'line', 0)
        code = getattr(finding, 'code_snippet', '') or getattr(finding, 'code', '')
        rule_id = getattr(finding, 'rule_id', '')

        # 规范化代码（去除空白）
        normalized = re.sub(r'\s+', '', code)[:100]
        raw = f"{file_path}:{rule_id}:{normalized}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _get_rule_confidence(self, rule_id: str) -> float:
        """获取规则置信度"""
        if rule_id in self.rule_stats:
            stats = self.rule_stats[rule_id]
            detection_rate = stats.get("detection_rate", 0.5)
            fp_rate = stats.get("fp_rate", 0.5)
            return detection_rate * (1 - fp_rate)
        return 0.7  # 默认置信度

    def add_fp_fingerprint(self, finding):
        """添加误报指纹"""
        fp = self._compute_fingerprint(finding)
        self.fp_fingerprints.add(fp)

    def clear_cache(self):
        """清除去重缓存"""
        self._seen_fingerprints.clear()


# ─────────────────────── L4 智能降噪 ───────────────────────

class NoiseReducerL4:
    """LLM辅助的边界案例判断"""

    BOUNDARY_JUDGMENT_PROMPT = """你是一个资深安全审计师，请判断以下代码是否存在真实安全风险。

代码片段:
```{language}
{code}
```

上下文:
- 文件: {file_path}
- 规则: {rule_id}
- 描述: {description}

请判定:
1. 是否存在真实安全风险?
2. 是否有合理的安全守卫?
3. 建议的判定: TRUE_POSITIVE / FALSE_POSITIVE / LIKELY_FALSE_POSITIVE

返回JSON格式:
{{"verdict": "...", "confidence": 0.0-1.0, "reasoning": "..."}}
"""

    def __init__(self, llm_client=None, cache_size: int = 1000):
        self.llm = llm_client
        self.cache: Dict[str, FilterResult] = {}
        self.cache_size = cache_size
        self.call_count = 0
        self.max_calls = 10  # 单次扫描最大调用次数

    async def filter(self, finding) -> FilterResult:
        """L4 过滤（仅边界案例触发）"""
        # 检查调用次数限制
        if self.call_count >= self.max_calls:
            return FilterResult(True, "L4调用上限", 0.5, "L4")

        # 检查缓存
        fingerprint = self._compute_fingerprint(finding)
        if fingerprint in self.cache:
            return self.cache[fingerprint]

        # 无LLM时跳过
        if not self.llm:
            return FilterResult(True, "无LLM", 0.5, "L4")

        # 调用LLM判断
        try:
            code = getattr(finding, 'code_snippet', '') or getattr(finding, 'code', '')
            prompt = self.BOUNDARY_JUDGMENT_PROMPT.format(
                language="javascript",
                code=code[:500],
                file_path=getattr(finding, 'file_path', ''),
                rule_id=getattr(finding, 'rule_id', ''),
                description=getattr(finding, 'message', ''),
            )

            response = await self._call_llm(prompt)
            import json
            result_data = json.loads(response)

            verdict = result_data.get("verdict", "NEEDS_REVIEW")
            confidence = result_data.get("confidence", 0.5)

            is_fp = verdict in ("FALSE_POSITIVE", "LIKELY_FALSE_POSITIVE")
            result = FilterResult(
                passed=not is_fp,
                reason=f"LLM判断: {result_data.get('reasoning', '')[:100]}",
                confidence=confidence,
                filter_level="L4",
            )

            # 缓存结果
            if len(self.cache) < self.cache_size:
                self.cache[fingerprint] = result

            return result

        except Exception as e:
            logger.error(f"L4 filter error: {e}")
            return FilterResult(True, "L4异常", 0.5, "L4")

    async def _call_llm(self, prompt: str) -> str:
        self.call_count += 1
        if hasattr(self.llm, 'chat'):
            response = await self.llm.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=500,
            )
            return response.choices[0].message.content
        elif hasattr(self.llm, 'generate'):
            return await self.llm.generate(prompt)
        raise ValueError("Unsupported LLM client")

    def _compute_fingerprint(self, finding) -> str:
        code = getattr(finding, 'code_snippet', '') or getattr(finding, 'code', '')
        return hashlib.md5(code[:200].encode()).hexdigest()


# ─────────────────────── 降噪流水线 ───────────────────────

class NoisePipeline:
    """四级降噪流水线"""

    def __init__(
        self,
        enable_l1: bool = True,
        enable_l2: bool = True,
        enable_l3: bool = True,
        enable_l4: bool = False,
        l3_db_path: str = None,
        llm_client=None,
    ):
        self.l1 = NoiseReducerL1() if enable_l1 else None
        self.l2 = NoiseReducerL2() if enable_l2 else None
        self.l3 = NoiseReducerL3(l3_db_path) if enable_l3 else None
        self.l4 = NoiseReducerL4(llm_client) if enable_l4 and llm_client else None

        self.stats = {
            "total": 0,
            "l1_filtered": 0,
            "l2_filtered": 0,
            "l3_filtered": 0,
            "l4_filtered": 0,
            "passed": 0,
        }

    async def process(self, findings: List[Any], context_provider=None) -> List[Any]:
        """处理发现列表"""
        self.stats["total"] = len(findings)
        passed = []

        for finding in findings:
            result = await self._filter_single(finding, context_provider)
            if result.passed:
                passed.append(finding)
            else:
                self._update_stats(result.filter_level)

        self.stats["passed"] = len(passed)
        return passed

    async def _filter_single(self, finding, context_provider=None) -> FilterResult:
        """过滤单条发现"""
        # L1 语法降噪
        if self.l1:
            result = self.l1.filter(finding)
            if not result.passed:
                return result

        # L2 语义降噪
        if self.l2:
            context_lines = None
            if context_provider:
                context_lines = context_provider.get_context(finding)
            result = self.l2.filter(finding, context_lines)
            if not result.passed:
                return result

        # L3 统计降噪
        if self.l3:
            result = self.l3.filter(finding)
            if not result.passed:
                return result

        # L4 智能降噪（仅边界案例）
        if self.l4:
            # 获取置信度，仅对边界案例(0.3-0.7)触发L4
            confidence = self._get_confidence(finding)
            if 0.3 <= confidence <= 0.7:
                result = await self.l4.filter(finding)
                if not result.passed:
                    return result

        return FilterResult(True, "通过全部", 1.0, "ALL")

    def _get_confidence(self, finding) -> float:
        """获取综合置信度"""
        return getattr(finding, 'confidence', 0.5) or 0.5

    def _update_stats(self, level: str):
        key = f"{level.lower()}_filtered"
        if key in self.stats:
            self.stats[key] += 1

    def get_stats(self) -> Dict[str, int]:
        return self.stats.copy()

    def reset_stats(self):
        for key in self.stats:
            self.stats[key] = 0
