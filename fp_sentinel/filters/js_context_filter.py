"""
JavaScript/TypeScript 上下文分析器

分析 JS/TS 代码上下文，识别误报:
- 框架检测 (React/Vue/Angular/jQuery)
- DOM 安全分析
- 数据流追踪
- 死代码检测
- 安全守卫识别
"""

import re
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

from ..models import (
    ScanResult, JSAnalysisResult,
    FilterResult, FilterReason, Verdict, Severity,
)
from ..rules.js import JS_SECURITY_GUARD_PATTERNS, FRAMEWORK_PATTERNS

logger = logging.getLogger(__name__)


class JSContextFilter:
    """JavaScript/TypeScript 上下文过滤器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.fp_threshold = self.config.get("false_positive_threshold", 0.5)
        self._context_cache: Dict[str, List[str]] = {}
        self._framework_cache: Dict[str, Optional[str]] = {}

    async def filter(self, scan_result: ScanResult) -> FilterResult:
        """过滤单条扫描结果"""
        reasons = []
        fp_score = 0.0

        # 1. 读取上下文
        context_lines = self._read_context(scan_result.file, scan_result.line)
        context_text = "\n".join(context_lines)

        # 2. 检测框架
        framework = self._detect_framework(scan_result.file, context_text)

        # 3. 死代码检测
        is_dead_code = self._check_dead_code(context_lines)
        if is_dead_code:
            fp_score += 0.8
            reasons.append(FilterReason(
                filter_level="L2",
                rule_name="js_dead_code",
                description="代码在死代码分支中",
                confidence=0.8,
            ))

        # 4. 安全守卫检测
        guard_result = self._check_security_guards(scan_result, context_lines)
        if guard_result["found"]:
            fp_score += guard_result["confidence"]
            reasons.append(FilterReason(
                filter_level="L2",
                rule_name="js_security_guard",
                description=guard_result["description"],
                confidence=guard_result["confidence"],
            ))

        # 5. 框架安全特性检测
        if framework:
            framework_result = self._check_framework_safety(
                scan_result, framework, context_lines
            )
            if framework_result["safe"]:
                fp_score += framework_result["confidence"]
                reasons.append(FilterReason(
                    filter_level="L2",
                    rule_name="js_framework_safety",
                    description=framework_result["description"],
                    confidence=framework_result["confidence"],
                ))

        # 6. 测试文件检测
        is_test = self._is_test_file(scan_result.file)
        if is_test:
            fp_score += 0.6
            reasons.append(FilterReason(
                filter_level="L2",
                rule_name="js_test_file",
                description="代码在测试文件中",
                confidence=0.6,
            ))

        # 7. 安全API使用检测
        uses_safe_api = self._check_safe_api_usage(context_lines, scan_result.rule_id)
        if uses_safe_api:
            fp_score += 0.4
            reasons.append(FilterReason(
                filter_level="L2",
                rule_name="js_safe_api",
                description="使用了安全的替代API",
                confidence=0.4,
            ))

        # 8. 构建JS分析结果
        js_analysis = JSAnalysisResult(
            uses_textContent=self._check_pattern(context_text, r"\.textContent\s*="),
            uses_innerHTML=self._check_pattern(context_text, r"\.innerHTML\s*="),
            has_sanitize_guard=guard_result["found"],
            is_framework_render=framework is not None,
            framework_type=framework,
            has_input_validation=self._check_input_validation(context_lines),
            uses_eval=self._check_pattern(context_text, r"\beval\s*\("),
            uses_safe_api=uses_safe_api,
            is_test_file=is_test,
            is_dead_code=is_dead_code,
            confidence_adjustment=fp_score,
        )

        # 9. 判定结果
        if fp_score >= self.fp_threshold:
            verdict = Verdict.FALSE_POSITIVE if fp_score >= 0.8 else Verdict.LIKELY_FALSE_POSITIVE
            confidence = min(fp_score, 1.0)
        else:
            verdict = Verdict.TRUE_POSITIVE
            confidence = 1.0 - fp_score

        # 10. 风险评分
        risk_score = self._calculate_risk_score(scan_result, fp_score)

        # 11. 建议
        recommendation = self._generate_recommendation(
            scan_result, verdict, js_analysis, framework
        )

        return FilterResult(
            original=scan_result,
            verdict=verdict,
            confidence=confidence,
            filter_reasons=reasons,
            risk_score=risk_score,
            recommendation=recommendation,
            js_analysis=js_analysis.model_dump(),
        )

    def _read_context(self, file_path: str, line_number: int, context_size: int = 20) -> List[str]:
        """读取文件上下文"""
        cache_key = f"{file_path}:{line_number}"
        if cache_key in self._context_cache:
            return self._context_cache[cache_key]

        try:
            path = Path(file_path)
            if not path.exists():
                return []

            lines = path.read_text(encoding="utf-8", errors="ignore").split("\n")
            start = max(0, line_number - context_size - 1)
            end = min(len(lines), line_number + context_size)
            context = lines[start:end]

            self._context_cache[cache_key] = context
            return context
        except Exception as e:
            logger.error(f"Failed to read context for {file_path}: {e}")
            return []

    def _detect_framework(self, file_path: str, context: str) -> Optional[str]:
        """检测使用的前端框架"""
        if file_path in self._framework_cache:
            return self._framework_cache[file_path]

        # 检查文件扩展名
        if file_path.endswith(".vue"):
            self._framework_cache[file_path] = "vue"
            return "vue"
        if file_path.endswith(".jsx") or file_path.endswith(".tsx"):
            self._framework_cache[file_path] = "react"
            return "react"

        # 检查代码模式
        for framework, patterns in FRAMEWORK_PATTERNS.items():
            for detect_pattern in patterns.get("detect", []):
                if re.search(detect_pattern, context, re.IGNORECASE):
                    self._framework_cache[file_path] = framework
                    return framework

        self._framework_cache[file_path] = None
        return None

    def _check_dead_code(self, context_lines: List[str]) -> bool:
        """检查是否为死代码"""
        dead_code_patterns = [
            r"if\s*\(\s*false\s*\)",
            r"if\s*\(\s*0\s*\)",
            r"if\s*\(\s*!true\s*\)",
            r"//\s*(TODO|FIXME|HACK).*remove",
            r"/\*.*disabled.*\*/",
            r"return;\s*//.*dead",
        ]

        for line in context_lines:
            for pattern in dead_code_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    return True
        return False

    def _check_security_guards(
        self, scan_result: ScanResult, context_lines: List[str]
    ) -> Dict[str, Any]:
        """检查安全守卫"""
        # 确定规则类别
        category = self._get_rule_category(scan_result.rule_id)
        if not category:
            return {"found": False, "confidence": 0.0, "description": ""}

        patterns = JS_SECURITY_GUARD_PATTERNS.get(category, [])
        if not patterns:
            return {"found": False, "confidence": 0.0, "description": ""}

        context_text = "\n".join(context_lines)
        for pattern in patterns:
            if re.search(pattern, context_text, re.IGNORECASE):
                return {
                    "found": True,
                    "confidence": 0.5,
                    "description": f"检测到安全守卫: {pattern}",
                }

        return {"found": False, "confidence": 0.0, "description": ""}

    def _check_framework_safety(
        self, scan_result: ScanResult, framework: str, context_lines: List[str]
    ) -> Dict[str, Any]:
        """检查框架安全特性"""
        fw_config = FRAMEWORK_PATTERNS.get(framework, {})
        if not fw_config:
            return {"safe": False, "confidence": 0.0, "description": ""}

        context_text = "\n".join(context_lines)

        # 检查是否使用了安全模式
        for pattern in fw_config.get("safe_patterns", []):
            if re.search(pattern, context_text, re.IGNORECASE):
                return {
                    "safe": True,
                    "confidence": 0.4,
                    "description": f"框架 {framework} 使用了安全模式",
                }

        # 检查是否自动转义
        if fw_config.get("auto_escape"):
            # 对于自动转义的框架，检查是否使用了危险模式
            for pattern in fw_config.get("dangerous_patterns", []):
                if re.search(pattern, context_text, re.IGNORECASE):
                    return {"safe": False, "confidence": 0.0, "description": ""}

            return {
                "safe": True,
                "confidence": 0.3,
                "description": f"框架 {framework} 默认自动转义",
            }

        return {"safe": False, "confidence": 0.0, "description": ""}

    def _is_test_file(self, file_path: str) -> bool:
        """检查是否为测试文件"""
        test_patterns = [
            r"\.test\.",
            r"\.spec\.",
            r"__tests__",
            r"test/",
            r"tests/",
            r"spec/",
            r"\.mock\.",
            r"__mocks__",
        ]
        for pattern in test_patterns:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False

    def _check_safe_api_usage(self, context_lines: List[str], rule_id: str) -> bool:
        """检查是否使用了安全的替代API"""
        context_text = "\n".join(context_lines)

        safe_alternatives = {
            "js.xss.innerhtml": [r"\.textContent\s*=", r"\.innerText\s*="],
            "js.injection.eval": [r"JSON\.parse", r"parseInt\s*\(", r"parseFloat\s*\("],
            "js.xss.document-write": [r"createElement", r"createTextNode"],
            "js.xss.jquery-html": [r"\.text\s*\("],
        }

        patterns = safe_alternatives.get(rule_id, [])
        for pattern in patterns:
            if re.search(pattern, context_text):
                return True
        return False

    def _check_input_validation(self, context_lines: List[str]) -> bool:
        """检查是否有输入验证"""
        validation_patterns = [
            r"(validate|check|verify|sanitize|escape)\s*\(",
            r"\.trim\s*\(",
            r"\.replace\s*\(",
            r"(isString|isNumber|isArray|isObject|isNaN)\s*\(",
            r"(typeof|instanceof)\s+",
            r"\.length\s*(>|<|===|!==)",
            r"(parseInt|parseFloat|Number)\s*\(",
            r"(match|test|exec)\s*\(\s*/",
        ]

        context_text = "\n".join(context_lines)
        for pattern in validation_patterns:
            if re.search(pattern, context_text):
                return True
        return False

    def _check_pattern(self, text: str, pattern: str) -> bool:
        """检查文本中是否存在模式"""
        return bool(re.search(pattern, text, re.IGNORECASE))

    def _get_rule_category(self, rule_id: str) -> Optional[str]:
        """从规则ID获取类别"""
        category_map = {
            "xss": "xss",
            "injection": "injection",
            "eval": "eval",
            "proto": "prototype_pollution",
            "crypto": "crypto",
            "secrets": "secrets",
            "command": "command_injection",
            "path": "path_traversal",
        }

        for key, category in category_map.items():
            if key in rule_id.lower():
                return category
        return None

    def _calculate_risk_score(self, scan_result: ScanResult, fp_score: float) -> float:
        """计算风险评分 (0-10)"""
        severity_scores = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 1.0,
        }

        base_score = severity_scores.get(scan_result.severity, 5.0)
        adjusted = base_score * (1.0 - fp_score)
        return round(max(0.0, min(10.0, adjusted)), 2)

    def _generate_recommendation(
        self,
        scan_result: ScanResult,
        verdict: Verdict,
        js_analysis: JSAnalysisResult,
        framework: Optional[str],
    ) -> str:
        """生成处理建议"""
        if verdict == Verdict.FALSE_POSITIVE:
            return "已判定为误报，可安全忽略"
        elif verdict == Verdict.LIKELY_FALSE_POSITIVE:
            return "疑似误报，建议人工复核"

        # 真实问题的建议
        recommendations = {
            "xss": "使用 textContent 替代 innerHTML，或使用 DOMPurify 进行消毒",
            "eval": "避免使用 eval()，使用 JSON.parse() 或安全的替代方案",
            "injection": "对用户输入进行严格的验证和转义",
            "crypto": "使用 Web Crypto API 或经过验证的加密库",
            "secrets": "将敏感信息移至环境变量或安全存储",
            "prototype_pollution": "使用 Object.create(null) 或 Map 代替普通对象",
        }

        category = self._get_rule_category(scan_result.rule_id) or ""
        base_rec = recommendations.get(category, "请进行人工安全审查")

        if framework:
            base_rec += f" (当前框架: {framework})"

        return base_rec

    def clear_cache(self):
        """清除缓存"""
        self._context_cache.clear()
        self._framework_cache.clear()
