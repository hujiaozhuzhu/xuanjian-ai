"""
L2: 上下文过滤器

基于代码上下文分析，识别：
- 死代码路径
- 安全守卫措施 (PreparedStatement, ORM, escape)
- 输入验证逻辑
- Java 特定分析 (MyBatis #{} vs ${}, Spring Security, etc.)
"""

import re
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path
from ..models import (
    ScanResult, FilterResult, FilterReason, Verdict,
    ContextAnalysisResult, JavaAnalysisResult, ScanTool,
)


class ContextFilter:
    """L2 上下文过滤器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.fp_threshold = self.config.get("false_positive_threshold", 0.5)
        self._file_cache: Dict[str, str] = {}

        # Java 安全守卫关键词
        self.java_security_guards = [
            "PreparedStatement", "prepareStatement", "setParameter",
            "createQuery", "createNamedQuery", "CriteriaBuilder",
            "#{}", "setParameterList", "bindValue",
            "HtmlUtils.htmlEscape", "StringEscapeUtils.escapeHtml",
            "URLEncoder.encode", "UriComponentsBuilder",
            "Whitelist", "Safelist", "Jsoup.clean",
            "Escapers", "HtmlEscapers",
        ]

        # Java 输入验证关键词
        self.java_validation_keywords = [
            "isValid", "validate", "checkNotNull", "checkArgument",
            "checkState", "Preconditions", "assertNotNull",
            "@Valid", "@NotNull", "@NotEmpty", "@NotBlank",
            "@Size", "@Min", "@Max", "@Pattern",
            "StringUtils.isNotEmpty", "StringUtils.isNotBlank",
            "Objects.requireNonNull",
        ]

        # Python 安全守卫关键词
        self.python_security_guards = [
            "sanitize", "escape", "validate", "verify", "check",
            "clean", "purify", "encode", "hash", "encrypt",
            "parameterized", "prepared", "query",
            "bleach.clean", "markupsafe.escape", "html.escape",
            "quote_plus", "url_encode",
        ]

        # 死代码模式
        self.dead_code_patterns = [
            r"if\s+False\s*:", r"if\s+0\s*:", r"if\s+false\s*;",
            r"if\s*\(\s*false\s*\)",  # Java if(false)
            r"if\s*\(\s*0\s*\)",      # Java if(0)
            r"//.*TODO.*remove", r"#.*TODO.*remove",
            r"//.*FIXME.*dead", r"#.*FIXME.*dead",
            r"^\s*pass\s*$", r"^\s*\.\.\.\s*$",
            r"return;\s*//.*unreachable",
        ]
        self._dead_code_re = [re.compile(p, re.MULTILINE) for p in self.dead_code_patterns]

    async def filter(self, scan_result: ScanResult) -> FilterResult:
        """过滤单条扫描结果"""
        if not self.enabled:
            return self._pass_through(scan_result)

        # 读取文件上下文
        context = self._read_context(scan_result)
        if context is None:
            return self._pass_through(scan_result)

        # 通用上下文分析
        ctx_result = self._analyze_context(scan_result, context)

        # Java 特定分析
        java_result = None
        if scan_result.tool in (ScanTool.SEMGREP, ScanTool.FINDSECBUGS, ScanTool.SPOTBUGS):
            if self._is_java_file(scan_result.file):
                java_result = self._analyze_java(scan_result, context)

        # 计算误报分数
        fp_score, reasons = self._evaluate(scan_result, ctx_result, java_result)

        if fp_score >= self.fp_threshold:
            verdict = Verdict.LIKELY_FALSE_POSITIVE
        else:
            verdict = Verdict.NEEDS_REVIEW

        return FilterResult(
            id=scan_result.id,
            original=scan_result,
            verdict=verdict,
            confidence=min(1.0, fp_score),
            filter_reasons=reasons,
            risk_score=self._calc_risk(scan_result, fp_score >= self.fp_threshold, fp_score),
            recommendation=self._gen_recommendation(verdict, fp_score),
            context_analysis=ctx_result.model_dump() if ctx_result else None,
            java_analysis=java_result.model_dump() if java_result else None,
        )

    def _read_context(self, scan_result: ScanResult) -> Optional[List[str]]:
        """读取文件上下文行"""
        file_path = scan_result.file
        if file_path in self._file_cache:
            lines = self._file_cache[file_path].split('\n')
        else:
            path = Path(file_path)
            if not path.exists():
                return None
            try:
                content = path.read_text(encoding='utf-8', errors='ignore')
                self._file_cache[file_path] = content
                lines = content.split('\n')
            except Exception:
                return None

        # 返回漏洞行前后20行
        start = max(0, scan_result.line - 21)
        end = min(len(lines), scan_result.line + 20)
        return lines[start:end]

    def _analyze_context(
        self, scan_result: ScanResult, context_lines: List[str]
    ) -> ContextAnalysisResult:
        """通用上下文分析"""
        context_text = '\n'.join(context_lines)

        is_dead_code = self._detect_dead_code(context_text)
        is_in_test = self._detect_test_file(scan_result.file)
        is_in_debug = self._detect_debug_branch(context_text)

        # 检测安全守卫
        guards = []
        all_guards = self.java_security_guards + self.python_security_guards
        for g in all_guards:
            if g.lower() in context_text.lower():
                guards.append(g)

        # 检测输入验证
        validations = []
        for v in self.java_validation_keywords:
            if v.lower() in context_text.lower():
                validations.append(v)

        return ContextAnalysisResult(
            file_path=scan_result.file,
            line_number=scan_result.line,
            is_dead_code=is_dead_code,
            has_security_guards=len(guards) > 0,
            has_input_validation=len(validations) > 0,
            is_in_test=is_in_test,
            is_in_debug_branch=is_in_debug,
            data_flow_length=self._estimate_data_flow(context_lines),
            complexity_score=self._calc_complexity(context_lines),
            context_features={
                "guard_keywords": guards,
                "validation_keywords": validations,
            },
        )

    def _analyze_java(
        self, scan_result: ScanResult, context_lines: List[str]
    ) -> JavaAnalysisResult:
        """Java 特定上下文分析"""
        context_text = '\n'.join(context_lines)

        # 检测 PreparedStatement
        uses_ps = bool(re.search(
            r'prepareStatement|PreparedStatement|createQuery|createQuery', context_text
        ))

        # 检测 ORM
        uses_orm = bool(re.search(
            r'@Entity|@Repository|JpaRepository|CrudRepository|HibernateTemplate|SessionFactory',
            context_text
        ))

        # 检测 MyBatis #{} vs ${}
        uses_mybatis_hash = '#{' in context_text
        uses_mybatis_dollar = '${' in context_text

        # 检测 HTML 转义
        uses_escape = bool(re.search(
            r'htmlEscape|escapeHtml|HtmlUtils|StringEscapeUtils|Jsoup\.clean|Safelist',
            context_text
        ))

        # 检测常量值
        is_constant = bool(re.search(
            r'(?:final\s+String|private\s+static\s+final|String\s+\w+\s*=\s*"[^"]*"\s*;)',
            context_text
        ))

        # 检测框架
        frameworks = []
        if 'Spring' in context_text or '@Controller' in context_text or '@RestController' in context_text:
            frameworks.append('spring')
        if 'MyBatis' in context_text or '@Mapper' in context_text or '@Select' in context_text:
            frameworks.append('mybatis')
        if '@Entity' in context_text or 'JPA' in context_text:
            frameworks.append('jpa')

        # 检测 URL 白名单
        has_url_whitelist = bool(re.search(
            r'whitelist|allowlist|allowedHosts|isValidUrl|validateUrl', context_text, re.IGNORECASE
        ))

        # 检测命令白名单
        has_cmd_whitelist = bool(re.search(
            r'allowedCommands|commandWhitelist|isAllowedCommand', context_text, re.IGNORECASE
        ))

        # 检测输入校验
        has_validation = bool(re.search(
            r'@Valid|@NotNull|@NotEmpty|@NotBlank|@Size|@Min|@Max|@Pattern|isValid|validate',
            context_text
        ))

        # 置信度调整
        adjustment = 0.0
        if uses_ps and 'sql' in scan_result.rule_id.lower():
            adjustment += 0.3
        if uses_orm and 'sql' in scan_result.rule_id.lower():
            adjustment += 0.25
        if uses_mybatis_hash and not uses_mybatis_dollar:
            adjustment += 0.3
        if uses_escape and 'xss' in scan_result.rule_id.lower():
            adjustment += 0.3
        if is_constant:
            adjustment += 0.2
        if has_url_whitelist and 'ssrf' in scan_result.rule_id.lower():
            adjustment += 0.25
        if has_cmd_whitelist and 'command' in scan_result.rule_id.lower():
            adjustment += 0.25

        return JavaAnalysisResult(
            uses_prepared_statement=uses_ps,
            uses_orm=uses_orm,
            uses_mybatis_hash=uses_mybatis_hash,
            uses_mybatis_dollar=uses_mybatis_dollar,
            has_input_validation=has_validation,
            has_url_whitelist=has_url_whitelist,
            has_command_whitelist=has_cmd_whitelist,
            uses_html_escape=uses_escape,
            is_constant_value=is_constant,
            framework_hints=frameworks,
            confidence_adjustment=adjustment,
        )

    def _evaluate(
        self,
        scan_result: ScanResult,
        ctx: ContextAnalysisResult,
        java_ctx: Optional[JavaAnalysisResult],
    ) -> Tuple[float, List[FilterReason]]:
        """评估误报可能性"""
        score = 0.0
        reasons = []

        # 死代码
        if ctx.is_dead_code:
            score += 0.8
            reasons.append(FilterReason(
                filter_level="L2", rule_name="dead_code",
                description="代码在死代码路径中，不可达", confidence=0.8,
            ))

        # 测试文件
        if ctx.is_in_test:
            score += 0.6
            reasons.append(FilterReason(
                filter_level="L2", rule_name="test_file",
                description="代码位于测试文件中", confidence=0.7,
            ))

        # 调试分支
        if ctx.is_in_debug_branch:
            score += 0.4
            reasons.append(FilterReason(
                filter_level="L2", rule_name="debug_branch",
                description="代码位于调试/开发分支中", confidence=0.5,
            ))

        # 安全守卫
        if ctx.has_security_guards:
            guards = ctx.context_features.get("guard_keywords", [])
            score += 0.5
            reasons.append(FilterReason(
                filter_level="L2", rule_name="security_guard",
                description=f"检测到安全守卫: {', '.join(guards[:3])}", confidence=0.6,
            ))

        # 输入验证
        if ctx.has_input_validation:
            score += 0.3
            reasons.append(FilterReason(
                filter_level="L2", rule_name="input_validation",
                description="检测到输入验证逻辑", confidence=0.4,
            ))

        # Java 特定调整
        if java_ctx:
            adj = java_ctx.confidence_adjustment
            if adj > 0:
                score += adj
                hints = []
                if java_ctx.uses_prepared_statement:
                    hints.append("PreparedStatement")
                if java_ctx.uses_orm:
                    hints.append("ORM框架")
                if java_ctx.uses_mybatis_hash and not java_ctx.uses_mybatis_dollar:
                    hints.append("MyBatis #{}参数绑定")
                if java_ctx.uses_html_escape:
                    hints.append("HTML转义")
                if java_ctx.is_constant_value:
                    hints.append("常量值")
                if hints:
                    reasons.append(FilterReason(
                        filter_level="L2", rule_name="java_security_analysis",
                        description=f"Java安全分析: {', '.join(hints)}", confidence=min(1.0, adj),
                    ))

        return min(1.0, score), reasons

    def _detect_dead_code(self, context: str) -> bool:
        for p in self._dead_code_re:
            if p.search(context):
                return True
        return False

    def _detect_test_file(self, file_path: str) -> bool:
        test_patterns = [
            "test_", "_test.", "tests/", "test/",
            "Test.java", "Tests.java", "IT.java",
            "spec_", "_spec.", "specs/",
            "__tests__", "__test__",
        ]
        fp = file_path.lower()
        return any(p.lower() in fp for p in test_patterns)

    def _detect_debug_branch(self, context: str) -> bool:
        return bool(re.search(
            r'if\s*\(\s*(?:DEBUG|isDebug|isDev|ENV\s*==\s*"development")',
            context, re.IGNORECASE,
        ))

    def _estimate_data_flow(self, lines: List[str]) -> int:
        for i, line in enumerate(reversed(lines)):
            stripped = line.strip()
            if any(stripped.startswith(k) for k in [
                "def ", "public ", "private ", "protected ", "static ",
                "void ", "int ", "String ", "function ",
            ]):
                return i
        return len(lines)

    def _calc_complexity(self, lines: List[str]) -> float:
        context = '\n'.join(lines)
        score = 0.0
        for kw in ['if', 'else', 'for', 'while', 'switch', 'case', 'try', 'catch', 'except']:
            score += context.count(kw) * 0.5
        return min(10.0, score)

    def _is_java_file(self, path: str) -> bool:
        return path.endswith('.java') or path.endswith('.class')

    def _calc_risk(self, scan_result: ScanResult, is_fp: bool, confidence: float) -> float:
        base = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 1.0}.get(
            scan_result.severity.value, 5.0
        )
        if is_fp:
            return round(base * (1 - confidence * 0.8), 2)
        return round(base * confidence, 2)

    def _gen_recommendation(self, verdict: Verdict, confidence: float) -> str:
        if verdict == Verdict.LIKELY_FALSE_POSITIVE:
            if confidence > 0.8:
                return "上下文分析强烈表明为误报，建议忽略"
            return "上下文分析表明可能为误报，建议人工确认"
        return "上下文分析未发现明显误报特征，需要进一步审查"

    def _pass_through(self, scan_result: ScanResult) -> FilterResult:
        return FilterResult(
            id=scan_result.id,
            original=scan_result,
            verdict=Verdict.NEEDS_REVIEW,
            confidence=0.5,
            filter_reasons=[],
            risk_score=self._calc_risk(scan_result, False, 0.5),
            recommendation="L2上下文分析未执行，传递到L3",
        )
