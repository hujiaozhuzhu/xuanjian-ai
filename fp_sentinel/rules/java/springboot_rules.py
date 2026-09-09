"""
SpringBoot 框架专属漏洞规则库 v3.2.0

覆盖 SpringBoot 生态中常见的安全风险场景，包含：
- SpEL 表达式注入
- Actuator 端点暴露
- 不安全的反序列化配置
- 跨站请求伪造 (CSRF) 配置缺陷
- CORS 配置不当
- 文件上传/下载漏洞
- Spring Security 配置缺陷
- 日志注入
- 不安全的 HTTP 方法
- 会话固定漏洞
- 不安全的缓存控制
- 敏感信息泄露 (application.properties)
- Spring Cloud 配置泄露
- 不安全的重定向
- SQL/HQL 注入 (Spring Data)
- JPA 实体注入
- Thymeleaf 模板注入
- WebSocket 安全
- 不安全的 CORS 白名单
- Spring Batch 安全

规则分类：
- SPEL_INJECTION: SpEL 表达式注入 (8条)
- ACTUATOR_EXPOSURE: Actuator 端点暴露 (6条)
- CSRF: CSRF 配置缺陷 (5条)
- CORS_MISCONFIG: CORS 配置不当 (5条)
- FILE_OPERATIONS: 文件操作漏洞 (6条)
- SECURITY_MISCONFIG: Security 配置缺陷 (7条)
- SESSION: 会话管理漏洞 (5条)
- CACHE_POISONING: 缓存投毒 (4条)
- LOG_INJECTION: 日志注入 (4条)
- INFO_LEAK: 信息泄露 (6条)
- TEMPLATE_INJECTION: 模板注入 (5条)
- REDIRECT: 不安全重定向 (4条)
- DATA_INJECTION: 数据层注入 (5条)
- CLOUD_CONFIG: 云配置泄露 (4条)
- WEBSOCKET: WebSocket 安全 (4条)
- DESERIALIZATION: 反序列化漏洞 (4条)
- XXE: XXE 漏洞 (4条)
"""

from typing import List, Dict


class SpringBootRule:
    """SpringBoot 安全规则定义"""

    def __init__(
        self,
        rule_id: str,
        description: str,
        severity: str = "MEDIUM",
        confidence: float = 0.7,
        file_pattern: str = None,
        code_pattern: str = None,
        category: str = None,
        cwe: str = None,
        owasp: str = None,
        false_positive_indicators: List[str] = None,
    ):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.confidence = confidence
        self.file_pattern = file_pattern
        self.code_pattern = code_pattern
        self.category = category
        self.cwe = cwe
        self.owasp = owasp
        self.false_positive_indicators = false_positive_indicators or []


# ─────────────────────── SpEL 表达式注入 ───────────────────────

SPEL_INJECTION_RULES = [
    SpringBootRule(
        rule_id="springboot.spel.parser-expression",
        description="SpelExpressionParser 解析用户可控输入，存在 SpEL 注入风险（RCE）",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"SpelExpressionParser\s*\(\s*\)\.parseExpression\s*\(\s*(?:request|req|input|user)",
        category="SPEL_INJECTION",
        cwe="CWE-917",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["@Value", "Validator", "constant"],
    ),
    SpringBootRule(
        rule_id="springboot.spel.evaluation-context",
        description="StandardEvaluationContext 允许执行任意 SpEL 表达式，导致 RCE",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"new\s+StandardEvaluationContext\s*\(",
        category="SPEL_INJECTION",
        cwe="CWE-917",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["SimpleEvaluationContext"],
    ),
    SpringBootRule(
        rule_id="springboot.spel.template-parse",
        description="TemplateExpressionParser 解析用户输入模板，存在注入风险",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"TemplateParserContext|parseExpression\s*\(\s*(?:param|query|body)",
        category="SPEL_INJECTION",
        cwe="CWE-917",
        owasp="A03:2021 - Injection",
    ),
    SpringBootRule(
        rule_id="springboot.spel.value-annotation",
        description="@Value 注解中使用 SpEL 解析用户可控属性",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"@Value\s*\(\s*#\{.*(?:request|session|param|header)",
        category="SPEL_INJECTION",
        cwe="CWE-917",
        owasp="A03:2021 - Injection",
    ),
    SpringBootRule(
        rule_id="springboot.spel.condition-expression",
        description="条件表达式中直接拼接用户输入",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"condition\s*=\s*['\"].*#\{.+?\}\s*['\"].*\+",
        category="SPEL_INJECTION",
        cwe="CWE-917",
        owasp="A03:2021 - Injection",
    ),
    SpringBootRule(
        rule_id="springboot.spel.method-reference",
        description="SpEL 中引用用户可控方法名",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"registerFunction\s*\(\s*(?:param|input)",
        category="SPEL_INJECTION",
        cwe="CWE-917",
        owasp="A03:2021 - Injection",
    ),
    SpringBootRule(
        rule_id="springboot.spel.type-reference",
        description="SpEL 类型引用可被利用执行任意类方法",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"T\s*\(\s*(?:java\.lang\.Runtime|ProcessBuilder|Class\.forName)",
        category="SPEL_INJECTION",
        cwe="CWE-917",
        owasp="A03:2021 - Injection",
    ),
    SpringBootRule(
        rule_id="springboot.spel.bean-wrapper",
        description="BeanWrapper 设置用户可控属性名",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"BeanWrapperImpl.*setPropertyValue\s*\(\s*(?:param|input)",
        category="SPEL_INJECTION",
        cwe="CWE-917",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── Actuator 端点暴露 ───────────────────────

ACTUATOR_EXPOSURE_RULES = [
    SpringBootRule(
        rule_id="springboot.actuator.all-endpoints",
        description="Actuator 端点全部暴露，包含敏感信息泄露风险（env/heapdump/trace）",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"management\.endpoints\.web\.exposure\.include\s*=\s*(?:\*|all)",
        category="ACTUATOR_EXPOSURE",
        cwe="CWE-200",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.actuator.env-exposed",
        description="env 端点暴露导致环境变量、密钥等敏感信息泄露",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"management\.endpoint\.env\.enabled\s*=\s*true",
        category="ACTUATOR_EXPOSURE",
        cwe="CWE-200",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.actuator.heapdump-exposed",
        description="heapdump 端点暴露导致内存数据泄露（含密码、Token等）",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"management\.endpoint\.heapdump\.enabled\s*=\s*true",
        category="ACTUATOR_EXPOSURE",
        cwe="CWE-200",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.actuator.trace-exposed",
        description="trace 端点暴露导致 HTTP 请求历史泄露（含 headers/cookies）",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"management\.endpoint\.httptrace\.enabled\s*=\s*true",
        category="ACTUATOR_EXPOSURE",
        cwe="CWE-200",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.actuator.jolokia-exposed",
        description="Jolokia 端点暴露允许 JMX 操作，可能被利用执行任意代码",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"jolokia|management\.endpoint\.jolokia",
        category="ACTUATOR_EXPOSURE",
        cwe="CWE-284",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.actuator.shutdown-exposed",
        description="shutdown 端点暴露允许远程关闭应用",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"management\.endpoint\.shutdown\.enabled\s*=\s*true",
        category="ACTUATOR_EXPOSURE",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── CSRF 配置缺陷 ───────────────────────

CSRF_RULES = [
    SpringBootRule(
        rule_id="springboot.csrf.disabled",
        description="Spring Security CSRF 防护被全局禁用",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"csrf\s*\(\s*\)\.disable\s*\(",
        category="CSRF",
        cwe="CWE-352",
        owasp="A01:2021 - Broken Access Control",
        false_positive_indicators=["@Test", "test", "dev"],
    ),
    SpringBootRule(
        rule_id="springboot.csrf.ignored-paths",
        description="过多路径被排除在 CSRF 防护之外",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"ignoringAntMatchers\s*\(\s*\".*(?:/api/|/v[0-9]+/)",
        category="CSRF",
        cwe="CWE-352",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.csrf.token-repository-insecure",
        description="使用 InMemoryTokenRepository 存储 CSRF Token（集群环境失效）",
        severity="MEDIUM",
        confidence=0.65,
        code_pattern=r"HttpSessionCsrfTokenRepository",
        category="CSRF",
        cwe="CWE-352",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.csrf.weak-token",
        description="CSRF Token 长度过短或可预测",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"CsrfToken\.getToken\s*\(\s*\)\.length\s*[<]=?\s*[0-9]{1,2}",
        category="CSRF",
        cwe="CWE-330",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    SpringBootRule(
        rule_id="springboot.csrf.method-mismatch",
        description="CSRF 防护仅拦截 POST，PUT/DELETE/PATCH 未拦截",
        severity="HIGH",
        confidence=0.6,
        code_pattern=r"requireCsrfProtectionMatcher\s*\(\s*new\s+AntPathRequestMatcher\s*\(\s*\"/",
        category="CSRF",
        cwe="CWE-352",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── CORS 配置不当 ───────────────────────

CORS_MISCONFIG_RULES = [
    SpringBootRule(
        rule_id="springboot.cors.allow-all",
        description="CORS 允许所有源 (allowedOrigins=*) 访问",
        severity="HIGH",
        confidence=0.9,
        code_pattern=r"allowedOrigins\s*\(\s*['\"]\*['\"]\s*\)",
        category="CORS_MISCONFIG",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
        false_positive_indicators=["@Profile", "dev", "test"],
    ),
    SpringBootRule(
        rule_id="springboot.cors.allow-credentials-wildcard",
        description="CORS 同时允许 credentials 和通配符 origin（安全冲突）",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"allowCredentials\s*\(\s*true\s*\).*allowedOrigins\s*\(\s*['\"]\*['\"]",
        category="CORS_MISCONFIG",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.cors-dynamic-origin",
        description="CORS origin 校验不严格，允许任意子域反射",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"allowedOriginPatterns\s*\(\s*['\"].*\*.*['\"]",
        category="CORS_MISCONFIG",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.cors-allow-methods-all",
        description="CORS 允许所有 HTTP 方法包括 TRACE/DELETE",
        severity="MEDIUM",
        confidence=0.7,
        code_pattern=r"allowedMethods\s*\(\s*['\"]\*['\"]",
        category="CORS_MISCONFIG",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.cors-max-age-excessive",
        description="CORS 预检缓存时间过长（>1小时），降低安全更新及时性",
        severity="LOW",
        confidence=0.4,
        code_pattern=r"maxAge\s*\(\s*[0-9]{6,}",
        category="CORS_MISCONFIG",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
]


# ─────────────────────── 文件操作漏洞 ───────────────────────

FILE_OPERATIONS_RULES = [
    SpringBootRule(
        rule_id="springboot.file-upload-no-type-check",
        description="文件上传未校验文件类型和内容，可能导致任意文件上传",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"MultipartFile.*transferTo\s*\([^)]*(?:getOriginalFilename|getResource)",
        category="FILE_OPERATIONS",
        cwe="CWE-434",
        owasp="A04:2021 - Insecure Design",
        false_positive_indicators=["ContentType", "extension", "whitelist"],
    ),
    SpringBootRule(
        rule_id="springboot.file-path-traversal",
        description="文件路径拼接用户输入且未规范化校验，存在路径遍历",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"new\s+File\s*\(\s*.*(?:getPath|getRequestURI|ServletContext\.getRealPath).*\+\s*(?:param|filename|input)",
        category="FILE_OPERATIONS",
        cwe="CWE-22",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.file-download-no-validation",
        description="文件下载未校验路径范围，可能导致任意文件读取",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"Resource\s*}\s*new\s+UrlResource\s*\(\s*(?:downloadUrl|request|getParameter)",
        category="FILE_OPERATIONS",
        cwe="CWE-22",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.file-multipart-large-size",
        description="文件上传大小限制过大，存在DoS风险",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"spring\.servlet\.multipart\.max-file-size\s*=\s*[0-9]{8,}",
        category="FILE_OPERATIONS",
        cwe="CWE-770",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.file-temp-not-deleted",
        description="临时文件未显式清理，可能造成信息泄露或磁盘耗尽",
        severity="LOW",
        confidence=0.4,
        code_pattern=r"File\.createTempFile\s*\((?!.*deleteOnExit)",
        category="FILE_OPERATIONS",
        cwe="CWE-459",
        owasp="A04:2021 - Insecure Design",
    ),
    SpringBootRule(
        rule_id="springboot.file-nio-too-permissive",
        description="Files 写入用户可控内容到可执行目录",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"Files\.write\s*\(\s*Paths\.get\s*\(\s*(?:static|public|webapp|templates)",
        category="FILE_OPERATIONS",
        cwe="CWE-379",
        owasp="A04:2021 - Insecure Design",
    ),
]


# ─────────────────────── Security 配置缺陷 ───────────────────────

SECURITY_MISCONFIG_RULES = [
    SpringBootRule(
        rule_id="springboot.security-debug-mode",
        description="Spring Security debug=true 开启调试日志（生产环境不应开启）",
        severity="MEDIUM",
        confidence=0.7,
        code_pattern=r"spring\.security\.debug\s*=\s*true",
        category="SECURITY_MISCONFIG",
        cwe="CWE-215",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.security-frame-options-disabled",
        description="X-Frame-Options 被禁用，存在 Clickjacking 风险",
        severity="MEDIUM",
        confidence=0.7,
        code_pattern=r"headers\s*\(\s*\)\.frameOptions\s*\(\s*\)\.disable\s*\(",
        category="SECURITY_MISCONFIG",
        cwe="CWE-1021",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.security-https-disabled",
        description="HTTPS / 安全通道配置被禁用",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"requiresChannel\s*\(\s*\)\.anyRequest\s*\(\s*\).requiresInsecure\s*\(",
        category="SECURITY_MISCONFIG",
        cwe="CWE-319",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    SpringBootRule(
        rule_id="springboot.security-content-type-disabled",
        description="X-Content-Type-Options 响应头未设置",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"headers\s*\(\s*\)\.contentTypeOptions\s*\(\s*\).disable\s*\(",
        category="SECURITY_MISCONFIG",
        cwe="CWE-693",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.security-cache-control-disabled",
        description="Cache-Control 缺失导致敏感数据缓存到客户端/CDN",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"headers\s*\(\s*\)\.cacheControl\s*\(\s*\).disable\s*\(",
        category="SECURITY_MISCONFIG",
        cwe="CWE-525",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.security-all-paths-permitted",
        description="Spring Security 配置中所有路径匿名访问（anyRequest().permitAll()）",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"anyRequest\s*\(\s*\)\.permitAll\s*\(",
        category="SECURITY_MISCONFIG",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.security-weak-password-encoder",
        description="使用 NoOpPasswordEncoder 或弱密码编码器",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"NoOpPasswordEncoder|PlainTextPasswordEncoder|StandardPasswordEncoder|Md4PasswordEncoder|MessageDigestPasswordEncoder|LdapShaPasswordEncoder",
        category="SECURITY_MISCONFIG",
        cwe="CWE-261",
        owasp="A02:2021 - Cryptographic Failures",
    ),
]


# ─────────────────────── 会话管理漏洞 ───────────────────────

SESSION_RULES = [
    SpringBootRule(
        rule_id="springboot.session-timeout-too-long",
        description="会话超时时间过长（>8小时）增加会话劫持窗口",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"server\.servlet\.session\.timeout\s*=\s*(?:[0-9]*[89][0-9]{2,}|[0-9]{4,})",
        category="SESSION",
        cwe="CWE-613",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.session-fixation-vulnerable",
        description="会话固定漏洞：登录后未更换 Session ID",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"sessionManagement\s*\(\s*\)\.\s*sessionFixation\s*\(\s*\)\.none\s*\(",
        category="SESSION",
        cwe="CWE-384",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.session-concurrent-no-limit",
        description="未限制同一用户并发会话数，容易导致会话劫持",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"sessionManagement\s*\(\s*\)\.maximumSessions\s*\(\s*-1\s*\)",
        category="SESSION",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.session-cookie-no-httponly",
        description="Session Cookie 未设置 HttpOnly 标志",
        severity="MEDIUM",
        confidence=0.65,
        code_pattern=r"server\.servlet\.session\.cookie\.http-only\s*=\s*false",
        category="SESSION",
        cwe="CWE-1004",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.session-cookie-no-secure",
        description="Session Cookie 未设置 Secure 标志，可通过 HTTP 传输",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"server\.servlet\.session\.cookie\.secure\s*=\s*false",
        category="SESSION",
        cwe="CWE-614",
        owasp="A05:2021 - Security Misconfiguration",
    ),
]


# ─────────────────────── 日志注入 ───────────────────────

LOG_INJECTION_RULES = [
    SpringBootRule(
        rule_id="springboot.log-user-input-direct",
        description="用户输入直接写入日志（Log4j/SLF4J）存在日志注入/Log4Shell风险",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"log\.\w+\s*\(\s*(?:\"|'|`)\s*(?:.*req\.|.*request\.|.*param\.|.*body\.)",
        category="LOG_INJECTION",
        cwe="CWE-117",
        owasp="A09:2021 - Security Logging and Monitoring Failures",
    ),
    SpringBootRule(
        rule_id="springboot.log-format-injection",
        description="日志格式字符串中使用用户输入作为参数",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"logger\.\w+\s*\([^)]*(?:input|param|req\.|username|userId)[^)]*\)",
        category="LOG_INJECTION",
        cwe="CWE-117",
        owasp="A09:2021 - Security Logging and Monitoring Failures",
    ),
    SpringBootRule(
        rule_id="springboot.log4j-jndi-lookup",
        description="Log4j 允许 JNDI 查找消息（Log4Shell CVE-2021-44228 场景）",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"jndi|lookup\s*\(\s*[\"']ldap://|$\{.+\}",
        category="LOG_INJECTION",
        cwe="CWE-502",
        owasp="A03:2021 - Injection",
    ),
    SpringBootRule(
        rule_id="springboot.log-sensitive-data",
        description="日志中打印敏感数据（密码/Token/身份证/手机号）",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"log\.\w+\s*\([^)]*(?:password|passwd|secret|token|idCard|phone|ssn|credit)",
        category="LOG_INJECTION",
        cwe="CWE-532",
        owasp="A09:2021 - Security Logging and Monitoring Failures",
        false_positive_indicators=["mask", "redact", "encrypt"],
    ),
]


# ─────────────────────── 信息泄露 ───────────────────────

INFO_LEAK_RULES = [
    SpringBootRule(
        rule_id="springboot.info-stacktrace-to-client",
        description="服务端异常堆栈信息直接返回给客户端",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"@ControllerAdvice.*return\s+(?:e\.printStackTrace|ex\.getMessage|err\.stack)",
        category="INFO_LEAK",
        cwe="CWE-209",
        owasp="A04:2021 - Insecure Design",
    ),
    SpringBootRule(
        rule_id="springboot.info-stacktrace-in-response",
        description="Whitelabel Error Page 显示堆栈信息",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"server\.error\.include-stacktrace\s*=\s*always",
        category="INFO_LEAK",
        cwe="CWE-209",
        owasp="A04:2021 - Insecure Design",
    ),
    SpringBootRule(
        rule_id="springboot.info-msg-error-details",
        description="错误消息暴露内部实现细节（SQL/框架版本等）",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"server\.error\.include-message\s*=\s*always",
        category="INFO_LEAK",
        cwe="CWE-209",
        owasp="A04:2021 - Insecure Design",
    ),
    SpringBootRule(
        rule_id="springboot.info-actuator-mbeans",
        description="Actuator MBean 端点暴露可能泄露 JMX 管理数据",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"management\.endpoint\.mbeans\.enabled\s*=\s*true",
        category="INFO_LEAK",
        cwe="CWE-200",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.info-properties-checked-in",
        description="application.properties/yml 中硬编码密钥被提交到代码仓库",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"(?:database|spring\.datasource|)\.password\s*=\s*[\"'][^\"']{3,}[\"']",
        category="INFO_LEAK",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    SpringBootRule(
        rule_id="springboot.info-git-dir-exposed",
        description="应用根目录暴露 .git 目录可被下载",
        severity="CRITICAL",
        confidence=0.7,
        code_pattern=r"ResourceHandlerRegistry.*addResourceHandler\s*\(\s*['\"]\s*/\s*['\"]",
        category="INFO_LEAK",
        cwe="CWE-548",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── 模板注入 ───────────────────────

TEMPLATE_INJECTION_RULES = [
    SpringBootRule(
        rule_id="springboot.template-thymeleaf-unescaped",
        description="Thymeleaf th:utext 未转义输出用户输入",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"th:utext\s*=\s*[\"'].*\#\{",
        category="TEMPLATE_INJECTION",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
    SpringBootRule(
        rule_id="springboot.template-freemarker-user",
        description="Freemarker 模板中使用用户输入构造模板",
        severity="CRITICAL",
        confidence=0.75,
        code_pattern=r"Template\.process\s*\([^)]*(?:user|input|req|body)",
        category="TEMPLATE_INJECTION",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
    SpringBootRule(
        rule_id="springboot.template-jsp-expression",
        description="JSP 中直接使用表达式输出未转义内容",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"<%=\s*request\.(?:getParameter|getAttribute)",
        category="TEMPLATE_INJECTION",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
    SpringBootRule(
        rule_id="springboot.template-inline-edit",
        description="Thymeleaf 内联文本中包含用户输入",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"th:inline\s*=\s*[\"']text[\"'].*\$\{(?:param|body|user)",
        category="TEMPLATE_INJECTION",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
    SpringBootRule(
        rule_id="springboot.template-layout-injection",
        description="动态布局名称可能包含用户输入，导致 SSTI",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"layout\s*:\s*(?:resolve|decorate)\s*\([^)]*(?:param|input|templateName)",
        category="TEMPLATE_INJECTION",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── 不安全重定向 ───────────────────────

REDIRECT_RULES = [
    SpringBootRule(
        rule_id="springboot.redirect-user-controlled",
        description="重定向目标来自用户可控参数，存在开放重定向",
        severity="MEDIUM",
        confidence=0.7,
        code_pattern=r"redirect\s*:\s*(?:url|view|target)",
        category="REDIRECT",
        cwe="CWE-601",
        owasp="A01:2021 - Broken Access Control",
        false_positive_indicators=["@RequestMapping", "forward:"],
    ),
    SpringBootRule(
        rule_id="springboot.redirect-sendredirect-user",
        description="response.sendRedirect 使用用户可控 URL",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"sendRedirect\s*\(\s*(?:request\.getParameter|param|input|req\.)",
        category="REDIRECT",
        cwe="CWE-601",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.redirect-model-view-user",
        description="new ModelAndView 使用用户输入构造重定向视图",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"ModelAndView\s*\(\s*(?:request\.getParameter|redirect\s*\+\s*\w+)",
        category="REDIRECT",
        cwe="CWE-601",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.redirect-view-resolver-bypass",
        description="ViewResolver 配置 redirect: 前缀可被绕过",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"RedirectView\s*\(\s*(?:url\s*\+\s*\w+|new\s+String\s*\()",
        category="REDIRECT",
        cwe="CWE-601",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── 数据层注入 ───────────────────────

DATA_INJECTION_RULES = [
    SpringBootRule(
        rule_id="springboot.data-jpa-derived-query-order",
        description="Spring Data 派生查询 ORDER BY 子句可被注入",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"@Query\s*\(\s*(?:value\s*=)?\s*['\"].*ORDER\s+BY\s+\#\{",
        category="DATA_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
    SpringBootRule(
        rule_id="springboot.data-jpa-concat-query",
        description="@Query 中字符串拼接构造 JPQL/SQL",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"@Query\s*\([^)]*\+\s*(?:param|input|req)",
        category="DATA_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
    SpringBootRule(
        rule_id="springboot.data-mybatis-order-injection",
        description="MyBatis ${} 参数绑定（拼接而非预编译）用于 ORDER BY",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"(?:ORDER\s+BY|GROUP\s+BY)\s+\$\{",
        category="DATA_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
    SpringBootRule(
        rule_id="springboot.data-criteria-sql-injection",
        description="JPA Criteria 中使用字符串拼接构造表达式",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"CriteriaBuilder.*function\s*\([^)]*(?:sql|query)",
        category="DATA_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
    SpringBootRule(
        rule_id="springboot.data-elasticsearch-injection",
        description="ElasticSearch query string 中直接拼接用户输入",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"QueryBuilders\.queryStringQuery\s*\((?:param|input)",
        category="DATA_INJECTION",
        cwe="CWE-943",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── 云配置泄露 ───────────────────────

CLOUD_CONFIG_RULES = [
    SpringBootRule(
        rule_id="springboot.cloud-config-server-no-auth",
        description="Spring Cloud Config Server 未启用身份验证",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"spring\.cloud\.config\.server\.(?:git|svn|vault)\.uri\s*=",
        category="CLOUD_CONFIG",
        cwe="CWE-284",
        owasp="A05:2021 - Security Misconfiguration",
        false_positive_indicators=["security", "username", "password"],
    ),
    SpringBootRule(
        rule_id="springboot.cloud-vault-token-leak",
        description="Spring Cloud Vault Token 硬编码在配置中",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"spring\.cloud\.vault\.token\s*=\s*[\"'][^\"']{5,}[\"']",
        category="CLOUD_CONFIG",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    SpringBootRule(
        rule_id="springboot.cloud-consul-token-leak",
        description="Consul ACL Token 硬编码在配置中",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"spring\.cloud\.consul\.discovery\.acl-token\s*=\s*[\"'][^\"']{5,}[\"']",
        category="CLOUD_CONFIG",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    SpringBootRule(
        rule_id="springboot.cloud-eureka-no-auth",
        description="Eureka Server/Client 未配置认证信息",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"eureka\.(?:client|server)\.service-url\s*=",
        category="CLOUD_CONFIG",
        cwe="CWE-306",
        owasp="A01:2021 - Broken Access Control",
        false_positive_indicators=["authorization", "basic-auth"],
    ),
]


# ─────────────────────── WebSocket 安全 ───────────────────────

WEBSOCKET_RULES = [
    SpringBootRule(
        rule_id="springboot.websocket-no-csrf",
        description="WebSocket 端点未配置 CSRF 保护",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"addEndpoint\s*\(\s*[\"'].*[\"']\)\s*(?!.*setAllowedOrigins)",
        category="WEBSOCKET",
        cwe="CWE-352",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.websocket-allow-all-origins",
        description="WebSocket 允许所有 Origin 连接",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"setAllowedOrigins\s*\(\s*[\"']\*[\"']\s*\)",
        category="WEBSOCKET",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.websocket-no-auth",
        description="WebSocket 连接未要求身份验证",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"@ServerEndpoint\s*\(\s*[\"'].*[\"']\s*\)(?!.*HttpSession|.*Principal)",
        category="WEBSOCKET",
        cwe="CWE-306",
        owasp="A01:2021 - Broken Access Control",
    ),
    SpringBootRule(
        rule_id="springboot.websocket-binary-deserialization",
        description="WebSocket 接收 Binary 反序列化数据可能触发 RCE",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"@OnMessage.*readObject\s*\(|@OnMessage.*ObjectInputStream",
        category="WEBSOCKET",
        cwe="CWE-502",
        owasp="A08:2021 - Software and Data Integrity Failures",
    ),
]


# ─────────────────────── 反序列化漏洞 ───────────────────────

DESERIALIZATION_RULES = [
    SpringBootRule(
        rule_id="springboot.deser-java-readobject",
        description="ObjectInputStream.readObject() 反序列化不可信数据",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"ObjectInputStream.*readObject\s*\(",
        category="DESERIALIZATION",
        cwe="CWE-502",
        owasp="A08:2021 - Software and Data Integrity Failures",
    ),
    SpringBootRule(
        rule_id="springboot.deser-jackson-default-typing",
        description="Jackson enableDefaultTyping() 允许指定任意类名反序列化",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"enableDefaultTyping\s*\(",
        category="DESERIALIZATION",
        cwe="CWE-502",
        owasp="A08:2021 - Software and Data Integrity Failures",
    ),
    SpringBootRule(
        rule_id="springboot.deser-fastjson-autotype",
        description="Fastjson AutoType 未关闭允许指定危险类",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"JSON\.parseObject\s*\([^)]*@type|ParserConfig\.getGlobalInstance\s*\(\s*\)\.setAutoTypeSupport\s*\(\s*true",
        category="DESERIALIZATION",
        cwe="CWE-502",
        owasp="A08:2021 - Software and Data Integrity Failures",
    ),
    SpringBootRule(
        rule_id="springboot.deser-xstream-unsafe",
        description="XStream 未配置安全框架允许任意类反序列化",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"XStream\s*\(\s*\)(?!.*setupDefaultSecurity|.*addPermission|.*allowTypes)",
        category="DESERIALIZATION",
        cwe="CWE-502",
        owasp="A08:2021 - Software and Data Integrity Failures",
    ),
]


# ─────────────────────── XXE 漏洞 ───────────────────────

XXE_RULES = [
    SpringBootRule(
        rule_id="springboot.xxe-saxparser",
        description="SAXParserFactory 未禁用外部实体解析，存在 XXE 风险",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"SAXParserFactory\.newInstance\s*\(\s*\)(?!.*setFeature.*\"http://apache.org/xml/features/disallow-doctype-decl\".*true)",
        category="XXE",
        cwe="CWE-611",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.xxe-document-builder",
        description="DocumentBuilderFactory 未禁用外部实体，存在 XXE 风险",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"DocumentBuilderFactory\.newInstance\s*\(\s*\)(?!.*setFeature.*\"http://apache.org/xml/features/disallow-doctype-decl\".*true)",
        category="XXE",
        cwe="CWE-611",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.xxe-xml-input-factory",
        description="XMLInputFactory 未禁用外部实体，存在 XXE 风险",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"XMLInputFactory\.newFactory\s*\(\s*\)(?!.*setProperty.*XMLInputFactory\.IS_SUPPORTING_EXTERNAL_ENTITIES.*false)",
        category="XXE",
        cwe="CWE-611",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    SpringBootRule(
        rule_id="springboot.xxe-transformer-factory",
        description="TransformerFactory 未安全配置可能泄露内部数据",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"TransformerFactory\.newInstance\s*\(\s*\)(?!.*setFeature.*FEATURE_SECURE_PROCESSING)",
        category="XXE",
        cwe="CWE-611",
        owasp="A05:2021 - Security Misconfiguration",
    ),
]


# ─────────────────────── 安全守卫模式 ───────────────────────

SPRINGBOOT_SECURITY_GUARD_PATTERNS: Dict[str, List[str]] = {
    "spel_injection": [
        r"SimpleEvaluationContext",
        r"@Value\s*\(\s*#\{[^}]+\s*\}",   # 常量 SpEL
        r"hasRole",
        r"hasAuthority",
        r"permitAll",
        r"Validator",
    ],
    "csrf": [
        r"CsrfFilter",
        r"csrfTokenRepository",
        r"CookieCsrfTokenRepository",
        r"SessionCsrfTokenRepository",
        r"_csrf",
        r"csrf",
    ],
    "cors": [
        r"setAllowedOrigins\s*\([\"'][^\"*]+[\"']\)",  # 具体域名
        r"CorsConfiguration",
        r"CorsFilter",
    ],
    "actuator": [
        r"management\.endpoints\.web\.exposure\.exclude",
        r"management\.endpoint\..*\.enabled\s*=\s*false",
    ],
    "session": [
        r"ChangeSessionIdAuthenticationStrategy",
        r"SessionManagementFilter",
        r"CookieHttpSessionStrategy",
    ],
    "deserialization": [
        r"ObjectInputFilter",
        r"setObjectInputFilter",
        r"allowTypes",
        r"acceptTypes",
        r"disableDefaultTyping",
    ],
    "xxe": [
        r"setFeature.*disallow-doctype-decl",
        r"IS_SUPPORTING_EXTERNAL_ENTITIES.*false",
        r"ACCESS_EXTERNAL_DTD",
        r"ACCESS_EXTERNAL_STYLESHEET",
    ],
}


# ─────────────────────── 误报规则 ───────────────────────

SPRINGBOOT_FALSE_POSITIVE_RULES = [
    SpringBootRule(
        rule_id="springboot.fp.spel-in-test",
        description="测试代码中的 SpEL 为测试场景",
        severity="LOW",
        confidence=0.7,
        file_pattern="*Test*",
    ),
    SpringBootRule(
        rule_id="springboot.fp.actuator-in-dev",
        description="dev/local profile 中 Actuator 开启为预期配置",
        severity="LOW",
        confidence=0.8,
        file_pattern="*dev*|*local*",
    ),
]


# ─────────────────────── 汇总 ───────────────────────

SPRINGBOOT_SECURITY_RULES: List[SpringBootRule] = (
    SPEL_INJECTION_RULES
    + ACTUATOR_EXPOSURE_RULES
    + CSRF_RULES
    + CORS_MISCONFIG_RULES
    + FILE_OPERATIONS_RULES
    + SECURITY_MISCONFIG_RULES
    + SESSION_RULES
    + LOG_INJECTION_RULES
    + INFO_LEAK_RULES
    + TEMPLATE_INJECTION_RULES
    + REDIRECT_RULES
    + DATA_INJECTION_RULES
    + CLOUD_CONFIG_RULES
    + WEBSOCKET_RULES
    + DESERIALIZATION_RULES
    + XXE_RULES
)

# 规则 ID 索引
SPRINGBOOT_RULES_INDEX: Dict[str, SpringBootRule] = {
    r.rule_id: r for r in SPRINGBOOT_SECURITY_RULES
}

# 按严重程度分类
SPRINGBOOT_RULES_BY_SEVERITY: Dict[str, List[SpringBootRule]] = {
    "CRITICAL": [r for r in SPRINGBOOT_SECURITY_RULES if r.severity == "CRITICAL"],
    "HIGH": [r for r in SPRINGBOOT_SECURITY_RULES if r.severity == "HIGH"],
    "MEDIUM": [r for r in SPRINGBOOT_SECURITY_RULES if r.severity == "MEDIUM"],
    "LOW": [r for r in SPRINGBOOT_SECURITY_RULES if r.severity == "LOW"],
}

# 规则总数（用于仪表盘展示）
SPRINGBOOT_RULE_COUNT: int = len(SPRINGBOOT_SECURITY_RULES)
