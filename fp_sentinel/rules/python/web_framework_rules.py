"""
Python Web 框架专属漏洞规则库 v3.2.0

覆盖 Django、Flask、FastAPI、Tornado 等 Python Web 框架的安全风险场景：
- Django 安全中间件配置缺陷
- Django ORM 注入
- Flask 会话/JWT 安全
- FastAPI 依赖注入安全
- Tornado XSS/CSRF
- 通用 SQL 注入 (SQLAlchemy/Raw)
- 模板注入 (Jinja2/Mako)
- CORS 配置不当
- 文件上传安全
- 认证/授权配置
"""

from typing import List, Dict


class PyWebRule:
    """Python Web 框架安全规则定义"""

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


# ─────────────────────── Django 安全 ───────────────────────

DJANGO_SECURITY_RULES = [
    PyWebRule(
        rule_id="django.debug-true",
        description="Django DEBUG=True 在生产环境开启，泄露敏感信息",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"DEBUG\s*=\s*(?:True|1)",
        category="DJANGO_SECURITY",
        cwe="CWE-489",
        owasp="A05:2021 - Security Misconfiguration",
        false_positive_indicators=["os.environ", "getenv", "config"],
    ),
    PyWebRule(
        rule_id="django.secret-key-hardcoded",
        description="Django SECRET_KEY 硬编码在代码中",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"SECRET_KEY\s*=\s*[\"'][^\"']{10,}[\"']",
        category="DJANGO_SECURITY",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
        false_positive_indicators=["os.environ", "getenv", "config"],
    ),
    PyWebRule(
        rule_id="django.csrf-middleware-missing",
        description="Django 未启用 CsrfViewMiddleware",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"MIDDLEWARE\s*=\s*\[(?!.*CsrfViewMiddleware)",
        category="DJANGO_SECURITY",
        cwe="CWE-352",
        owasp="A01:2021 - Broken Access Control",
    ),
    PyWebRule(
        rule_id="django.security-middleware-missing",
        description="Django 未启用 SecurityMiddleware",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"MIDDLEWARE\s*=\s*\[(?!.*SecurityMiddleware)",
        category="DJANGO_SECURITY",
        cwe="CWE-693",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="django.allowed-hosts-wildcard",
        description="Django ALLOWED_HOSTS 使用通配符 '*'",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']",
        category="DJANGO_SECURITY",
        cwe="CWE-644",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="django.ssl-redirect-disabled",
        description="Django SECURE_SSL_REDIRECT=False 未强制 HTTPS",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"SECURE_SSL_REDIRECT\s*=\s*False",
        category="DJANGO_SECURITY",
        cwe="CWE-319",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    PyWebRule(
        rule_id="django.hsts-disabled",
        description="Django SECURE_HSTS_SECONDS=0 未启用 HSTS",
        severity="MEDIUM",
        confidence=0.7,
        code_pattern=r"SECURE_HSTS_SECONDS\s*=\s*0",
        category="DJANGO_SECURITY",
        cwe="CWE-523",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="django.xframe-options-wrong",
        description="Django X_FRAME_OPTIONS 设置为 ALLOW 导致 Clickjacking",
        severity="MEDIUM",
        confidence=0.65,
        code_pattern=r"X_FRAME_OPTIONS\s*=\s*[\"']ALLOW[\"']",
        category="DJANGO_SECURITY",
        cwe="CWE-1021",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="django.cors-allow-all",
        description="django-cors-headers 允许所有 Origin",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True",
        category="DJANGO_SECURITY",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="django.cors-allow-credentials-wildcard",
        description="CORS 同时允许 credentials 和通配符 origin",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"CORS_ALLOW_CREDENTIALS\s*=\s*True.*CORS_ALLOW_ALL_ORIGINS\s*=\s*True",
        category="DJANGO_SECURITY",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
]


# ─────────────────────── Flask 安全 ───────────────────────

FLASK_SECURITY_RULES = [
    PyWebRule(
        rule_id="flask.debug-enabled",
        description="Flask 生产环境开启 debug 模式",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"app\.debug\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True",
        category="FLASK_SECURITY",
        cwe="CWE-489",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="flask.secret-key-hardcoded",
        description="Flask SECRET_KEY 硬编码",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"app\.config\[[\"']SECRET_KEY[\"']\]\s*=\s*[\"'][^\"']{8,}[\"']",
        category="FLASK_SECURITY",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    PyWebRule(
        rule_id="flask.httponly-missing",
        description="Flask session cookie 未设置 httponly",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"SESSION_COOKIE_HTTPONLY\s*=\s*False",
        category="FLASK_SECURITY",
        cwe="CWE-1004",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="flask.secure-cookie-disabled",
        description="Flask session cookie secure 标志未设置",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"SESSION_COOKIE_SECURE\s*=\s*False",
        category="FLASK_SECURITY",
        cwe="CWE-614",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="flask.samesite-lax-missing",
        description="Flask session cookie SameSite 未设置",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"SESSION_COOKIE_SAMESITE\s*=\s*[\"']None[\"']",
        category="FLASK_SECURITY",
        cwe="CWE-1275",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="flask.jwt-weak-algorithm",
        description="Flask-JWT 使用弱算法或 'none'",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"JWT_ALGORITHM\s*=\s*[\"']none[\"']|algorithms\s*=\s*[\[\"']HS128[\"']\]",
        category="FLASK_SECURITY",
        cwe="CWE-327",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    PyWebRule(
        rule_id="flask.file-upload-no-validate",
        description="Flask 文件上传未校验 extension/内容",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"request\.files\s*\[[^\]]+\]\.save\s*\((?!.*allowed_file|.*secure_filename)",
        category="FLASK_SECURITY",
        cwe="CWE-434",
        owasp="A04:2021 - Insecure Design",
    ),
    PyWebRule(
        rule_id="flask.open-redirect",
        description="Flask 使用用户可控 URL 重定向",
        severity="MEDIUM",
        confidence=0.7,
        code_pattern=r"redirect\s*\([^)]*request\.(?:args|form|json)",
        category="FLASK_SECURITY",
        cwe="CWE-601",
        owasp="A01:2021 - Broken Access Control",
    ),
    PyWebRule(
        rule_id="flask.error-handler-exposes",
        description="Flask 错误处理泄露内部细节",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"app\.errorhandler\s*\([^)]*return\s.*(?:traceback|e\.(?:args|__str__))",
        category="FLASK_SECURITY",
        cwe="CWE-209",
        owasp="A04:2021 - Insecure Design",
    ),
    PyWebRule(
        rule_id="flask.rate-limit-missing",
        description="Flask 登录接口缺少速率限制",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"@app\.route\s*\([^)]*login[^)]*\)",
        category="FLASK_SECURITY",
        cwe="CWE-307",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
]


# ─────────────────────── FastAPI 安全 ───────────────────────

FASTAPI_SECURITY_RULES = [
    PyWebRule(
        rule_id="fastapi.cors-allow-all",
        description="FastAPI CORSMiddleware 允许所有 Origin",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"CORSMiddleware.*allow_origins\s*=\s*\[\s*[\"']\*[\"']",
        category="FASTAPI_SECURITY",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="fastapi.cors-allow-credentials-all",
        description="FastAPI CORS 同时允许 credentials 和 all origins",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"CORSMiddleware.*allow_credentials\s*=\s*True.*allow_origins\s*=\s*\[\s*[\"']\*[\"']",
        category="FASTAPI_SECURITY",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="fastapi.dep-injection-user",
        description="FastAPI 依赖注入直接使用用户输入未校验",
        severity="MEDIUM",
        confidence=0.65,
        code_pattern=r"Depends\s*\([^)]*request\.(?:query|body|path)",
        category="FASTAPI_SECURITY",
        cwe="CWE-20",
        owasp="A04:2021 - Insecure Design",
    ),
    PyWebRule(
        rule_id="fastapi.jwt-no-verify",
        description="FastAPI OAuth2 JWT 未校验 signature",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"jwt\.decode\s*\([^)]*verify\s*=\s*False|options\s*=\s*\{[^}]*verify_signature\s*:\s*False",
        category="FASTAPI_SECURITY",
        cwe="CWE-347",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    PyWebRule(
        rule_id="fastapi.jwt-none-algorithm",
        description="FastAPI JWT 允许 'none' 算法",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"algorithms\s*=\s*\[[^\]]*none",
        category="FASTAPI_SECURITY",
        cwe="CWE-327",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    PyWebRule(
        rule_id="fastapi.exception-handler-exposes",
        description="FastAPI 全局异常处理器泄露堆栈",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"@app\.exception_handler.*return\s+JSONResponse\s*\([^)]*detail\s*=\s*str\s*\(\s*e",
        category="FASTAPI_SECURITY",
        cwe="CWE-209",
        owasp="A04:2021 - Insecure Design",
    ),
    PyWebRule(
        rule_id="fastapi.direct-response-template",
        description="FastAPI TemplateResponse 中直接渲染用户输入（SSTI）",
        severity="CRITICAL",
        confidence=0.75,
        code_pattern=r"TemplateResponse\s*\([^)]*(?:user|input|param)",
        category="FASTAPI_SECURITY",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
    PyWebRule(
        rule_id="fastapi.sql-injection-orm",
        description="FastAPI 使用 SQLAlchemy text() 执行拼接 SQL",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"text\s*\([^)]*f[\"']|text\s*\([^)]*\.format",
        category="FASTAPI_SECURITY",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── ORM 注入 ───────────────────────

SQLALCHEMY_INJECTION_RULES = [
    PyWebRule(
        rule_id="sqlalchemy.text-concat",
        description="SQLAlchemy text() 中使用 f-string/format 拼接 SQL",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"text\s*\(\s*f[\"']|text\s*\([^)]*\.format",
        category="SQLALCHEMY_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
    PyWebRule(
        rule_id="sqlalchemy.execute-raw",
        description="connection.execute() 直接拼接 SQL 字符串",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"execute\s*\([^)]*\"[^\"]*(?:SELECT|INSERT|UPDATE).*\+\s*(?:user|input|param)",
        category="SQLALCHEMY_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
    PyWebRule(
        rule_id="sqlalchemy.order-by-injection",
        description="SQLAlchemy order_by 使用用户可控列名",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"order_by\s*\([^)]*getattr",
        category="SQLALCHEMY_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
    PyWebRule(
        rule_id="sqlalchemy.raw-sql-format",
        description="SQLAlchemy 使用字符串格式化 % 操作符构造 SQL",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"(?:raw_sql|s)\s*=\s*[\"'][^\"']*(?:SELECT|UPDATE|INSERT)[^\"']*[\"']\s*%\s*\w+",
        category="SQLALCHEMY_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
    PyWebRule(
        rule_id="django.orm-raw-query",
        description="Django ORM 使用 raw() 方法执行未过滤 SQL",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"\.raw\s*\([^)]*\"[^\"]*(?:SELECT|INSERT|UPDATE)[^\"]*\".*\+",
        category="SQLALCHEMY_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
    PyWebRule(
        rule_id="django.orm-extra-injection",
        description="Django extra() 方法中使用用户输入",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"\.extra\s*\([^]]*%(?:s|user|input)",
        category="SQLALCHEMY_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── Python 模板注入 ───────────────────────

TEMPLATE_INJECTION_PY_RULES = [
    PyWebRule(
        rule_id="py.template-jinja2-from-input",
        description="Jinja2 Template() 编译包含用户输入的模板字符串",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"Template\s*\([^)]*(?:request|req|input|user|param|body)",
        category="TEMPLATE_INJECTION_PY",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
    PyWebRule(
        rule_id="py.template-mako-user",
        description="Mako Template() 使用用户输入构造模板",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"mako\.Template\s*\([^)]*(?:user|input|data)",
        category="TEMPLATE_INJECTION_PY",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
    PyWebRule(
        rule_id="py.template-autoescape-off",
        description="Jinja2 Environment 禁用 autoescape",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"Environment\s*\([^)]*autoescape\s*=\s*False",
        category="TEMPLATE_INJECTION_PY",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    PyWebRule(
        rule_id="py.template-render-with-user",
        description="template.render() 使用用户可控数据但模板本身包含用户输入",
        severity="CRITICAL",
        confidence=0.75,
        code_pattern=r"(?:jinja_template|tpl|tmpl)\.render\s*\([^)]*(?:request|req|user|input)",
        category="TEMPLATE_INJECTION_PY",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
    PyWebRule(
        rule_id="py.template-string-ssti",
        description="Python 字符串格式化（f-string）用于构造 HTML/SQL",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"(?:Markup|mark_safe)\s*\([^)]*f['\"]",
        category="TEMPLATE_INJECTION_PY",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
    PyWebRule(
        rule_id="py.template-django-auto",
        description="Django 模板中使用自定义 filter 绕过 autoescape",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"@register\.filter.*@stringfilter.*def\s+\w+[^:]*:.*return\s+(?:Markup|mark_safe)",
        category="TEMPLATE_INJECTION_PY",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── Python CORS 配置 ───────────────────────

CORS_PY_RULES = [
    PyWebRule(
        rule_id="py.cors-wildcard",
        description="Python 服务使用 CORS 通配符 '*'",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"CORS\s*\([^]]*origins\s*=\s*[\"']\*\s*[\"']|Access-Control-Allow-Origin\s*=\s*[\"']\*[\"']",
        category="CORS_PY",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="py.cors-reflect-origin",
        description="CORS 服务端反射请求 Origin（不校验直接信任）",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"Access-Control-Allow-Origin\s*=\s*request\.(?:headers|META)\s*\[[\"']Origin[\"']\]",
        category="CORS_PY",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="py.cors-allow-credentials-wildcard",
        description="CORS 同时允许 Access-Control-Allow-Credentials 和通配符 Origin",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"Allow-Credentials.*true.*(?:Allow-Origin.*\*|\"':.*Allow-Origin)",
        category="CORS_PY",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="py.cors-preflight-cache-long",
        description="CORS Access-Control-Max-Age 缓存时间过长（>24h）",
        severity="LOW",
        confidence=0.4,
        code_pattern=r"Access-Control-Max-Age['\":\s]+[7-9][0-9]{3,}",
        category="CORS_PY",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    PyWebRule(
        rule_id="py.cors-allow-methods-all",
        description="CORS 允许所有 HTTP 方法包括 TRACE/DELETE",
        severity="MEDIUM",
        confidence=0.65,
        code_pattern=r"Access-Control-Allow-Methods['\":\s]+[\"']\\*[\"']",
        category="CORS_PY",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
    ),
]


# ─────────────────────── Python 认证 ───────────────────────

AUTH_PY_RULES = [
    PyWebRule(
        rule_id="py.auth-bcrypt-rounds-low",
        description="bcrypt 哈希轮数低于推荐值（<10）",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"bcrypt\.(?:gensalt|hashpw)\s*\([^]]*rounds\s*=\s*[0-9]|bcrypt.*rounds\s*=\s*[1-9]\b",
        category="AUTH_PY",
        cwe="CWE-916",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    PyWebRule(
        rule_id="py.auth-compare-string",
        description="密码比较使用 '==' 而非恒定时间比较（时序攻击）",
        severity="MEDIUM",
        confidence=0.7,
        code_pattern=r"(?:password|passwd|pwd|secret)\s*==",
        category="AUTH_PY",
        cwe="CWE-208",
        owasp="A02:2021 - Cryptographic Failures",
        false_positive_indicators=["hmac.compare_digest", "secrets.compare_digest"],
    ),
    PyWebRule(
        rule_id="py.auth-no-password-policy",
        description="Python 用户注册密码没有最小长度/复杂度限制",
        severity="MEDIUM",
        confidence=0.45,
        code_pattern=r"password\s*=\s*request\.(?:POST|GET|json)\s*\[[\"']password[\"']\](?!.*len|.*min|.*validate)",
        category="AUTH_PY",
        cwe="CWE-521",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    PyWebRule(
        rule_id="py.auth-jwt-expiry-long",
        description="JWT Token 过期时间过长（>7天）",
        severity="LOW",
        confidence=0.45,
        code_pattern=r"(?:exp|EXPIRES)\s*[:=]\s*[\"']?[0-9]{4}[\"']?",
        category="AUTH_PY",
        cwe="CWE-613",
        owasp="A01:2021 - Broken Access Control",
    ),
    PyWebRule(
        rule_id="py.auth-no-mfa",
        description="敏感操作未启用 MFA/TOTP 双因子认证",
        severity="MEDIUM",
        confidence=0.4,
        code_pattern=r"(?:admin|root|superuser)\.login[^]]*(?!.*mfa|.*totp|.*two_factor|.*2fa)",
        category="AUTH_PY",
        cwe="CWE-308",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
]


# ─────────────────────── 安全守卫模式 ───────────────────────

PYWEB_SECURITY_GUARD_PATTERNS: Dict[str, List[str]] = {
    "django": [
        "CsrfViewMiddleware",
        "SecurityMiddleware",
        "SECURE_SSL_REDIRECT",
        "SECURE_HSTS_SECONDS",
    ],
    "flask": [
        "SESSION_COOKIE_HTTPONLY",
        "SESSION_COOKIE_SECURE",
        "SESSION_COOKIE_SAMESITE",
        "@login_required",
    ],
    "fastapi": [
        "OAuth2PasswordBearer",
        "get_current_active_user",
    ],
    "template": [
        "autoescape",
        "select_autoescape",
        "Markup.escape",
    ],
}


# ─────────────────────── 误报规则 ───────────────────────

PYWEB_FALSE_POSITIVE_RULES: List[PyWebRule] = []


# ─────────────────────── 汇总 ───────────────────────

PYWEB_SECURITY_RULES: List[PyWebRule] = (
    DJANGO_SECURITY_RULES
    + FLASK_SECURITY_RULES
    + FASTAPI_SECURITY_RULES
    + SQLALCHEMY_INJECTION_RULES
    + TEMPLATE_INJECTION_PY_RULES
    + CORS_PY_RULES
    + AUTH_PY_RULES
)

PYWEB_RULES_INDEX: Dict[str, PyWebRule] = {r.rule_id: r for r in PYWEB_SECURITY_RULES}

PYWEB_RULES_BY_SEVERITY: Dict[str, List[PyWebRule]] = {
    "CRITICAL": [r for r in PYWEB_SECURITY_RULES if r.severity == "CRITICAL"],
    "HIGH": [r for r in PYWEB_SECURITY_RULES if r.severity == "HIGH"],
    "MEDIUM": [r for r in PYWEB_SECURITY_RULES if r.severity == "MEDIUM"],
    "LOW": [r for r in PYWEB_SECURITY_RULES if r.severity == "LOW"],
}

PYWEB_RULE_COUNT: int = len(PYWEB_SECURITY_RULES)


# Python Web 框架检测模式
PYWEB_FRAMEWORK_DETECT: Dict[str, List[str]] = {
    "django": ["django", "from django", "DJANGO_SETTINGS_MODULE"],
    "flask": ["from flask", "import Flask", "@app.route"],
    "fastapi": ["from fastapi", "FastAPI(", "@app.get", "@app.post"],
    "tornado": ["from tornado", "import tornado", "tornado.web"],
}
