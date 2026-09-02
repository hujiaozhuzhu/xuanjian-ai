"""
JavaScript/TypeScript 安全规则库

覆盖 OWASP Top 10 中与前端相关的安全问题
包括: XSS、注入、原型污染、不安全加密、敏感信息泄露等
"""

from typing import List, Dict, Any


class CustomRule:
    """自定义规则定义"""
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


# ─────────────────────── XSS 规则 ───────────────────────

XSS_RULES = [
    CustomRule(
        rule_id="js.xss.innerhtml",
        description="innerHTML 赋值可能导致 DOM XSS",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"\.innerHTML\s*=",
        category="XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["textContent", "innerText", "DOMPurify", "sanitize"],
    ),
    CustomRule(
        rule_id="js.xss.outerhtml",
        description="outerHTML 赋值可能导致 DOM XSS",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"\.outerHTML\s*=",
        category="XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="js.xss.document-write",
        description="document.write 可能导致 DOM XSS",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"document\.write(ln)?\s*\(",
        category="XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="js.xss.jquery-html",
        description="jQuery .html() 可能导致 DOM XSS",
        severity="MEDIUM",
        confidence=0.65,
        code_pattern=r"\$\(.*\)\.html\s*\(",
        category="XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        false_positive_indicators=[".text()", "textContent"],
    ),
    CustomRule(
        rule_id="js.xss.dangerously-set",
        description="React dangerouslySetInnerHTML 可能导致 XSS",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"dangerouslySetInnerHTML",
        category="XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="js.xss.v-html",
        description="Vue v-html 指令可能导致 XSS",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"v-html\s*=",
        category="XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="js.xss.insert-adjacent-html",
        description="insertAdjacentHTML 可能导致 DOM XSS",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"\.insertAdjacentHTML\s*\(",
        category="XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="js.xss.href-javascript",
        description="javascript: 协议 URL 可能导致 XSS",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"href\s*=\s*['\"]javascript:",
        category="XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── 代码注入规则 ───────────────────────

INJECTION_RULES = [
    CustomRule(
        rule_id="js.injection.eval",
        description="eval() 执行任意代码，存在代码注入风险",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"\beval\s*\(",
        category="INJECTION",
        cwe="CWE-95",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["JSON.parse", "parseInt", "parseFloat"],
    ),
    CustomRule(
        rule_id="js.injection.function-constructor",
        description="Function 构造器可执行任意代码",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"new\s+Function\s*\(",
        category="INJECTION",
        cwe="CWE-95",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="js.injection.settimeout-string",
        description="setTimeout/setInterval 传入字符串参数可执行任意代码",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"(setTimeout|setInterval)\s*\(\s*['\"]",
        category="INJECTION",
        cwe="CWE-95",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="js.injection.script-src",
        description="动态加载外部脚本",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"\.src\s*=.*\+",
        category="INJECTION",
        cwe="CWE-95",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── 原型污染规则 ───────────────────────

PROTOTYPE_POLLUTION_RULES = [
    CustomRule(
        rule_id="js.proto.object-assign-merge",
        description="Object.assign 合并用户输入可能导致原型污染",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"Object\.assign\s*\(\s*[^,]+,\s*(req\.|params|body|query|input|data)",
        category="PROTOTYPE_POLLUTION",
        cwe="CWE-1321",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="js.proto.deep-merge",
        description="深合并用户输入可能导致原型污染",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"(merge|deepMerge|extend)\s*\(\s*[^,]+,\s*(req\.|params|body|query)",
        category="PROTOTYPE_POLLUTION",
        cwe="CWE-1321",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="js.proto.bracket-notation",
        description="动态属性访问可能导致原型污染",
        severity="MEDIUM",
        confidence=0.45,
        code_pattern=r"\[.*\]\s*=.*\[.*\]",
        category="PROTOTYPE_POLLUTION",
        cwe="CWE-1321",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── 不安全加密规则 ───────────────────────

CRYPTO_RULES = [
    CustomRule(
        rule_id="js.crypto.math-random",
        description="Math.random() 不是密码学安全的随机数生成器",
        severity="LOW",
        confidence=0.6,
        code_pattern=r"Math\.random\s*\(\)",
        category="CRYPTO",
        cwe="CWE-338",
        owasp="A02:2021 - Cryptographic Failures",
        false_positive_indicators=["Math.ceil", "Math.floor", "color", "position", "animation"],
    ),
    CustomRule(
        rule_id="js.crypto.md5",
        description="MD5 算法已被破解，不应用于安全场景",
        severity="MEDIUM",
        confidence=0.7,
        code_pattern=r"(md5|MD5)\s*\(",
        category="CRYPTO",
        cwe="CWE-328",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    CustomRule(
        rule_id="js.crypto.sha1",
        description="SHA-1 算法已被破解，不应用于安全场景",
        severity="LOW",
        confidence=0.6,
        code_pattern=r"(sha1|SHA1|sha-1)\s*\(",
        category="CRYPTO",
        cwe="CWE-328",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    CustomRule(
        rule_id="js.crypto.des",
        description="DES/3DES 算法不安全",
        severity="MEDIUM",
        confidence=0.75,
        code_pattern=r"(des|DES|tripleDES|3des)\s*\(",
        category="CRYPTO",
        cwe="CWE-327",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    CustomRule(
        rule_id="js.crypto.ecb-mode",
        description="ECB 模式不安全，应使用 CBC/GCM",
        severity="MEDIUM",
        confidence=0.7,
        code_pattern=r"mode:\s*['\"]?ECB",
        category="CRYPTO",
        cwe="CWE-327",
        owasp="A02:2021 - Cryptographic Failures",
    ),
]


# ─────────────────────── 敏感信息泄露规则 ───────────────────────

SECRETS_RULES = [
    CustomRule(
        rule_id="js.secrets.hardcoded-password",
        description="硬编码密码",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
        category="SECRETS",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
        false_positive_indicators=["placeholder", "example", "test", "xxx", "***", "null", "undefined"],
    ),
    CustomRule(
        rule_id="js.secrets.hardcoded-api-key",
        description="硬编码 API Key",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{16,}['\"]",
        category="SECRETS",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    CustomRule(
        rule_id="js.secrets.hardcoded-token",
        description="硬编码 Token",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"(token|secret|auth)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]",
        category="SECRETS",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
        false_positive_indicators=["Bearer ", "Basic ", "${", "process.env"],
    ),
    CustomRule(
        rule_id="js.secrets.hardcoded-private-key",
        description="硬编码私钥",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        category="SECRETS",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
]


# ─────────────────────── 传输安全规则 ───────────────────────

TRANSPORT_RULES = [
    CustomRule(
        rule_id="js.transport.http-request",
        description="使用 HTTP 明文传输数据",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"(fetch|axios|XMLHttpRequest|\.ajax)\s*\(\s*['\"]http://",
        category="TRANSPORT",
        cwe="CWE-319",
        owasp="A02:2021 - Cryptographic Failures",
        false_positive_indicators=["localhost", "127.0.0.1", "0.0.0.0"],
    ),
    CustomRule(
        rule_id="js.transport.insecure-fetch",
        description="fetch 请求未验证响应",
        severity="LOW",
        confidence=0.4,
        code_pattern=r"fetch\s*\([^)]+\)\s*\.then\s*\(\s*r\s*=>\s*r\.(text|json)\s*\(\)\s*\)",
        category="TRANSPORT",
        cwe="CWE-295",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
]


# ─────────────────────── 不安全操作规则 ───────────────────────

UNSAFE_RULES = [
    CustomRule(
        rule_id="js.unsafe.cookie-no-httponly",
        description="Cookie 未设置 HttpOnly 标志",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"document\.cookie\s*=",
        category="UNSAFE",
        cwe="CWE-1004",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    CustomRule(
        rule_id="js.unsafe.localstorage-sensitive",
        description="localStorage 存储敏感信息",
        severity="MEDIUM",
        confidence=0.45,
        code_pattern=r"localStorage\.(setItem|getItem)\s*\(\s*['\"](token|password|secret|key|auth|session)",
        category="UNSAFE",
        cwe="CWE-922",
        owasp="A04:2021 - Insecure Design",
    ),
    CustomRule(
        rule_id="js.unsafe.window-open",
        description="window.open 可能被拦截或导致安全问题",
        severity="LOW",
        confidence=0.4,
        code_pattern=r"window\.open\s*\(",
        category="UNSAFE",
        cwe="CWE-1021",
        owasp="A04:2021 - Insecure Design",
    ),
    CustomRule(
        rule_id="js.unsafe-postmessage-wildcard",
        description="postMessage 使用通配符 targetOrigin",
        severity="MEDIUM",
        confidence=0.75,
        code_pattern=r"\.postMessage\s*\([^,]+,\s*['\"]*\*['\"]*\s*\)",
        category="UNSAFE",
        cwe="CWE-345",
        owasp="A08:2021 - Software and Data Integrity Failures",
    ),
]


# ─────────────────────── Node.js 特定规则 ───────────────────────

NODEJS_RULES = [
    CustomRule(
        rule_id="js.node.command-injection",
        description="child_process 命令注入",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"(exec|execSync|spawn|spawnSync|execFile)\s*\(\s*[^)]*\+",
        category="INJECTION",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
        file_pattern="*.js",
    ),
    CustomRule(
        rule_id="js.node.path-traversal",
        description="文件路径拼接可能导致路径穿越",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"(readFile|readFileSync|createReadStream|createWriteStream)\s*\(\s*[^)]*\+",
        category="PATH_TRAVERSAL",
        cwe="CWE-22",
        owasp="A01:2021 - Broken Access Control",
        file_pattern="*.js",
    ),
    CustomRule(
        rule_id="js.node.sql-injection",
        description="SQL 拼接可能导致 SQL 注入",
        severity="CRITICAL",
        confidence=0.75,
        code_pattern=r"(query|execute|run)\s*\(\s*['\"`].*\$\{|.*\+\s*(req\.|params|body|query)",
        category="SQL_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
        file_pattern="*.js",
    ),
    CustomRule(
        rule_id="js.node.nosql-injection",
        description="NoSQL 查询可能被注入",
        severity="HIGH",
        confidence=0.6,
        code_pattern=r"\$where\s*:|\.find\s*\(\s*\{.*req\.",
        category="SQL_INJECTION",
        cwe="CWE-943",
        owasp="A03:2021 - Injection",
        file_pattern="*.js",
    ),
    CustomRule(
        rule_id="js.node.ssrf",
        description="服务端请求伪造 (SSRF)",
        severity="HIGH",
        confidence=0.55,
        code_pattern=r"(axios|fetch|request|got|http\.get|https\.get)\s*\(\s*(req\.|params|body|query|url)",
        category="SSRF",
        cwe="CWE-918",
        owasp="A10:2021 - Server-Side Request Forgery",
        file_pattern="*.js",
    ),
    CustomRule(
        rule_id="js.node.open-redirect",
        description="开放重定向",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"(res\.redirect|window\.location\s*=|location\.href\s*=)\s*(req\.|params|query|\.)",
        category="UNSAFE",
        cwe="CWE-601",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── AIGC 安全规则 (v2.0) ───────────────────────

AIGC_SECURITY_RULES = [
    # ── Prompt Injection ──
    CustomRule(
        rule_id="js.aigc.prompt-injection-concat",
        description="Prompt 拼接可能导致 Prompt Injection",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"(prompt|system_prompt|messages)\s*[\[+].*\+.*(?:user|input|req\.)",
        category="AIGC",
        cwe="CWE-77",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["template", "escape", "sanitize"],
    ),
    CustomRule(
        rule_id="js.aigc.prompt-injection-template",
        description="模板字符串中的 Prompt Injection 风险",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"`[^`]*\$\{.*(?:user|input|req\.|params)[^`]*`",
        category="AIGC",
        cwe="CWE-77",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="js.aigc.system-prompt-leak",
        description="系统提示词可能被泄露",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"system(?:_prompt|Message)?\s*[:=].*['\"]",
        category="AIGC",
        cwe="CWE-200",
        owasp="A01:2021 - Broken Access Control",
    ),

    # ── AI 输出直接执行 ──
    CustomRule(
        rule_id="js.aigc.llm-output-eval",
        description="LLM 输出直接作为代码执行",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"eval\s*\(\s*(?:llm|ai|gpt|claude|response|completion|result)",
        category="AIGC",
        cwe="CWE-95",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="js.aigc.llm-output-function",
        description="LLM 输出直接作为函数构造",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"new\s+Function\s*\(\s*(?:llm|ai|gpt|claude|response|completion|result)",
        category="AIGC",
        cwe="CWE-95",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="js.aigc.llm-output-sql",
        description="LLM 输出直接作为 SQL 查询",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"(query|execute)\s*\(\s*`?\$\{?\s*(?:llm|ai|gpt|claude|response|completion)",
        category="AIGC",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="js.aigc.llm-output-command",
        description="LLM 输出直接作为系统命令执行",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"(exec|spawn|execSync)\s*\(\s*(?:llm|ai|gpt|claude|response|completion|result)",
        category="AIGC",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
    ),
    CustomRule(
        rule_id="js.aigc.llm-output-shell",
        description="LLM 输出直接传递给 shell",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"shell\.(?:exec|run|command)\s*\(\s*(?:llm|ai|gpt|claude|response|completion)",
        category="AIGC",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
    ),

    # ── 幻觉依赖检测 ──
    CustomRule(
        rule_id="js.aigc.hallucination-import",
        description="导入可能不存在的 AI 生成的包名",
        severity="MEDIUM",
        confidence=0.4,
        code_pattern=r"(?:import|require)\s*\(\s*['\"](?:ai-|gpt-|llm-|openai-|claude-)[\w-]+['\"]",
        category="AIGC",
        cwe="CWE-829",
        owasp="A08:2021 - Software and Data Integrity Failures",
    ),

    # ── AI 特有逻辑漏洞 ──
    CustomRule(
        rule_id="js.aigc.unvalidated-llm-response",
        description="LLM 响应未经验证直接使用",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"(?:await\s+)?(?:openai|anthropic|llm|ai)\.(?:chat|complete|generate).*\.(?:json|data|content)",
        category="AIGC",
        cwe="CWE-20",
        owasp="A04:2021 - Insecure Design",
    ),
    CustomRule(
        rule_id="js.aigc.llm-api-key-exposure",
        description="LLM API Key 硬编码",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"(?:OPENAI|ANTHROPIC|CLAUDE|GPT)[_-]?(?:API[_-]?KEY|SECRET)\s*[:=]\s*['\"][sk-ant-][^'\"]+['\"]",
        category="AIGC",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    CustomRule(
        rule_id="js.aigc.llm-token-in-url",
        description="LLM Token 通过 URL 传输",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"(?:openai|anthropic|api)\.(?:openai|anthropic)\.com.*(?:token|key|api_key)=",
        category="AIGC",
        cwe="CWE-598",
        owasp="A02:2021 - Cryptographic Failures",
    ),

    # ── RLS/权限缺失 ──
    CustomRule(
        rule_id="js.aigc.supabase-no-rls",
        description="Supabase 查询未启用 RLS",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"supabase\.(?:from|rpc)\s*\([^)]*\)\.(?:select|insert|update|delete)",
        category="AIGC",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
        false_positive_indicators=["auth", "policy", "rls"],
    ),
    CustomRule(
        rule_id="js.aigc.firestore-no-rules",
        description="Firestore 操作未验证安全规则",
        severity="MEDIUM",
        confidence=0.45,
        code_pattern=r"(?:getDoc|setDoc|updateDoc|deleteDoc|addDoc)\s*\(\s*(?:doc|collection)\s*\(",
        category="AIGC",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
        file_pattern="*firebase*|*firestore*",
    ),
]


# ─────────────────────── 汇总所有规则 ───────────────────────

JS_SECURITY_RULES: List[CustomRule] = (
    XSS_RULES
    + INJECTION_RULES
    + PROTOTYPE_POLLUTION_RULES
    + CRYPTO_RULES
    + SECRETS_RULES
    + TRANSPORT_RULES
    + UNSAFE_RULES
    + NODEJS_RULES
    + AIGC_SECURITY_RULES  # v2.0 新增
)

# 规则ID索引
JS_RULES_INDEX: Dict[str, CustomRule] = {r.rule_id: r for r in JS_SECURITY_RULES}


# ─────────────────────── 误报规则 ───────────────────────

JS_FALSE_POSITIVE_RULES = [
    # 测试文件中的安全问题通常是误报
    CustomRule(
        rule_id="js.fp.test-file",
        description="测试文件中的安全问题",
        file_pattern="*test*|*spec*|*__tests__*|*mock*",
        confidence=0.7,
    ),
    # 示例/文档文件
    CustomRule(
        rule_id="js.fp.example-file",
        description="示例/文档文件中的安全问题",
        file_pattern="*example*|*demo*|*sample*|*doc*",
        confidence=0.6,
    ),
    # 构建产物
    CustomRule(
        rule_id="js.fp.build-output",
        description="构建产物中的安全问题",
        file_pattern="*dist*|*build*|*min.js|*bundle*|*vendor*",
        confidence=0.8,
    ),
    # node_modules
    CustomRule(
        rule_id="js.fp.node-modules",
        description="第三方依赖中的安全问题",
        file_pattern="*node_modules*",
        confidence=0.9,
    ),
    # JSON.parse 不是 eval
    CustomRule(
        rule_id="js.fp.json-parse",
        description="JSON.parse 不是 eval",
        code_pattern=r"JSON\.parse",
        confidence=0.95,
    ),
    # textContent 是安全的
    CustomRule(
        rule_id="js.fp.text-content",
        description="textContent 赋值是安全的",
        code_pattern=r"\.textContent\s*=",
        confidence=0.9,
    ),
    # innerText 是安全的
    CustomRule(
        rule_id="js.fp.inner-text",
        description="innerText 赋值是安全的",
        code_pattern=r"\.innerText\s*=",
        confidence=0.85,
    ),
    # createElement 是安全的
    CustomRule(
        rule_id="js.fp.create-element",
        description="createElement 通常是安全的",
        code_pattern=r"document\.createElement",
        confidence=0.7,
    ),
    # console.log 中的字符串不是安全问题
    CustomRule(
        rule_id="js.fp.console-log",
        description="console.log 中的字符串",
        code_pattern=r"console\.(log|debug|info|warn|error)\s*\(",
        confidence=0.8,
    ),
]


# ─────────────────────── 安全守卫模式 ───────────────────────

JS_SECURITY_GUARD_PATTERNS: Dict[str, List[str]] = {
    "xss": [
        r"DOMPurify\.sanitize",
        r"sanitize\s*\(",
        r"escapeHtml\s*\(",
        r"textContent\s*=",
        r"innerText\s*=",
        r"createElement",
        r"createTextNode",
        r"\.text\s*\(",           # jQuery .text() 是安全的
        r"Vue\.compile",          # Vue 模板编译
        r"React\.createElement",  # React JSX
        r"jsx",                   # JSX 标记
    ],
    "eval": [
        r"JSON\.parse",
        r"parseInt\s*\(",
        r"parseFloat\s*\(",
        r"Number\s*\(",
        r"Boolean\s*\(",
    ],
    "prototype_pollution": [
        r"Object\.freeze\s*\(",
        r"Object\.seal\s*\(",
        r"hasOwnProperty\s*\(",
        r"Object\.create\s*\(\s*null\s*\)",  # 无原型对象
        r"Map\s*\(",                           # 使用 Map 代替对象
    ],
    "injection": [
        r"sanitize\s*\(",
        r"escape\s*\(",
        r"encode\s*\(",
        r"validate\s*\(",
        r"whitelist",
        r"allowlist",
    ],
    "secrets": [
        r"process\.env\.",
        r"import\.meta\.env\.",
        r"getenv\s*\(",
        r"config\.",
        r"dotenv",
    ],
    "command_injection": [
        r"execFile\s*\(",         # execFile 比 exec 安全
        r"spawn\s*\(",            # spawn 使用数组参数
        r"child_process\.fork",
        r"shell:\s*false",
    ],
    "path_traversal": [
        r"path\.resolve\s*\(",
        r"path\.normalize\s*\(",
        r"__dirname",
        r"__filename",
        r"getCanonicalPath",
    ],
}


# ─────────────────────── 框架检测模式 ───────────────────────

FRAMEWORK_PATTERNS: Dict[str, Dict[str, Any]] = {
    "react": {
        "detect": [r"from\s+['\"]react['\"]", r"React\.", r"jsx", r"tsx?"],
        "safe_patterns": [r"React\.createElement", r"jsx", r"\{\{.*\}\}"],
        "dangerous_patterns": [r"dangerouslySetInnerHTML", r"__html"],
        "auto_escape": True,
    },
    "vue": {
        "detect": [r"from\s+['\"]vue['\"]", r"Vue\.", r"\.vue", r"v-html", r"v-bind"],
        "safe_patterns": [r"\{\{.*\}\}", r"v-text"],
        "dangerous_patterns": [r"v-html", r"\$options\.render"],
        "auto_escape": True,
    },
    "angular": {
        "detect": [r"@angular/", r"@Component", r"@Injectable", r"ngOnInit"],
        "safe_patterns": [r"interpolation", r"\{\{.*\}\}"],
        "dangerous_patterns": [r"\[innerHTML\]", r"bypassSecurityTrust"],
        "auto_escape": True,
    },
    "jquery": {
        "detect": [r"jQuery", r"\$\s*\(", r"from\s+['\"]jquery['\"]"],
        "safe_patterns": [r"\.text\s*\(", r"\.attr\s*\(", r"\.prop\s*\("],
        "dangerous_patterns": [r"\.html\s*\(", r"\.append\s*\(", r"\.prepend\s*\("],
        "auto_escape": False,
    },
    "express": {
        "detect": [r"from\s+['\"]express['\"]", r"require\s*\(\s*['\"]express['\"]"],
        "safe_patterns": [r"res\.json\s*\(", r"res\.send\s*\("],
        "dangerous_patterns": [r"res\.send\s*\(\s*req\.", r"res\.redirect\s*\(\s*req\."],
        "auto_escape": False,
    },
    "next": {
        "detect": [r"from\s+['\"]next", r"next/router", r"getServerSideProps"],
        "safe_patterns": [r"getServerSideProps", r"getStaticProps"],
        "dangerous_patterns": [r"dangerouslySetInnerHTML"],
        "auto_escape": True,
    },
}
