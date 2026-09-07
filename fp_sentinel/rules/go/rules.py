"""
Go 安全规则库 v2.3.0 (28条)

覆盖 OWASP Top 10 中与 Go 相关的常见高危漏洞场景。
所有正则经过 re.compile 验证，确保编译安全。

规则分类：
- COMMAND_INJECTION: 命令注入 (5条)
- SQL_INJECTION: SQL 注入 (4条)
- PATH_TRAVERSAL: 路径遍历 (4条)
- SECRETS: 硬编码密钥/敏感信息 (5条)
- SSRF: 服务端请求伪造 (3条)
- CRYPTO: 弱加密算法 (3条)
- TEMPLATE_INJECTION: 模板注入 (2条)
- INSECURE_TRANSPORT: 不安全传输 (2条)
"""

from typing import List, Dict


class GoRule:
    """Go 安全规则定义"""
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


# ─────────────────────── 命令注入 ───────────────────────

COMMAND_INJECTION_RULES = [
    GoRule(
        rule_id="go.injection.exec-cmd",
        description="exec.Command 传入外部输入变量作为参数，存在命令注入风险",
        severity="CRITICAL",
        confidence=0.75,
        code_pattern=r"exec\.Command\s*\(\s*(?:[a-z_]\w*\.?[a-zA-Z]+|os\.Args\[\d+\]|flag\.Arg\(\d?\))",
        category="COMMAND_INJECTION",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
        false_positive_indicators=[
            "exec.CommandContext", "ctx", "CommandContext", "stdin", "whitelist",
        ],
    ),
    GoRule(
        rule_id="go.injection.exec-shell",
        description="exec.Command 调用 shell (sh/bash/cmd) 执行动态命令，存在命令注入风险",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"""exec\.Command\s*\(\s*["'](?:sh|bash|cmd|powershell|zsh)["']""",
        category="COMMAND_INJECTION",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
    ),
    GoRule(
        rule_id="go.injection.exec-output",
        description="exec.CommandOutput 输出未经过滤，可能泄露敏感信息",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"""(?:\.CombinedOutput|\.Output)\s*\(\s*\)""",
        category="COMMAND_INJECTION",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["hex.EncodeToString", "base64"],
    ),
    GoRule(
        rule_id="go.injection.syscall-exec",
        description="syscall.Exec 或 syscall.ForkExec 直接执行外部命令",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"syscall\.(?:Exec|ForkExec)\s*\(",
        category="COMMAND_INJECTION",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
    ),
    GoRule(
        rule_id="go.injection-os-start-process",
        description="os.StartProcess 直接启动外部进程",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"os\.StartProcess\s*\(",
        category="COMMAND_INJECTION",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── SQL 注入 ───────────────────────

SQL_INJECTION_RULES = [
    GoRule(
        rule_id="go.injection.sql-query-fmt",
        description="使用 fmt.Sprintf/Sprintf 拼接 SQL 查询，存在 SQL 注入风险",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"""fmt\.S?printf\s*\(\s*["'`].*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b""",
        category="SQL_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
        false_positive_indicators=[
            "db.QueryRow", "db.Query", "db.Exec", "stmt", "Prepare", "placeholder",
        ],
    ),
    GoRule(
        rule_id="go.injection.sql-query-concat",
        description="使用字符串拼接构造 SQL 语句，存在 SQL 注入风险",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"""(?:"SELECT|"INSERT|"UPDATE|"DELETE|"WHERE)[^"]*\s*\+\s*(?:req\.|r\.|\w*(?:Param|Query|Form|Input|ID|id))""",
        category="SQL_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
    GoRule(
        rule_id="go.injection.sql-string-concat",
        description="使用字符串拼接构造 SQL 查询，存在 SQL 注入风险",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"""(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^;]*\+\s*(?:req\.|r\.|\w*(?:Param|Query|Form|Input))""",
        category="SQL_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
    GoRule(
        rule_id="go.injection.sql-template-string",
        description="使用 text/template 或 html/template 拼接 SQL，存在注入风险",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"""(?:(?:text|html)/template)\.New.*\.Parse.*(?:SELECT|INSERT|UPDATE|DELETE)""",
        category="SQL_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
    ),
    GoRule(
        rule_id="go.injection-sql-raw-query",
        description="database/sql 使用 RawBytes 或直接拼接查询字符串（未参数化）",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"""(?:\.QueryRow|\.Query|\.Exec)\s*\(\s*(?:fmt\.|"[^"]*["+])""",
        category="SQL_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["?", "$1", "$2", "args..."],
    ),
]


# ─────────────────────── 路径遍历 ───────────────────────

PATH_TRAVERSAL_RULES = [
    GoRule(
        rule_id="go.path.open-user-input",
        description="os.Open/ioutil.ReadFile 使用用户可控的文件路径，存在路径遍历风险",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"""(?:os\.(?:Open|OpenFile|Create|Remove|RemoveAll)|ioutil\.ReadFile|ioutil\.WriteFile|os\.ReadFile|os\.WriteFile)\s*\(\s*(?:[a-z_]\w*|r\.|\.)""",
        category="PATH_TRAVERSAL",
        cwe="CWE-22",
        owasp="A01:2021 - Broken Access Control",
        false_positive_indicators=[
            "filepath.Clean", "filepath.Abs", "strings.HasPrefix", "strings.Contains",
            "path.Join", "filepath.Join", "secure", "validate", "sanitize",
        ],
    ),
    GoRule(
        rule_id="go.path.join-user-input",
        description="filepath.Join 拼接用户输入路径，可能被 ../ 遍历",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"""filepath\.Join\s*\([^)]*(?:req\.|r\.|\w*(?:Param|Query|File|Path|Dir))""",
        category="PATH_TRAVERSAL",
        cwe="CWE-22",
        owasp="A01:2021 - Broken Access Control",
        false_positive_indicators=[
            "filepath.Clean", "strings.HasPrefix", "validate", "sanitize",
        ],
    ),
    GoRule(
        rule_id="go.path.ioutil-readdir",
        description="ioutil.ReadDir 使用用户可控的目录路径，可能泄露目录结构",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"""(?:ioutil\.ReadDir|os\.ReadDir)\s*\(\s*(?:[a-z_]\w*|r\.)""",
        category="PATH_TRAVERSAL",
        cwe="CWE-22",
        owasp="A01:2021 - Broken Access Control",
    ),
    GoRule(
        rule_id="go.path.symlink-follow",
        description="os.Symlink 创建符号链接或未校验的符号链接跟随，可能导致路径穿越",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"""(?:os\.Symlink|os\.Readlink|os\.Lstat)\s*\([^)]*(?:input|param|req\.|r\.)""",
        category="PATH_TRAVERSAL",
        cwe="CWE-59",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── 硬编码密钥/敏感信息 ───────────────────────

SECRETS_RULES = [
    GoRule(
        rule_id="go.secrets.hardcoded-password",
        description="Go 代码中硬编码密码",
        severity="CRITICAL",
        confidence=0.75,
        code_pattern=r"""(?i)(?:password|passwd|pwd)\s*(?:=|:)\s*["'][A-Za-z0-9!@#$%^&*()_+\-]{6,}["']""",
        category="SECRETS",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
        false_positive_indicators=[
            "os.Getenv", "os.LookupEnv", "flag.String", "viper.Get", "config.",
            "Getenv", "env.", "example", "placeholder", "test",
        ],
    ),
    GoRule(
        rule_id="go.secrets.hardcoded-api-key",
        description="Go 代码中硬编码 API Key",
        severity="CRITICAL",
        confidence=0.75,
        code_pattern=r"""(?i)(?:api[_-]?key|apikey|secret)\s*(?:=|:)\s*["'][A-Za-z0-9_\-]{16,}["']""",
        category="SECRETS",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
        false_positive_indicators=[
            "os.Getenv", "os.LookupEnv", "viper.Get", "config.", "Getenv",
        ],
    ),
    GoRule(
        rule_id="go.secrets.hardcoded-token",
        description="Go 代码中硬编码 Token",
        severity="CRITICAL",
        confidence=0.75,
        code_pattern=r"""(?i)(?:token|access_token|auth_token)\s*(?:=|:)\s*["'][A-Za-z0-9_\-\.]{20,}["']""",
        category="SECRETS",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
        false_positive_indicators=[
            "os.Getenv", "viper.Get", "config.", "jwt.", "Bearer",
        ],
    ),
    GoRule(
        rule_id="go.secrets.hardcoded-private-key",
        description="Go 代码中硬编码私钥",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
        category="SECRETS",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    GoRule(
        rule_id="go.secrets.aws-access-key",
        description="Go 代码中硬编码 AWS Access Key",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"AKIA[0-9A-Z]{16}",
        category="SECRETS",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
]


# ─────────────────────── SSRF ───────────────────────

SSRF_RULES = [
    GoRule(
        rule_id="go.ssrf.http-get-user-input",
        description="http.Get/http.Post 使用用户可控 URL，存在 SSRF 风险",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"""(?:http\.(?:Get|Post|PostForm|Head|Do)|client\.(?:Get|Post|Do))\s*\(\s*(?:[a-z_]\w*|r\.|req\.)""",
        category="SSRF",
        cwe="CWE-918",
        owasp="A10:2021 - Server-Side Request Forgery",
        false_positive_indicators=[
            "whitelist", "allowlist", "allowedHosts", "isAllowed", "validateURL",
            "url.Parse", "strings.HasPrefix", "isLoopback", "url.ParseRequestURI",
        ],
    ),
    GoRule(
        rule_id="go.ssrf.http-new-request",
        description="http.NewRequest 使用用户可控 URL，存在 SSRF 风险",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"""http\.NewRequest\s*\(\s*(?:"GET"|"POST"|"PUT"|"DELETE"|http\.[A-Z]+)\s*,\s*(?:[a-z_]\w*|r\.|req\.)""",
        category="SSRF",
        cwe="CWE-918",
        owasp="A10:2021 - Server-Side Request Forgery",
        false_positive_indicators=[
            "whitelist", "allowlist", "isAllowed", "validateURL", "url.ParseHost",
        ],
    ),
    GoRule(
        rule_id="go.ssrf.http-no-timeout",
        description="http.Client 未设置超时，可能导致资源耗尽或 SSRF 利用",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"http\.Client\s*\{\s*(?:(?!Timeout).)*?\}",
        category="SSRF",
        cwe="CWE-400",
        owasp="A05:2021 - Security Misconfiguration",
    ),
]


# ─────────────────────── 弱加密 ───────────────────────

CRYPTO_RULES = [
    GoRule(
        rule_id="go.crypto.weak-hash",
        description="使用 MD5/SHA1 哈希算法，已不再安全",
        severity="MEDIUM",
        confidence=0.7,
        code_pattern=r"""(?:md5\.(?:New|Sum)|sha1\.New|crypto/(?:md5|sha1))""",
        category="CRYPTO",
        cwe="CWE-328",
        owasp="A02:2021 - Cryptographic Failures",
        false_positive_indicators=["etag", "checksum", "noncrypto", "fingerprint"],
    ),
    GoRule(
        rule_id="go.crypto.des-3des",
        description="使用 DES/3DES 加密算法，已不再安全",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"cipher\.New(?:TripleDESCipher|DECBloB Cipher)|des\.New(?:Triple|Cipher)",
        category="CRYPTO",
        cwe="CWE-327",
        owasp="A02:2021 - Cryptographic Failures",
        false_positive_indicators=["cipher.NewCBCEncrypter", "cipher.NewGCM"],
    ),
    GoRule(
        rule_id="go.crypto.static-iv",
        description="使用固定初始化向量 (IV)，导致加密模式不安全",
        severity="MEDIUM",
        confidence=0.65,
        code_pattern=r"""(?:iv|nonce)\s*(?:=|:)\s*(?:\[\]byte|make\(\[\]byte)[^;]*\{[\s0x,]+\}""",
        category="CRYPTO",
        cwe="CWE-329",
        owasp="A02:2021 - Cryptographic Failures",
    ),
]


# ─────────────────────── Template 注入 ───────────────────────

TEMPLATE_INJECTION_RULES = [
    GoRule(
        rule_id="go.template.html-untrusted",
        description="html/template 渲染未经过滤的用户输入，存在 XSS/Template 注入风险",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"""(?:\.Execute|\.ExecuteTemplate)\s*\(\s*(?:\w+,\s*(?:req\.|r\.|\w*(?:Param|Query)))""",
        category="TEMPLATE_INJECTION",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["html Escape", "jsEscape", "template.HTMLEscape"],
    ),
    GoRule(
        rule_id="go.template.text-template-user",
        description="text/template 渲染用户可控输入（不使用自动转义）",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"""template\.(?:Must|New).*\.Parse(?:File|s)?\s*\(.*(?:input|param|user)""",
        category="TEMPLATE_INJECTION",
        cwe="CWE-1336",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── 不安全传输 ───────────────────────

INSECURE_TRANSPORT_RULES = [
    GoRule(
        rule_id="go.transport.insecure-skip-verify",
        description="TLS InsecureSkipVerify=true 跳过证书验证，存在中间人攻击风险",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"InsecureSkipVerify\s*:\s*(?:true|!0)",
        category="INSECURE_TRANSPORT",
        cwe="CWE-295",
        owasp="A02:2021 - Cryptographic Failures",
        false_positive_indicators=["devMode", "testing", "TestOnly", "localhost"],
    ),
    GoRule(
        rule_id="go.transport.http-no-tls",
        description="使用 net.Listen 提供 HTTP 服务而非 TLS",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"\.Listen\s*\(\s*\"http://",
        category="INSECURE_TRANSPORT",
        cwe="CWE-319",
        owasp="A02:2021 - Cryptographic Failures",
        false_positive_indicators=["localhost", "127.0.0.1", "10.0."],
    ),
]


# ─────────────────────── 汇总 ───────────────────────

GO_SECURITY_RULES: List[GoRule] = (
    COMMAND_INJECTION_RULES
    + SQL_INJECTION_RULES
    + PATH_TRAVERSAL_RULES
    + SECRETS_RULES
    + SSRF_RULES
    + CRYPTO_RULES
    + TEMPLATE_INJECTION_RULES
    + INSECURE_TRANSPORT_RULES
)

# 规则 ID 索引（O(1) 查找）
GO_RULES_INDEX: Dict[str, GoRule] = {r.rule_id: r for r in GO_SECURITY_RULES}


# ─────────────────────── 安全守卫模式 ───────────────────────

GO_SECURITY_GUARD_PATTERNS: Dict[str, List[str]] = {
    "command_injection": [
        r"exec\.CommandContext",       # 带上下文的命令执行
        r"whitelist",
        r"allowlist",
        r"isAllowed",
        r"shell\s*=\s*false",
        r"\.Fields\s*\(",              # 分割参数
        r"shlex",
    ],
    "sql_injection": [
        r"\$1", r"\$2",                # PostgreSQL 占位符
        r"\?",                          # MySQL/SQLite 占位符
        r":\w+",                        # Named parameter
        r"Prepare",
        r"parameterized",
        r"db\.Query",
        r"db\.Exec",
    ],
    "path_traversal": [
        r"filepath\.Clean",
        r"filepath\.Abs",
        r"filepath\.Rel",
        r"\.HasPrefix\s*\(",           # 前缀校验
        r"\.Contains\s*\(",            # 包含检查
        r"validate",
        r"sanitize",
    ],
    "ssrf": [
        r"whitelist",
        r"allowlist",
        r"isAllowed",
        r"validateURL",
        r"isLoopback",
        r"isPrivate",
        r"\.HasPrefix\s*\(",           # URL 前缀校验
        r"url\.Parse",
    ],
    "secrets": [
        r"os\.Getenv",
        r"os\.LookupEnv",
        r"viper\.Get",
        r"flag\.String",
        r"config\.",
    ],
    "crypto": [
        r"crypto/sha256",
        r"crypto/sha512",
        r"crypto/aes",
        r"cipher\.NewGCM",
    ],
}


# ─────────────────────── 误报规则 ───────────────────────

GO_FALSE_POSITIVE_RULES = [
    # 测试文件中的硬编码凭证
    GoRule(
        rule_id="go.fp.test-file",
        description="测试文件中的安全问题",
        file_pattern="*_test.go",
        confidence=0.85,
    ),
    # 示例/文档文件
    GoRule(
        rule_id="go.fp.example-file",
        description="示例/文档文件",
        file_pattern="*example*|*demo*|*sample*",
        confidence=0.6,
    ),
    # TestMain 函数
    GoRule(
        rule_id="go.fp.testmain",
        description="TestMain 中的配置",
        code_pattern=r"func\s+TestMain\s*\(",
        confidence=0.7,
    ),
    # _test.go 文件中的硬编码密码非真实风险
    GoRule(
        rule_id="go.fp.fake-password",
        description="明显的假密码/测试密码",
        code_pattern=r"""(?:password|passwd|pwd)\s*=\s*["'](?:test|example|123456|admin|password|changeme)["']""",
        confidence=0.9,
    ),
]
