"""
Python 安全规则库 (20条)

覆盖 OWASP Top 10 高危场景
"""

from typing import List, Dict, Any


class PythonRule:
    """Python 安全规则"""
    def __init__(
        self,
        rule_id: str,
        description: str,
        severity: str = "MEDIUM",
        confidence: float = 0.7,
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
        self.code_pattern = code_pattern
        self.category = category
        self.cwe = cwe
        self.owasp = owasp
        self.false_positive_indicators = false_positive_indicators or []


# ─────────────────────── SQL 注入 ───────────────────────

SQL_INJECTION_RULES = [
    PythonRule(
        rule_id="py.injection.sql",
        description="字符串拼接构造SQL语句，存在SQL注入风险",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"""(?:execute|executemany|raw)\s*\(\s*(?:f['\"]|['\"].*%|['\"].*\+|['\"].*\.format)""",
        category="SQL_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["%s", "%d", "parameterized", "prepared", "orm", "sqlalchemy"],
    ),
    PythonRule(
        rule_id="py.injection.format",
        description="使用 .format() 拼接SQL，存在注入风险",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"""(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*\.format\s*\(""",
        category="SQL_INJECTION",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["safe", "escape"],
    ),
]

# ─────────────────────── 命令注入 ───────────────────────

COMMAND_INJECTION_RULES = [
    PythonRule(
        rule_id="py.injection.command",
        description="使用 os.system/subprocess 执行命令，存在命令注入风险",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"""(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output))\s*\(\s*(?:f['\"]|['\"].*\+|['\"].*%)""",
        category="COMMAND_INJECTION",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["shell=False", "shlex.quote", "list2cmdline"],
    ),
    PythonRule(
        rule_id="py.injection.eval",
        description="使用 eval/exec 执行动态代码",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"""(?:eval|exec)\s*\(""",
        category="CODE_INJECTION",
        cwe="CWE-95",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["json.loads", "ast.literal_eval"],
    ),
    PythonRule(
        rule_id="py.injection.template",
        description="Jinja2模板未启用autoescape，存在XSS风险",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"""(?:Environment|Template)\s*\(\s*(?:.*autoescape\s*=\s*False|(?:(?!autoescape).)*$)""",
        category="XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        false_positive_indicators=["autoescape=True", "select_autoescape"],
    ),
]

# ─────────────────────── 反序列化 ───────────────────────

DESERIALIZATION_RULES = [
    PythonRule(
        rule_id="py.deserialization.pickle",
        description="使用pickle反序列化不可信数据，存在RCE风险",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"""pickle\.(?:loads?|Unpickler)\s*\(""",
        category="DESERIALIZATION",
        cwe="CWE-502",
        owasp="A08:2021 - Software and Data Integrity Failures",
    ),
    PythonRule(
        rule_id="py.deserialization.yaml",
        description="使用yaml.load而非safe_load，存在代码执行风险",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"""yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)""",
        category="DESERIALIZATION",
        cwe="CWE-502",
        owasp="A08:2021 - Software and Data Integrity Failures",
        false_positive_indicators=["safe_load", "SafeLoader"],
    ),
    PythonRule(
        rule_id="py.deserialization.marshal",
        description="使用marshal反序列化，存在安全风险",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"""marshal\.loads?\s*\(""",
        category="DESERIALIZATION",
        cwe="CWE-502",
        owasp="A08:2021 - Software and Data Integrity Failures",
    ),
]

# ─────────────────────── 加密问题 ───────────────────────

CRYPTO_RULES = [
    PythonRule(
        rule_id="py.crypto.weak_hash",
        description="使用MD5/SHA1进行密码哈希，强度不足",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"""(?:hashlib\.(?:md5|sha1)|MD5|SHA1)\s*\(""",
        category="CRYPTO",
        cwe="CWE-328",
        owasp="A02:2021 - Cryptographic Failures",
        false_positive_indicators=["checksum", "fingerprint", "digest", "hex"],
    ),
    PythonRule(
        rule_id="py.crypto.hardcoded_key",
        description="硬编码加密密钥或密码",
        severity="CRITICAL",
        confidence=0.7,
        code_pattern=r"""(?:SECRET_KEY|PASSWORD|API_KEY|TOKEN|PRIVATE_KEY)\s*=\s*['\"][A-Za-z0-9+/=]{16,}['\"]""",
        category="SECRETS",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
        false_positive_indicators=["os.environ", "getenv", "config", "settings", "example", "placeholder"],
    ),
    PythonRule(
        rule_id="py.crypto.weak_cipher",
        description="使用DES/RC4等弱加密算法",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"""(?:DES|RC4|Blowfish|ARC4)\s*\(|(?:ECB)\s*["\']""",
        category="CRYPTO",
        cwe="CWE-327",
        owasp="A02:2021 - Cryptographic Failures",
    ),
]

# ─────────────────────── 认证问题 ───────────────────────

AUTH_RULES = [
    PythonRule(
        rule_id="py.auth.debug_mode",
        description="生产环境开启DEBUG模式",
        severity="HIGH",
        confidence=0.6,
        code_pattern=r"""DEBUG\s*=\s*True""",
        category="MISCONFIGURATION",
        cwe="CWE-489",
        owasp="A05:2021 - Security Misconfiguration",
        false_positive_indicators=["os.environ", "getenv", "config", "settings.DEBUG"],
    ),
    PythonRule(
        rule_id="py.auth.no_csrf",
        description="Flask应用未启用CSRF保护",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"""Flask\s*\(__name__\).*(?!CSRFProtect|csrf)""",
        category="MISCONFIGURATION",
        cwe="CWE-352",
        owasp="A01:2021 - Broken Access Control",
    ),
    PythonRule(
        rule_id="py.auth.jwt_weak",
        description="JWT使用弱密钥或none算法",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"""(?:jwt\.encode|jwt\.decode)\s*\(.*(?:algorithms?\s*=\s*['\"]none['\"]|key\s*=\s*['\"][^'\"]{1,8}['\"])""",
        category="AUTH",
        cwe="CWE-347",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
]

# ─────────────────────── SSRF ───────────────────────

SSRF_RULES = [
    PythonRule(
        rule_id="py.ssrf.requests",
        description="requests访问用户可控URL，存在SSRF风险",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"""(?:requests\.(?:get|post|put|delete|head|patch)|urllib\.request\.urlopen)\s*\(\s*(?:req\.|params|body|url|user)""",
        category="SSRF",
        cwe="CWE-918",
        owasp="A10:2021 - Server-Side Request Forgery",
        false_positive_indicators=["whitelist", "allowlist", "validate_url"],
    ),
]

# ─────────────────────── 路径穿越 ───────────────────────

PATH_TRAVERSAL_RULES = [
    PythonRule(
        rule_id="py.path.traversal",
        description="文件路径拼接用户输入，存在路径穿越风险",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"""(?:open|os\.path\.join|pathlib\.Path)\s*\(\s*(?:req\.|params|user|input|\+)""",
        category="PATH_TRAVERSAL",
        cwe="CWE-22",
        owasp="A01:2021 - Broken Access Control",
        false_positive_indicators=["os.path.abspath", "resolve", "normalize", "secure_filename"],
    ),
]

# ─────────────────────── XXE ───────────────────────

XXE_RULES = [
    PythonRule(
        rule_id="py.xxe.lxml",
        description="lxml解析外部实体，存在XXE风险",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"""(?:etree\.parse|etree\.fromstring|lxml\.etree\.parse)\s*\((?!.*resolve_entities\s*=\s*False)""",
        category="XXE",
        cwe="CWE-611",
        owasp="A05:2021 - Security Misconfiguration",
        false_positive_indicators=["resolve_entities=False", "no_network"],
    ),
    PythonRule(
        rule_id="py.xxe.minidom",
        description="minidom解析XML，可能存在XXE风险",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"""xml\.dom\.minidom\.parse(?:String)?\s*\(""",
        category="XXE",
        cwe="CWE-611",
        owasp="A05:2021 - Security Misconfiguration",
    ),
]

# ─────────────────────── 敏感信息 ───────────────────────

SECRETS_RULES = [
    PythonRule(
        rule_id="py.secrets.env_leak",
        description="硬编码敏感环境变量",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"""(?:DATABASE_URL|REDIS_URL|AWS_SECRET|MONGODB_URI)\s*=\s*['\"][^'\"]+['\"]""",
        category="SECRETS",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
        false_positive_indicators=["os.environ", "getenv", "config"],
    ),
    PythonRule(
        rule_id="py.secrets.aws_key",
        description="AWS密钥泄露",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"""(?:AKIA[0-9A-Z]{16}|aws_secret_access_key\s*=\s*['\"][A-Za-z0-9+/=]{40}['\"])""",
        category="SECRETS",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
        false_positive_indicators=["example", "placeholder", "YOUR_KEY"],
    ),
]


# ─────────────────────── 汇总 ───────────────────────

PYTHON_SECURITY_RULES: List[PythonRule] = (
    SQL_INJECTION_RULES
    + COMMAND_INJECTION_RULES
    + DESERIALIZATION_RULES
    + CRYPTO_RULES
    + AUTH_RULES
    + SSRF_RULES
    + PATH_TRAVERSAL_RULES
    + XXE_RULES
    + SECRETS_RULES
)

PYTHON_RULES_INDEX: Dict[str, PythonRule] = {r.rule_id: r for r in PYTHON_SECURITY_RULES}
