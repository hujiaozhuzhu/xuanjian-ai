"""
Openfire 服务器专属漏洞规则库 v3.2.0

覆盖 Openfire XMPP 服务器中常见的安全风险场景，包含：
- 管理控制台安全
- 弱口令/默认凭证
- 未授权访问
- 跨站脚本 (XSS)
- 跨站请求伪造 (CSRF)
- 不安全的连接管理
- 文件上传安全
- 群组聊天权限
- LDAP/数据库配置安全
- 插件安全

规则分类：
- OPENFIRE_ADMIN: 管理控制台 (6条)
- OPENFIRE_AUTH: 弱口令/默认凭证 (5条)
- OPENFIRE_XSS: XSS 漏洞 (5条)
- OPENFIRE_CSRF: CSRF 漏洞 (4条)
- OPENFIRE_FILE: 文件操作 (5条)
- OPENFIRE_DB: 数据库配置 (5条)
- OPENFIRE_PLUGIN: 插件安全 (5条)
- OPENFIRE_LDAP: LDAP 配置 (5条)
"""

from typing import List, Dict


class OpenfireRule:
    """Openfire 安全规则定义"""

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


# ─────────────────────── 管理控制台安全 ───────────────────────

OPENFIRE_ADMIN_RULES = [
    OpenfireRule(
        rule_id="openfire.admin-default-port",
        description="Openfire 管理控制台使用默认端口 9090/9091",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"(?:port|listen)[\"'\s]* (=|:)[\s\"']*9090|9091[\"']",
        category="OPENFIRE_ADMIN",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
    OpenfireRule(
        rule_id="openfire.admin-no-ip-restriction",
        description="Openfire 控制台未限制允许的 IP 地址",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"admin\.console\.network\.trustedIPs\s*=\s*[\"'][\"']",
        category="OPENFIRE_ADMIN",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
    OpenfireRule(
        rule_id="openfire.admin-ssl-disabled",
        description="Openfire 控制台未启用 SSL 加密传输",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"admin\.console\.secure\.enabled\s*=\s*false|console\.ssl\.enabled\s*=\s*false",
        category="OPENFIRE_ADMIN",
        cwe="CWE-319",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    OpenfireRule(
        rule_id="openfire.admin-debug-enabled",
        description="Openfire 管理控制台调试模式开启",
        severity="MEDIUM",
        confidence=0.65,
        code_pattern=r"admin\.console\.debug\.enabled\s*=\s*true|console\.debug\s*=\s*true",
        category="OPENFIRE_ADMIN",
        cwe="CWE-489",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    OpenfireRule(
        rule_id="openfire.admin-session-timeout-low",
        description="Openfire 会话超时时间过长（>12小时）",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"admin\.console\.session\.timeout\s*=\s*[0-9]{5,}",
        category="OPENFIRE_ADMIN",
        cwe="CWE-613",
        owasp="A01:2021 - Broken Access Control",
    ),
    OpenfireRule(
        rule_id="openfire.admin-websocket-open",
        description="Openfire WebSocket (ws/wss) 端点未授权访问",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"httpbinding\.enabled\s*=\s*true(?!.*websocket\.secured\s*=\s*true)",
        category="OPENFIRE_ADMIN",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── 弱口令/默认凭证 ───────────────────────

OPENFIRE_AUTH_RULES = [
    OpenfireRule(
        rule_id="openfire.auth-default-admin",
        description="Openfire 使用默认 admin/admin 或 admin/password 账号",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"admin\.password\s*=\s*[\"'][^\"']{1,20}[\"']|user\.password\s*=\s*[\"']admin[\"']|\"admin\",\s*\"[^\"']{1,10}[\"']\s*\)",
        category="OPENFIRE_AUTH",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    OpenfireRule(
        rule_id="openfire.auth-empty-password",
        description="Openfire 管理员账号配置为空密码",
        severity="CRITICAL",
        confidence=0.95,
        code_pattern=r"(?:user|admin|manager)\.password\s*=\s*[\"'][\"']",
        category="OPENFIRE_AUTH",
        cwe="CWE-258",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    OpenfireRule(
        rule_id="openfire.auth-hashed-password-weak",
        description="Openfire 密码使用弱哈希（Blowfish/MD5）",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"password\b.*=|setPassword.*[Bb]lowfish|user\.password.*MD5",
        category="OPENFIRE_AUTH",
        cwe="CWE-327",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    OpenfireRule(
        rule_id="openfire.auth-no-login-limit",
        description="Openfire 未启用登录失败锁定",
        severity="MEDIUM",
        confidence=0.65,
        code_pattern=r"admin\.console\.login\.enabled\s*=\s*true(?!.*max\.attempts)",
        category="OPENFIRE_AUTH",
        cwe="CWE-307",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    OpenfireRule(
        rule_id="openfire.auth-registration-open",
        description="Openfire 允许任意用户自助注册",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"registration\.enabled\s*=\s*true|inband\.registration\.enabled\s*=\s*true",
        category="OPENFIRE_AUTH",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── XSS 漏洞 ───────────────────────

OPENFIRE_XSS_RULES = [
    OpenfireRule(
        rule_id="openfire.xss-muc-message",
        description="Openfire 多用户聊天(MUC)消息未做 XSS 过滤",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"ForumHistory|MessageBroadcast\.setMessage\s*\([^)]*(?!.*sanitize)",
        category="OPENFIRE_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    OpenfireRule(
        rule_id="openfire.xss-stream-content",
        description="Openfire XMPP 流内容中未过滤 HTML 标签",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"XMPPPacketFilter.*body|getBody\(\)\s*(?!.*sanitize|.*escape)",
        category="OPENFIRE_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    OpenfireRule(
        rule_id="openfire.xss-admin-console",
        description="Openfire 管理控制台页面 XSS（param直接打印）",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"PrintWriter\.write\s*\(\s*req\.getParameter|response\.getWriter\s*\(\s*\).print\s*\(\s*param",
        category="OPENFIRE_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    OpenfireRule(
        rule_id="openfire.xss-pubsub-payload",
        description="Openfire PubSub 节点发布内容未过滤",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"setPayload\s*\([^)]*getPayloadString\s*\(\s*\)(?!.*sanitize)",
        category="OPENFIRE_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
    OpenfireRule(
        rule_id="openfire.xss-bookmark-url",
        description="Openfire URL 书签存储/读取未过滤",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"URLBookmark\.setURL|getURL\(\)\s*(?!.*validate)",
        category="OPENFIRE_XSS",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
    ),
]


# ─────────────────────── CSRF 漏洞 ───────────────────────

OPENFIRE_CSRF_RULES = [
    OpenfireRule(
        rule_id="openfire.csrf-admin-actions",
        description="Openfire 管理控制台操作缺少 CSRF 校验",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"@RequestMapping.*admin(?!.*@Csrf|.*CSRF)",
        category="OPENFIRE_CSRF",
        cwe="CWE-352",
        owasp="A01:2021 - Broken Access Control",
    ),
    OpenfireRule(
        rule_id="openfire.csrf-missing-token",
        description="Openfire Plugin 未检查 CSRF Token",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"doPost\s*\([^)]*\)\s*\{[^}]*(?!.*csrf|.*Xsrf|.*_xsrf)",
        category="OPENFIRE_CSRF",
        cwe="CWE-352",
        owasp="A01:2021 - Broken Access Control",
    ),
    OpenfireRule(
        rule_id="openfire.csrf-form-no-token",
        description="Openfire 表单提交缺少 _xsrf/CSRF 参数",
        severity="MEDIUM",
        confidence=0.65,
        code_pattern=r"<form[^>]*action[^>]*admin[^>]*(?!.*_xsrf|.*csrf_token)",
        category="OPENFIRE_CSRF",
        cwe="CWE-352",
        owasp="A01:2021 - Broken Access Control",
    ),
    OpenfireRule(
        rule_id="openfire.csrf-get-state-change",
        description="Openfire 使用 GET 请求执行状态变更操作（删除/修改）",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"@GetMapping.*delete|@GetMapping.*drop|@GetMapping.*disable|@GetMapping.*clear",
        category="OPENFIRE_CSRF",
        cwe="CWE-352",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── 文件操作安全 ───────────────────────

OPENFIRE_FILE_RULES = [
    OpenfireRule(
        rule_id="openfire.file-transfer-no-scan",
        description="Openfire 文件传输未做恶意文件扫描",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"FileTransferManager.*transfer(?!.*scan|.*antivirus)",
        category="OPENFIRE_FILE",
        cwe="CWE-434",
        owasp="A04:2021 - Insecure Design",
    ),
    OpenfireRule(
        rule_id="openfire.file-upload-no-type-check",
        description="Openfire 文件上传未校验文件类型",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"uploadFile\s*\([^)]*(?!.*ContentType|.*extension|.*whitelist)",
        category="OPENFIRE_FILE",
        cwe="CWE-434",
        owasp="A04:2021 - Insecure Design",
    ),
    OpenfireRule(
        rule_id="openfire.file-share-executable",
        description="Openfire 文件共享允许上传可执行文件",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"fileShare\.executable.*allowed\s*=\s*true|fileShare\.allowedExtensions\s*=\s*['\"]*,['\"]*",
        category="OPENFIRE_FILE",
        cwe="CWE-434",
        owasp="A04:2021 - Insecure Design",
    ),
    OpenfireRule(
        rule_id="openfire.file-vcard-unrestricted",
        description="Openfire vCard 头像上传未限制文件路径",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"setVCard\s*\([^)]*(?!.*allowedExtensions|.*whitelist)",
        category="OPENFIRE_FILE",
        cwe="CWE-434",
        owasp="A04:2021 - Insecure Design",
    ),
    OpenfireRule(
        rule_id="openfire.file-path-traversal",
        description="Openfire 文件读取操作未过滤 ../ 路径遍历",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"getServletContext\s*\(\s*\)\.getRealPath\s*\([^)]*(?:param|input|user)",
        category="OPENFIRE_FILE",
        cwe="CWE-22",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── 数据库配置安全 ───────────────────────

OPENFIRE_DB_RULES = [
    OpenfireRule(
        rule_id="openfire.db-default-creds",
        description="Openfire 使用默认数据库账号（sa/空密码）",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"connection\.password\s*=\s*[\"'][\"']|connection\.username\s*=\s*[\"']sa[\"']",
        category="OPENFIRE_DB",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    OpenfireRule(
        rule_id="openfire.db-plaintext-password",
        description="Openfire 数据库配置中密码明文存储",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"(?:db\.password|database\.password)\s*=\s*[\"'][^\"']{3,}[\"']",
        category="OPENFIRE_DB",
        cwe="CWE-256",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    OpenfireRule(
        rule_id="openfire.db-no-ssl",
        description="Openfire 数据库连接未启用 SSL/TLS",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"(?:db|database)\.url\s*=\s*[^\"']*(?:sqlserver|mysql|postgresql)(?!.*ssl=true|.*encrypt=true)",
        category="OPENFIRE_DB",
        cwe="CWE-319",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    OpenfireRule(
        rule_id="openfire.db-permissive-schema",
        description="Openfire 数据库用户权限过大（非最小权限）",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"database\.privileges\s*=\s*[\"']all[\"']|connection\.role\s*=\s*[\"']dba[\"']",
        category="OPENFIRE_DB",
        cwe="CWE-266",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    OpenfireRule(
        rule_id="openfire.db-hsqldb-internal",
        description="Openfire 使用 HSQLDB 内嵌数据库（不推荐生产环境）",
        severity="MEDIUM",
        confidence=0.65,
        code_pattern=r"hsqldb|database\.driver\s*=\s*[\"']org\.hsqldb\.jdbcDriver[\"']",
        category="OPENFIRE_DB",
        cwe="CWE-1187",
        owasp="A04:2021 - Insecure Design",
    ),
]


# ─────────────────────── 插件安全 ───────────────────────

OPENFIRE_PLUGIN_RULES = [
    OpenfireRule(
        rule_id="openfire.plugin-dev-mode",
        description="Openfire 开发模式允许加载未签名插件",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"plugin\.developer\.mode\s*=\s*true|plugin\.allow\.unsigned\s*=\s*true",
        category="OPENFIRE_PLUGIN",
        cwe="CWE-494",
        owasp="A08:2021 - Software and Data Integrity Failures",
    ),
    OpenfireRule(
        rule_id="openfire.plugin-auto-update",
        description="Openfire 插件自动更新未校验签名",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"plugin\.update\.auto\s*=\s*true(?!.*verify|.*checksum|.*signature)",
        category="OPENFIRE_PLUGIN",
        cwe="CWE-494",
        owasp="A08:2021 - Software and Data Integrity Failures",
    ),
    OpenfireRule(
        rule_id="openfire.plugin-console-permissive",
        description="Openfire 控制台允许安装任意 JAR 插件",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"plugin\.install\.未经校验|plugin\.upload(?!.*verify|.*whitelist)",
        category="OPENFIRE_PLUGIN",
        cwe="CWE-494",
        owasp="A08:2021 - Software and Data Integrity Failures",
    ),
    OpenfireRule(
        rule_id="openfire.plugin-obsolete-version",
        description="Openfire 已安装已知漏洞版本插件（如 Monitoring/ fastpath）",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"<version>\\s*((?:0|1|2)\\.(?:0|1|2|3|4|5)\\.[0-9]+)\\s*</version>",
        category="OPENFIRE_PLUGIN",
        cwe="CWE-1104",
        owasp="A08:2021 - Software and Data Integrity Failures",
    ),
    OpenfireRule(
        rule_id="openfire.plugin-web-context-exposed",
        description="Openfire Plugin Web 上下文路径暴露未配置安全约束",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"<context-param>\s*<param-name>(?!.*security)",
        category="OPENFIRE_PLUGIN",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── LDAP 配置安全 ───────────────────────

OPENFIRE_LDAP_RULES = [
    OpenfireRule(
        rule_id="openfire.ldap-anon-bind",
        description="Openfire LDAP 匿名绑定（无需凭证）",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"ldap\.anonymousBind\s*=\s*true|ldap\.allowAnonymous\s*=\s*true",
        category="OPENFIRE_LDAP",
        cwe="CWE-287",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    OpenfireRule(
        rule_id="openfire.ldap-plaintext-bind",
        description="Openfire LDAP 绑定密码明文存储",
        severity="HIGH",
        confidence=0.9,
        code_pattern=r"ldap\.managerDN\s*=.*ldap\.managerPassword\s*=\s*[\"'][^\"']{3,}[\"']",
        category="OPENFIRE_LDAP",
        cwe="CWE-256",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    OpenfireRule(
        rule_id="openfire.ldap-no-starttls",
        description="Openfire LDAP 连接未使用 STARTTLS/LDAPS",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"ldap\.host\s*=\s*[\"']ldap://(?!.*startTls)",
        category="OPENFIRE_LDAP",
        cwe="CWE-319",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    OpenfireRule(
        rule_id="openfire.ldap-base-dn-open",
        description="Openfire LDAP 基础 DN 未限制用户搜索范围",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"ldap\.baseDN\s*=\s*[\"'].*,dc=com[\"'](?!.*subtree)",
        category="OPENFIRE_LDAP",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
    OpenfireRule(
        rule_id="openfire.ldap-posix-group-no-filter",
        description="Openfire posixGroup 模式未配置 groupSearchFilter",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"ldap\.group\.searchFilter\s*=[\"'][\"']",
        category="OPENFIRE_LDAP",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── 安全守卫模式 ───────────────────────

OPENFIRE_SECURITY_GUARD_PATTERNS: Dict[str, List[str]] = {
    "admin": [
        r"admin\.console\.security",
        r"RemoteAddrValve",
        r"_trustedIPs",
    ],
    "auth": [
        r"PBKDF2",
        r"BCrypt",
        r"passwordHash",
        r"ScramSha1",
    ],
    "csrf": [
        r"CsrfToken",
        r"_xsrf",
        r"@Csrf",
        r"RequestToken",
    ],
    "plugin": [
        r"plugin\.verify",
        r"signed",
        r"checksum",
    ],
}


# ─────────────────────── 误报规则 ───────────────────────

OPENFIRE_FALSE_POSITIVE_RULES = []


# ─────────────────────── 汇总 ───────────────────────

OPENFIRE_SECURITY_RULES: List[OpenfireRule] = (
    OPENFIRE_ADMIN_RULES
    + OPENFIRE_AUTH_RULES
    + OPENFIRE_XSS_RULES
    + OPENFIRE_CSRF_RULES
    + OPENFIRE_FILE_RULES
    + OPENFIRE_DB_RULES
    + OPENFIRE_PLUGIN_RULES
    + OPENFIRE_LDAP_RULES
)

OPENFIRE_RULES_INDEX: Dict[str, OpenfireRule] = {
    r.rule_id: r for r in OPENFIRE_SECURITY_RULES
}

OPENFIRE_RULES_BY_SEVERITY: Dict[str, List[OpenfireRule]] = {
    "CRITICAL": [r for r in OPENFIRE_SECURITY_RULES if r.severity == "CRITICAL"],
    "HIGH": [r for r in OPENFIRE_SECURITY_RULES if r.severity == "HIGH"],
    "MEDIUM": [r for r in OPENFIRE_SECURITY_RULES if r.severity == "MEDIUM"],
    "LOW": [r for r in OPENFIRE_SECURITY_RULES if r.severity == "LOW"],
}

OPENFIRE_RULE_COUNT: int = len(OPENFIRE_SECURITY_RULES)

# Openfire 特征文件模式
OPENFIRE_FILE_PATTERNS = [
    "openfire.xml",
    "conf/openfire.xml",
    "plugins/admin/web-INF/",
    "*.jar (plugin)",
    "openfire.xmllevel",
]
