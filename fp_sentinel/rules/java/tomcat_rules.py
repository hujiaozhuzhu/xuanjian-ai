"""
Tomcat 服务器专属漏洞规则库 v3.2.0

覆盖 Apache Tomcat 容器中常见的安全风险场景，包含：
- AJP 幽灵猫漏洞 (CVE-2020-1938)
- 弱口令/默认口令
- 管理界面暴露
- 不安全的反序列化配置
- Session 持久化风险
- 不安全的 CORS 配置
- 连接器安全配置缺陷
- SSL/TLS 弱配置
- 不安全的错误页面
- 目录遍历/欢迎文件风险

规则分类：
- AJP_GHOSTCAT: AJP 协议漏洞 (5条)
- DEFAULT_CREDENTIAL: 默认/弱口令 (5条)
- MANAGER_EXPOSURE: 管理界面暴露 (6条)
- SSL_TLS_MISCONFIG: SSL/TLS 弱配置 (6条)
- CONNECTOR_MISCONFIG: 连接器配置缺陷 (5条)
- ERROR_PAGE: 错误页面信息泄露 (4条)
- DIRECTORY_TRAVERSAL: 目录遍历风险 (5条)
- CLUSTER_SECURITY: 集群通信安全 (4条)
"""

from typing import List, Dict


class TomcatRule:
    """Tomcat 安全规则定义"""

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


# ─────────────────────── AJP 幽灵猫漏洞 ───────────────────────

AJP_GHOSTCAT_RULES = [
    TomcatRule(
        rule_id="tomcat.ajp-enabled",
        description="Tomcat AJP 连接器开启且未设置 secret，存在 CVE-2020-1938 幽灵猫漏洞",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"<Connector\s+protocol=\"AJP/1.3\"(?!.*secretRequired=\"true\").*(?!.*secret=\")",
        category="AJP_GHOSTCAT",
        cwe="CWE-284",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    TomcatRule(
        rule_id="tomcat.ajp-weak-secret",
        description="Tomcat AJP 连接器使用弱口令 secret（容易被爆破）",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"secret=[\"'](?:tomcat|admin|password|123456|changeme|secret)[\"']",
        category="AJP_GHOSTCAT",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    TomcatRule(
        rule_id="tomcat.ajp-allow-all-ip",
        description="AJP 连接器未限制允许的 IP 来源",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"<Connector\s+protocol=\"AJP/1.3\"(?!.*allowedRequestAttributesPattern).*(?!.*address=)",
        category="AJP_GHOSTCAT",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
    TomcatRule(
        rule_id="tomcat.ajp-port-public",
        description="AJP 端口绑定到公网 IP (0.0.0.0)",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"<Connector\s+protocol=\"AJP/1.3\".*address=[\"']0\.0\.0\.0[\"']",
        category="AJP_GHOSTCAT",
        cwe="CWE-668",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    TomcatRule(
        rule_id="tomcat.ajp-secret-required-disabled",
        description="Tomcat 9.0.31+ 未设置 secretRequired=true",
        severity="HIGH",
        confidence=0.8,
        code_pattern=r"<Connector\s+protocol=\"AJP/1.3\"(?!.*secretRequired)",
        category="AJP_GHOSTCAT",
        cwe="CWE-284",
        owasp="A05:2021 - Security Misconfiguration",
    ),
]


# ─────────────────────── 默认/弱口令 ───────────────────────

DEFAULT_CREDENTIAL_RULES = [
    TomcatRule(
        rule_id="tomcat.default-manager-user",
        description="Tomcat 使用默认 manager 用户/密码（tomcat/tomcat 等）",
        severity="CRITICAL",
        confidence=0.9,
        code_pattern=r"(?:username|password)=[\"'](?:tomcat|admin|manager|role1|both|j2deployer|ovwebusr|cxsdk|ADMIN|ROOT|max|power)[\"']",
        category="DEFAULT_CREDENTIAL",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    TomcatRule(
        rule_id="tomcat.hardcoded-credentials",
        description="tomcat-users.xml 中硬编码用户密码",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"password=[\"'][^\"']{1,20}[\"']",
        category="DEFAULT_CREDENTIAL",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
        false_positive_indicators=["encrypted", "CredentialHandler"],
    ),
    TomcatRule(
        rule_id="tomcat.empty-password",
        description="Tomcat 用户配置为空密码",
        severity="CRITICAL",
        confidence=0.95,
        code_pattern=r"password=[\"'][\"']",
        category="DEFAULT_CREDENTIAL",
        cwe="CWE-258",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    TomcatRule(
        rule_id="tomcat.weak-password-hash",
        description="Tomcat 配置弱密码哈希算法（MD5/SHA1）",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"CredentialHandler.*algorithm=[\"'](?:MD5|SHA1|SHA)[\"']",
        category="DEFAULT_CREDENTIAL",
        cwe="CWE-327",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    TomcatRule(
        rule_id="tomcat.shared-account",
        description="Tomcat 配置中多个用户使用相同账号密码",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"(?:password=[\"'][^\"']+[\"'][\s\S]*){2,}",
        category="DEFAULT_CREDENTIAL",
        cwe="CWE-287",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
]


# ─────────────────────── 管理界面暴露 ───────────────────────

MANAGER_EXPOSURE_RULES = [
    TomcatRule(
        rule_id="tomcat.manager-app-deployed",
        description="Tomcat Manager 应用部署在公网环境",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"manager\.xml|manager-webapp|Tomcat Manager",
        category="MANAGER_EXPOSURE",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
    TomcatRule(
        rule_id="tomcat.host-manager-exposed",
        description="Host Manager 应用暴露允许远程管理虚拟主机",
        severity="CRITICAL",
        confidence=0.85,
        code_pattern=r"host-manager\.xml|/host-manager/\"",
        category="MANAGER_EXPOSURE",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
    TomcatRule(
        rule_id="tomcat.manager-remote-access",
        description="Tomcat Manager 允许远程 IP 访问（未限制 127.0.0.1）",
        severity="CRITICAL",
        confidence=0.8,
        code_pattern=r"<Valve\s+className=\"org\.apache\.catalina\.valves\.RemoteAddrValve\"(?!.*allow=[\"']127\\.)",
        category="MANAGER_EXPOSURE",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
    TomcatRule(
        rule_id="tomcat.manager-get-upload",
        description="Tomcat Manager 允许通过 GET 请求部署应用（CVE-2009-0580 类似风险）",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"/manager/html/upload",
        category="MANAGER_EXPOSURE",
        cwe="CWE-434",
        owasp="A04:2021 - Insecure Design",
    ),
    TomcatRule(
        rule_id="tomcat.example-app-present",
        description="Tomcat 示例应用 (sample/docs) 未删除",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"examples\.war|docs\.war|sample\.war|ROOT[\/\\]examples",
        category="MANAGER_EXPOSURE",
        cwe="CWE-200",
        owasp="A01:2021 - Broken Access Control",
    ),
    TomcatRule(
        rule_id="tomcat.admin-gui-exposed",
        description="Tomcat Admin GUI 端点暴露",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"admin\.war|/admin/\"",
        category="MANAGER_EXPOSURE",
        cwe="CWE-200",
        owasp="A01:2021 - Broken Access Control",
    ),
]


# ─────────────────────── SSL/TLS 弱配置 ───────────────────────

SSL_TLS_MISCONFIG_RULES = [
    TomcatRule(
        rule_id="tomcat.ssl-weak-protocol",
        description="Tomcat 使用 SSLv3/TLSv1.0/TLSv1.1 弱协议",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"sslProtocol=[\"'][\"']|sslEnabledProtocols=[\"'](?:TLSv1|TLSv1\\.1|SSLv3)[\"']",
        category="SSL_TLS_MISCONFIG",
        cwe="CWE-326",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    TomcatRule(
        rule_id="tomcat.ssl-weak-cipher",
        description="Tomcat 启用弱加密套件（RC4/DES/3DES/NULL/EXPORT）",
        severity="HIGH",
        confidence=0.85,
        code_pattern=r"ciphers=[\"'].*(?:RC4|DES|NULL|EXPORT|anon|MD5|SHA)[\"']",
        category="SSL_TLS_MISCONFIG",
        cwe="CWE-327",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    TomcatRule(
        rule_id="tomcat.ssl-no-redirect",
        description="Tomcat 未配置 HTTP 到 HTTPS 强制跳转",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"redirectPort=[\"']8080[\"']",
        category="SSL_TLS_MISCONFIG",
        cwe="CWE-319",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    TomcatRule(
        rule_id="tomcat.ssl-unverified-client",
        description="Tomcat 要求客户端证书但未验证",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"clientAuth=[\"']want[\"']",
        category="SSL_TLS_MISCONFIG",
        cwe="CWE-295",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    TomcatRule(
        rule_id="tomcat.ssl-keystore-weak-password",
        description="Tomcat keystore 使用弱密码",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"keystorePass=[\"'](?:changeit|tomcat|password|123456|admin)[\"']",
        category="SSL_TLS_MISCONFIG",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
    ),
    TomcatRule(
        rule_id="tomcat.ssl-hsts-missing",
        description="Tomcat 未启用 HSTS（HTTP Strict Transport Security）",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"hstsEnabled=[\"']false[\"']",
        category="SSL_TLS_MISCONFIG",
        cwe="CWE-523",
        owasp="A05:2021 - Security Misconfiguration",
    ),
]


# ─────────────────────── 连接器配置缺陷 ───────────────────────

CONNECTOR_MISCONFIG_RULES = [
    TomcatRule(
        rule_id="tomcat.connector-max-post-size",
        description="Tomcat 连接器 maxPostSize 过大可能导致 DOS",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"maxPostSize=[\"'][0-9]{8,}[\"']",
        category="CONNECTOR_MISCONFIG",
        cwe="CWE-770",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    TomcatRule(
        rule_id="tomcat.connector-max-threads-low",
        description="Tomcat 最大线程数过低易被 DOS",
        severity="LOW",
        confidence=0.4,
        code_pattern=r"maxThreads=[\"'][0-9]{1,2}[\"']",
        category="CONNECTOR_MISCONFIG",
        cwe="CWE-770",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    TomcatRule(
        rule_id="tomcat.connector-timeout-long",
        description="Tomcat connectionTimeout 过慢（>60s）增加慢速攻击风险",
        severity="MEDIUM",
        confidence=0.5,
        code_pattern=r"connectionTimeout=[\"'][0-9]{5,}[\"']",
        category="CONNECTOR_MISCONFIG",
        cwe="CWE-400",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    TomcatRule(
        rule_id="tomcat.connector-keepalive-disabled",
        description="Tomcat keepAlive 禁用影响性能但不影响安全",
        severity="LOW",
        confidence=0.4,
        code_pattern=r"keepAliveTimeout=[\"']-1[\"']",
        category="CONNECTOR_MISCONFIG",
        cwe="CWE-400",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    TomcatRule(
        rule_id="tomcat.connector-lookup-disabled",
        description="Tomcat DNS 反向查找关闭不影响安全但可能影响日志记录",
        severity="LOW",
        confidence=0.35,
        code_pattern=r"enableLookups=[\"']false[\"']",
        category="CONNECTOR_MISCONFIG",
        cwe="CWE-200",
        owasp="A05:2021 - Security Misconfiguration",
    ),
]


# ─────────────────────── 错误页面信息泄露 ───────────────────────

ERROR_PAGE_RULES = [
    TomcatRule(
        rule_id="tomcat.error-page-stacktrace",
        description="Tomcat 默认错误页面暴露堆栈信息",
        severity="MEDIUM",
        confidence=0.7,
        code_pattern=r"<error-page>(?!.*<location>/error\\.html)</error-page>",
        category="ERROR_PAGE",
        cwe="CWE-209",
        owasp="A04:2021 - Insecure Design",
    ),
    TomcatRule(
        rule_id="tomcat.error-page-server-info",
        description="Tomcat Server 信息头暴露版本号（Server: Tomcat/8.5.xx）",
        severity="LOW",
        confidence=0.5,
        code_pattern=r"server=[\"'][\"']",
        category="ERROR_PAGE",
        cwe="CWE-200",
        owasp="A05:2021 - Security Misconfiguration",
    ),
    TomcatRule(
        rule_id="tomcat.error-jserv-info",
        description="Tomcat mod_jk 信息页面暴露内部路由信息",
        severity="HIGH",
        confidence=0.65,
        code_pattern=r"jstatus|modjk|jkmanager",
        category="ERROR_PAGE",
        cwe="CWE-200",
        owasp="A01:2021 - Broken Access Control",
    ),
    TomcatRule(
        rule_id="tomcat.error-nginx-proxy-info",
        description="Tomcat 错误页面暴露内部地址可能被用于 SSRF",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"proxyErrorOverride=[\"']false[\"']",
        category="ERROR_PAGE",
        cwe="CWE-215",
        owasp="A04:2021 - Insecure Design",
    ),
]


# ─────────────────────── 目录遍历风险 ───────────────────────

DIRECTORY_TRAVERSAL_RULES = [
    TomcatRule(
        rule_id="tomcat.dir-listing-enabled",
        description="Tomcat 默认 Servlet 允许目录遍历",
        severity="MEDIUM",
        confidence=0.75,
        code_pattern=r"<init-param>\s*<param-name>listings</param-name>\s*<param-value>true</param-value>\s*</init-param>",
        category="DIRECTORY_TRAVERSAL",
        cwe="CWE-548",
        owasp="A01:2021 - Broken Access Control",
    ),
    TomcatRule(
        rule_id="tomcat.dir-welcome-files-unsafe",
        description="Tomcat welcome-file 配置存在服务端文件风险",
        severity="MEDIUM",
        confidence=0.6,
        code_pattern=r"<welcome-file>.*\\.(?:jsp|jspx|html|htm)",
        category="DIRECTORY_TRAVERSAL",
        cwe="CWE-219",
        owasp="A04:2021 - Insecure Design",
    ),
    TomcatRule(
        rule_id="tomcat.context-cross-accessible",
        description="TomContext crossContext=true 允许跨上下文访问",
        severity="MEDIUM",
        confidence=0.65,
        code_pattern=r"crossContext=[\"']true[\"']",
        category="DIRECTORY_TRAVERSAL",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
    TomcatRule(
        rule_id="tomcat.context-docbase-absolute",
        description="Tomcat Context 使用绝对 docBase 存在 SSRF/RCE 风险",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"docBase=[\"'][\"']",
        category="DIRECTORY_TRAVERSAL",
        cwe="CWE-22",
        owasp="A01:2021 - Broken Access Control",
    ),
    TomcatRule(
        rule_id="tomcat.context-privileged",
        description="Tomcat privileged=true 允许访问 Servlet API",
        severity="MEDIUM",
        confidence=0.55,
        code_pattern=r"privileged=[\"']true[\"']",
        category="DIRECTORY_TRAVERSAL",
        cwe="CWE-266",
        owasp="A04:2021 - Insecure Design",
    ),
]


# ─────────────────────── 集群通信安全 ───────────────────────

CLUSTER_SECURITY_RULES = [
    TomcatRule(
        rule_id="tomcat.cluster-multicast-no-auth",
        description="Tomcat 集群组播通信未加密/未认证",
        severity="HIGH",
        confidence=0.75,
        code_pattern=r"<Cluster(?!.*className=\"org\.apache\.catalina\.tribes\.group\.interceptors\.EncryptInterceptor\")",
        category="CLUSTER_SECURITY",
        cwe="CWE-319",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    TomcatRule(
        rule_id="tomcat.cluster-tcp-listener-open",
        description="Tomcat 集群 TCP 监听端口未做访问限制",
        severity="MEDIUM",
        confidence=0.65,
        code_pattern=r"<Receiver\s+className=\"org\.apache\.catalina\.tribes\.transport\.bio\.BioReceiver\"(?!.*address=\"127)",
        category="CLUSTER_SECURITY",
        cwe="CWE-284",
        owasp="A01:2021 - Broken Access Control",
    ),
    TomcatRule(
        rule_id="tomcat.session-replication-unencrypted",
        description="Tomcat Session 复制未加密传输",
        severity="HIGH",
        confidence=0.7,
        code_pattern=r"<Manager\s+className=\"org\.apache\.catalina\.ha\.session\.DeltaManager\"(?!.*expireSessionsOnShutdown)",
        category="CLUSTER_SECURITY",
        cwe="CWE-319",
        owasp="A02:2021 - Cryptographic Failures",
    ),
    TomcatRule(
        rule_id="tomcat.cluster-replication-valve",
        description="Tomcat 集群使用 ReplicationValve 但未过滤敏感请求",
        severity="LOW",
        confidence=0.4,
        code_pattern=r"ReplicationValve",
        category="CLUSTER_SECURITY",
        cwe="CWE-523",
        owasp="A04:2021 - Insecure Design",
    ),
]


# ─────────────────────── 安全守卫模式 ───────────────────────

TOMCAT_SECURITY_GUARD_PATTERNS: Dict[str, List[str]] = {
    "ajp": [
        r"secretRequired",
        r"secret=",
        r"AJP/1.3.*address=\"127",
        r"allowedRequestAttributesPattern",
    ],
    "ssl": [
        r"TLSv1\\.2",
        r"TLSv1\\.3",
        r"ciphers=\".*(?:ECDHE|CHACHA20|AES_256_GCM)",
        r"HSTSFilter",
        r"httpHeaderSecurityFilter",
    ],
    "manager": [
        r"RemoteAddrValve.*allow.*127\\.",
        r"RemoteHostValve",
        r"/manager/html.*deny",
    ],
    "credentials": [
        r"CredentialHandler.*algorithm=\"SHA-512\"",
        r"MessageDigestCredentialHandler",
        r"Salted",
    ],
}


# ─────────────────────── 误报规则 ───────────────────────

TOMCAT_FALSE_POSITIVE_RULES = []


# ─────────────────────── 汇总 ───────────────────────

TOMCAT_SECURITY_RULES: List[TomcatRule] = (
    AJP_GHOSTCAT_RULES
    + DEFAULT_CREDENTIAL_RULES
    + MANAGER_EXPOSURE_RULES
    + SSL_TLS_MISCONFIG_RULES
    + CONNECTOR_MISCONFIG_RULES
    + ERROR_PAGE_RULES
    + DIRECTORY_TRAVERSAL_RULES
    + CLUSTER_SECURITY_RULES
)

TOMCAT_RULES_INDEX: Dict[str, TomcatRule] = {r.rule_id: r for r in TOMCAT_SECURITY_RULES}

TOMCAT_RULES_BY_SEVERITY: Dict[str, List[TomcatRule]] = {
    "CRITICAL": [r for r in TOMCAT_SECURITY_RULES if r.severity == "CRITICAL"],
    "HIGH": [r for r in TOMCAT_SECURITY_RULES if r.severity == "HIGH"],
    "MEDIUM": [r for r in TOMCAT_SECURITY_RULES if r.severity == "MEDIUM"],
    "LOW": [r for r in TOMCAT_SECURITY_RULES if r.severity == "LOW"],
}

TOMCAT_RULE_COUNT: int = len(TOMCAT_SECURITY_RULES)


# 与 SpringBoot 规则互斥：检查是否为 Tomcat 配置
TOMCAT_FILE_PATTERNS = [
    "server.xml",
    "tomcat-users.xml",
    "web.xml",
    "context.xml",
    "catalina.properties",
    "catalina.policy",
    "logging.properties",
]
