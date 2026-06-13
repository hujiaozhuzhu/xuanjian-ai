"""
Java 安全审计规则

针对 Java 代码审计的误报规则集
"""

# Java 常见误报规则
JAVA_FALSE_POSITIVE_RULES = [
    # SQL 注入误报
    {
        "name": "java_sql_prepared_statement",
        "rule_id_pattern": "sql.injection|sql-injection|SQL_INJECTION",
        "code_pattern": r"prepareStatement|createQuery|@Query|@Select|#\{",
        "reason": "使用PreparedStatement或ORM参数化查询",
        "confidence": 0.85,
    },
    {
        "name": "java_sql_mybatis_hash",
        "rule_id_pattern": "sql.injection|sql-injection|SQL_INJECTION",
        "code_pattern": r"#\{[^}]+\}",
        "reason": "MyBatis使用#{}参数绑定，安全",
        "confidence": 0.9,
    },
    {
        "name": "java_sql_constant",
        "rule_id_pattern": "sql.injection|sql-injection|SQL_INJECTION",
        "code_pattern": r'final\s+String\s+\w+\s*=\s*"[^"]*"',
        "reason": "SQL语句为常量，非用户输入",
        "confidence": 0.8,
    },

    # XSS 误报
    {
        "name": "java_xss_escape",
        "rule_id_pattern": "xss|XSS|cross.site",
        "code_pattern": r"htmlEscape|escapeHtml|HtmlUtils|StringEscapeUtils|Jsoup\.clean|Safelist",
        "reason": "使用HTML转义函数",
        "confidence": 0.85,
    },
    {
        "name": "java_xss_json_response",
        "rule_id_pattern": "xss|XSS|cross.site",
        "code_pattern": r"@RestController|produces.*application/json|ResponseEntity",
        "reason": "REST API返回JSON，不直接渲染HTML",
        "confidence": 0.7,
    },

    # SSRF 误报
    {
        "name": "java_ssrf_whitelist",
        "rule_id_pattern": "ssrf|SSRF|url.connection",
        "code_pattern": r"whitelist|allowlist|allowedHosts|isValidUrl|validateUrl",
        "reason": "存在URL白名单验证",
        "confidence": 0.8,
    },

    # 命令注入误报
    {
        "name": "java_cmd_constant",
        "rule_id_pattern": "command.injection|COMMAND_INJECTION|exec",
        "code_pattern": r'Runtime\.getRuntime\(\)\.exec\(\s*"[^"]*"\s*\)',
        "reason": "命令为常量字符串",
        "confidence": 0.85,
    },
    {
        "name": "java_cmd_whitelist",
        "rule_id_pattern": "command.injection|COMMAND_INJECTION|exec",
        "code_pattern": r"allowedCommands|commandWhitelist|isAllowedCommand",
        "reason": "存在命令白名单验证",
        "confidence": 0.8,
    },

    # 路径遍历误报
    {
        "name": "java_path_normalize",
        "rule_id_pattern": "path.traversal|PATH_TRAVERSAL|file.read",
        "code_pattern": r"normalize\(\)|toRealPath\(\)|getCanonicalPath\(\)",
        "reason": "使用路径规范化函数",
        "confidence": 0.75,
    },

    # 反序列化误报
    {
        "name": "java_deser_filter",
        "rule_id_pattern": "deserialization|DESERIALIZATION|object.input",
        "code_pattern": r"ObjectInputFilter|SerializationFilter|whitelistClasses",
        "reason": "使用ObjectInputFilter过滤",
        "confidence": 0.8,
    },

    # 硬编码密码误报（测试文件）
    {
        "name": "java_hardcoded_test",
        "rule_id_pattern": "hardcoded.password|hardcoded.secret|HARDCODED",
        "file_pattern": r".*(?:test|Test|tests|Tests|example|Example).*",
        "reason": "测试/示例文件中的硬编码凭证",
        "confidence": 0.9,
    },

    # 弱加密误报（TLS配置）
    {
        "name": "java_weak_crypto_tls13",
        "rule_id_pattern": "weak.crypto|WEAK_CRYPTO|insecure.ssl",
        "code_pattern": r"TLSv1\.3|TLS_1_3|SSLContext\.getInstance.*TLSv1\.3",
        "reason": "使用TLS 1.3，安全",
        "confidence": 0.85,
    },
]

# Java 安全守卫检测模式
JAVA_SECURITY_GUARD_PATTERNS = {
    "sql_injection": [
        r"PreparedStatement",
        r"prepareStatement",
        r"createQuery",
        r"@\s*Query",
        r"JpaRepository",
        r"CrudRepository",
        r"#\{",
        r"setParameter",
        r"bindValue",
    ],
    "xss": [
        r"htmlEscape",
        r"escapeHtml",
        r"HtmlUtils",
        r"StringEscapeUtils",
        r"Jsoup\.clean",
        r"Safelist",
        r"Whitelist",
    ],
    "ssrf": [
        r"UriComponentsBuilder",
        r"URLEncoder\.encode",
        r"whitelist",
        r"allowlist",
        r"isValidUrl",
    ],
    "command_injection": [
        r"ProcessBuilder",
        r"allowedCommands",
        r"commandWhitelist",
    ],
    "path_traversal": [
        r"normalize",
        r"toRealPath",
        r"getCanonicalPath",
        r"Path\.of.*normalize",
    ],
}
