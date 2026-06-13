"""
Java 安全审计规则

针对 Java 代码审计的误报规则集
"""

# Java 常见误报规则
JAVA_FALSE_POSITIVE_RULES = [
    # ================================================================
    # SQL 注入误报规则（15条）
    # ================================================================
    {
        "name": "java_sql_prepared_statement",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "code_pattern": r"prepareStatement|PreparedStatement",
        "reason": "使用PreparedStatement参数化查询，非拼接SQL",
        "confidence": 0.9,
    },
    {
        "name": "java_sql_mybatis_hash",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "code_pattern": r"#\{[^}]+\}",
        "reason": "MyBatis使用#{}参数绑定，安全",
        "confidence": 0.9,
    },
    {
        "name": "java_sql_jpa_parameterized",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "code_pattern": r"createQuery|@Query|setParameter|setParam|TypedQuery|CriteriaBuilder|CriteriaQuery",
        "reason": "JPA/Hibernate使用参数化查询",
        "confidence": 0.85,
    },
    {
        "name": "java_sql_spring_jdbcTemplate",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "code_pattern": r"JdbcTemplate|jdbcTemplate\.query|jdbcTemplate\.update|jdbcTemplate\.execute",
        "reason": "Spring JdbcTemplate内部使用PreparedStatement",
        "confidence": 0.85,
    },
    {
        "name": "java_sql_constant",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "code_pattern": r'final\s+String\s+\w+\s*=\s*"[^"]*"',
        "reason": "SQL语句为常量，非用户输入",
        "confidence": 0.8,
    },
    {
        "name": "java_sql_test_code",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "file_pattern": r".*(?:test|Test|tests|Tests|mock|Mock|spec|Spec).*\.(?:java|kt)$",
        "reason": "测试代码中的SQL，非生产风险",
        "confidence": 0.85,
    },
    {
        "name": "java_sql_input_validation",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "code_pattern": r"(?:isValid|validate|sanitize|checkInput|InputValidator|Pattern\.matches|matches\(\s*\"[^\"]*\"\s*\))",
        "reason": "SQL拼接前有输入校验/清洗",
        "confidence": 0.7,
    },
    {
        "name": "java_sql_named_parameter_jdbc",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "code_pattern": r"NamedParameterJdbcTemplate|SqlParameterSource|MapSqlParameterSource|BeanPropertySqlParameterSource",
        "reason": "使用NamedParameterJdbcTemplate参数化查询",
        "confidence": 0.9,
    },
    {
        "name": "java_sql_criteria_api",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "code_pattern": r"CriteriaBuilder|CriteriaQuery|Root\b|Predicate\b|cq\.where|cb\.equal|cb\.like",
        "reason": "使用JPA Criteria API类型安全查询",
        "confidence": 0.9,
    },
    {
        "name": "java_sql_mybatis_plus_lambda",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "code_pattern": r"LambdaQueryWrapper|Wrappers\.lambdaQuery|QueryWrapper|LambdaUpdateWrapper",
        "reason": "MyBatis-Plus LambdaQueryWrapper类型安全查询",
        "confidence": 0.9,
    },
    {
        "name": "java_sql_jooq",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "code_pattern": r"DSL\.|DSLContext|org\.jooq\.|selectFrom|fetchInto|\.from\(|\.where\(",
        "reason": "JOOQ类型安全SQL构建器，参数自动绑定",
        "confidence": 0.9,
    },
    {
        "name": "java_sql_flyway_liquibase",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "file_pattern": r".*(?:flyway|liquibase|migration|db/migration|changelog).*",
        "reason": "Flyway/Liquibase数据库迁移脚本，非动态SQL",
        "confidence": 0.9,
    },
    {
        "name": "java_sql_hql_jpql",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "code_pattern": r"createQuery\s*\(\s*\".*:\w+|createQuery\s*\(\s*\".*\?.*\"|setString|setInteger|setParameter",
        "reason": "HQL/JPQL参数化查询",
        "confidence": 0.85,
    },
    {
        "name": "java_sql_r2dbc",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "code_pattern": r"DatabaseClient|R2dbcEntityTemplate|bind\(|bindNull|\.sql\(|execute\(\)",
        "reason": "R2DBC响应式参数化查询",
        "confidence": 0.85,
    },
    {
        "name": "java_sql_repository_pattern",
        "rule_id_pattern": r"sql.injection|sql-injection|SQL_INJECTION|sql-inject",
        "code_pattern": r"CrudRepository|JpaRepository|PagingAndSortingRepository|findBy|@Modifying|@NamedQuery",
        "reason": "Spring Data Repository模式自动参数化",
        "confidence": 0.9,
    },

    # ================================================================
    # XSS 误报规则（10条）
    # ================================================================
    {
        "name": "java_xss_escape",
        "rule_id_pattern": r"xss|XSS|cross.site|reflected.xss|stored.xss",
        "code_pattern": r"htmlEscape|escapeHtml|HtmlUtils|StringEscapeUtils|Jsoup\.clean|Safelist|OWASP\.Java\.Encoder",
        "reason": "使用HTML转义函数",
        "confidence": 0.85,
    },
    {
        "name": "java_xss_json_response",
        "rule_id_pattern": r"xss|XSS|cross.site|reflected.xss|stored.xss",
        "code_pattern": r"@RestController|produces.*application/json|ResponseEntity.*json|@ResponseBody",
        "reason": "REST API返回JSON，不直接渲染HTML",
        "confidence": 0.7,
    },
    {
        "name": "java_xss_template_auto_escape",
        "rule_id_pattern": r"xss|XSS|cross.site|reflected.xss|stored.xss",
        "code_pattern": r"th:|th:text|th:utext|c:out|<c:out|escapeXml|<%@\s*page.*isELIgnored|thymeleaf",
        "reason": "模板引擎自动转义输出（Thymeleaf/JSP c:out）",
        "confidence": 0.85,
    },
    {
        "name": "java_xss_log_output",
        "rule_id_pattern": r"xss|XSS|cross.site|reflected.xss|stored.xss",
        "code_pattern": r"log\.(?:info|debug|warn|error|trace)|Logger|LoggerFactory|logger\.|LOG\.|SLF4J",
        "reason": "日志输出而非页面输出，不构成XSS",
        "confidence": 0.8,
    },
    {
        "name": "java_xss_constant_string",
        "rule_id_pattern": r"xss|XSS|cross.site|reflected.xss|stored.xss",
        "code_pattern": r'<(?:div|span|p|a|img|h[1-6]|table|ul|ol|li|section|article)\b[^>]*>\s*(?:"[^"]*"|\s)*</(?:div|span|p|a|img|h[1-6]|table|ul|ol|li|section|article)>',
        "reason": "常量HTML字符串，不含动态用户输入",
        "confidence": 0.75,
    },
    {
        "name": "java_xss_csp_header",
        "rule_id_pattern": r"xss|XSS|cross.site|reflected.xss|stored.xss",
        "code_pattern": r"Content-Security-Policy|addHeader.*CSP|ContentSecurityPolicy|@CSP|CSP_HEADER",
        "reason": "已设置CSP头防护XSS",
        "confidence": 0.7,
    },
    {
        "name": "java_xss_owasp_encoder",
        "rule_id_pattern": r"xss|XSS|cross.site|reflected.xss|stored.xss",
        "code_pattern": r"Encode\.forHtml|Encode\.forUri|Encoder\.forHtml|org\.owasp\.encoder|ESAPI\.encoder",
        "reason": "使用OWASP Java Encoder进行输出编码",
        "confidence": 0.9,
    },
    {
        "name": "java_xss_spring_html_utils",
        "rule_id_pattern": r"xss|XSS|cross.site|reflected.xss|stored.xss",
        "code_pattern": r"HtmlUtils\.htmlEscape|HtmlUtils\.htmlEscapeDecimal|HtmlUtils\.htmlEscapeHex|Spring\.htmlEscape",
        "reason": "使用Spring HtmlUtils转义",
        "confidence": 0.9,
    },
    {
        "name": "java_xss_freemarker_autoescape",
        "rule_id_pattern": r"xss|XSS|cross.site|reflected.xss|stored.xss",
        "code_pattern": r"auto_esc|autoEscaping|freemarker.*escape|<#escape|<#autoesc|output_format.*HTML",
        "reason": "Freemarker自动转义配置",
        "confidence": 0.85,
    },
    {
        "name": "java_xss_safe_attribute",
        "rule_id_pattern": r"xss|XSS|cross.site|reflected.xss|stored.xss",
        "code_pattern": r"textContent|innerText|createTextNode|setAttribute\(|\.style\b|\.className\b",
        "reason": "使用安全HTML属性赋值（textContent而非innerHTML）",
        "confidence": 0.7,
    },

    # ================================================================
    # SSRF 误报规则（10条）
    # ================================================================
    {
        "name": "java_ssrf_constant_url",
        "rule_id_pattern": r"ssrf|SSRF|url.connection|url.fetch|http.request",
        "code_pattern": r'(?:https?://)[\w.-]+\.(?:com|org|net|io|cn|gov|edu)',
        "reason": "URL为常量字符串，非用户可控",
        "confidence": 0.8,
    },
    {
        "name": "java_ssrf_whitelist",
        "rule_id_pattern": r"ssrf|SSRF|url.connection|url.fetch|http.request",
        "code_pattern": r"whitelist|allowlist|allowedHosts|isValidUrl|validateUrl|AllowedUrls|urlValidator",
        "reason": "存在URL白名单验证",
        "confidence": 0.8,
    },
    {
        "name": "java_ssrf_internal_check",
        "rule_id_pattern": r"ssrf|SSRF|url.connection|url.fetch|http.request",
        "code_pattern": r"isLoopback|isSiteLocalAddress|isAnyLocal|127\.0\.0\.1|10\.|172\.(?:1[6-9]|2|3[01])\.|192\.168\.|internalHostCheck|denyInternal|blockPrivate",
        "reason": "禁止内网地址检查",
        "confidence": 0.85,
    },
    {
        "name": "java_ssrf_uri_components_builder",
        "rule_id_pattern": r"ssrf|SSRF|url.connection|url.fetch|http.request",
        "code_pattern": r"UriComponentsBuilder|UriComponents\.build|encode\(\)|fromUriString|fromHttpUrl",
        "reason": "使用UriComponentsBuilder安全构建URL",
        "confidence": 0.8,
    },
    {
        "name": "java_ssrf_url_validator",
        "rule_id_pattern": r"ssrf|SSRF|url.connection|url.fetch|http.request",
        "code_pattern": r"UrlValidator|URLValidator|isValid\(\s*new\s+URL|InetAddress\.getByName|getAddress",
        "reason": "使用URL验证器进行校验",
        "confidence": 0.8,
    },
    {
        "name": "java_ssrf_test_code",
        "rule_id_pattern": r"ssrf|SSRF|url.connection|url.fetch|http.request",
        "file_pattern": r".*(?:test|Test|tests|Tests|mock|Mock|spec|Spec).*\.(?:java|kt)$",
        "reason": "测试代码中的URL请求，非生产风险",
        "confidence": 0.85,
    },
    {
        "name": "java_ssrf_config_url",
        "rule_id_pattern": r"ssrf|SSRF|url.connection|url.fetch|http.request",
        "code_pattern": r"@\s*Value|@ConfigurationProperties|@PropertySource|application\.(?:yml|properties)|Environment\.getProperty",
        "reason": "URL来自配置文件，非用户直接输入",
        "confidence": 0.75,
    },
    {
        "name": "java_ssrf_rest_template",
        "rule_id_pattern": r"ssrf|SSRF|url.connection|url.fetch|http.request",
        "code_pattern": r"RestTemplate|restTemplate\.|exchange\(|getForObject|getForEntity|postForObject",
        "reason": "使用RestTemplate，通常配合固定base URL",
        "confidence": 0.6,
    },
    {
        "name": "java_ssrf_web_client",
        "rule_id_pattern": r"ssrf|SSRF|url.connection|url.fetch|http.request",
        "code_pattern": r"WebClient\.builder|WebClient\.create|\.uri\(|\.retrieve\(|\.exchange\(",
        "reason": "使用WebClient，通常配合已知host",
        "confidence": 0.6,
    },
    {
        "name": "java_ssrf_feign_client",
        "rule_id_pattern": r"ssrf|SSRF|url.connection|url.fetch|http.request",
        "code_pattern": r"@FeignClient|FeignClient|@RequestLine|Feign\.builder",
        "reason": "使用FeignClient，URL由服务发现或注解定义",
        "confidence": 0.85,
    },

    # ================================================================
    # 命令注入误报规则（8条）
    # ================================================================
    {
        "name": "java_cmd_constant",
        "rule_id_pattern": r"command.injection|COMMAND_INJECTION|exec|os.command|cmd.exec",
        "code_pattern": r'Runtime\.getRuntime\(\)\.exec\(\s*"[^"]*"\s*|ProcessBuilder\(\s*(?:List\.of|Arrays\.asList)\s*\(\s*"[^"]*"',
        "reason": "命令为常量字符串，非用户输入",
        "confidence": 0.85,
    },
    {
        "name": "java_cmd_process_builder_array",
        "rule_id_pattern": r"command.injection|COMMAND_INJECTION|exec|os.command|cmd.exec",
        "code_pattern": r"new\s+ProcessBuilder\s*\(\s*(?:List\.of|Arrays\.asList|new\s+String\s*\[)|ProcessBuilder\(\s*\w+\s*\)",
        "reason": "ProcessBuilder使用参数数组而非字符串拼接",
        "confidence": 0.8,
    },
    {
        "name": "java_cmd_runtime_exec_array",
        "rule_id_pattern": r"command.injection|COMMAND_INJECTION|exec|os.command|cmd.exec",
        "code_pattern": r"Runtime\.getRuntime\(\)\.exec\(\s*(?:new\s+String|String\[\]|List\.of|Arrays\.asList|\w+\s*,\s*(?:new\s+)?String)",
        "reason": "Runtime.exec使用参数数组",
        "confidence": 0.8,
    },
    {
        "name": "java_cmd_test_code",
        "rule_id_pattern": r"command.injection|COMMAND_INJECTION|exec|os.command|cmd.exec",
        "file_pattern": r".*(?:test|Test|tests|Tests|mock|Mock|spec|Spec).*\.(?:java|kt)$",
        "reason": "测试代码中的命令执行，非生产风险",
        "confidence": 0.85,
    },
    {
        "name": "java_cmd_allowlist",
        "rule_id_pattern": r"command.injection|COMMAND_INJECTION|exec|os.command|cmd.exec",
        "code_pattern": r"allowedCommands|commandWhitelist|isAllowedCommand|COMMAND_ALLOWLIST|commandAllowlist|ALLOWED_COMMANDS",
        "reason": "存在命令白名单验证",
        "confidence": 0.8,
    },
    {
        "name": "java_cmd_enum_whitelist",
        "rule_id_pattern": r"command.injection|COMMAND_INJECTION|exec|os.command|cmd.exec",
        "code_pattern": r"enum\s+\w*(?:Command|CMD|Op|Operation)\b|CommandEnum\.|CommandType\.",
        "reason": "使用白名单命令枚举类型",
        "confidence": 0.8,
    },
    {
        "name": "java_cmd_spring_shell",
        "rule_id_pattern": r"command.injection|COMMAND_INJECTION|exec|os.command|cmd.exec",
        "code_pattern": r"@ShellComponent|@ShellMethod|@Command|SpringShell|CommandLineRunner|picocli",
        "reason": "Spring Shell/Picocli框架命令处理",
        "confidence": 0.85,
    },
    {
        "name": "java_cmd_commons_exec",
        "rule_id_pattern": r"command.injection|COMMAND_INJECTION|exec|os.command|cmd.exec",
        "code_pattern": r"CommandLine\.parse|DefaultExecutor|org\.apache\.commons\.exec|ExecuteWatchdog|PumpStreamHandler",
        "reason": "使用Commons Exec库，参数安全处理",
        "confidence": 0.8,
    },

    # ================================================================
    # 路径穿越误报规则（7条）
    # ================================================================
    {
        "name": "java_path_canonical",
        "rule_id_pattern": r"path.traversal|PATH_TRAVERSAL|file.read|file.access|path.travers",
        "code_pattern": r"getCanonicalPath|canonicalPath|File\([^)]*\)\.getCanonicalPath",
        "reason": "使用canonicalPath规范化并可校验路径",
        "confidence": 0.75,
    },
    {
        "name": "java_path_normalize",
        "rule_id_pattern": r"path.traversal|PATH_TRAVERSAL|file.read|file.access|path.travers",
        "code_pattern": r"normalize\(\)|toRealPath\(\)|\.normalize\(\)",
        "reason": "使用normalize()消除路径中的..和.",
        "confidence": 0.75,
    },
    {
        "name": "java_path_of_normalize",
        "rule_id_pattern": r"path.traversal|PATH_TRAVERSAL|file.read|file.access|path.travers",
        "code_pattern": r"Path\.of\(.*\)\.normalize|Paths\.get\(.*\)\.normalize|Path\.resolve\(.*\)\.normalize",
        "reason": "使用Path.of().normalize()规范化路径",
        "confidence": 0.8,
    },
    {
        "name": "java_path_filename_utils",
        "rule_id_pattern": r"path.traversal|PATH_TRAVERSAL|file.read|file.access|path.travers",
        "code_pattern": r"FilenameUtils\.getName|FilenameUtils\.getBaseName|FilenameUtils\.normalize",
        "reason": "使用FilenameUtils.getName()提取文件名，去除路径组件",
        "confidence": 0.85,
    },
    {
        "name": "java_path_constant",
        "rule_id_pattern": r"path.traversal|PATH_TRAVERSAL|file.read|file.access|path.travers",
        "code_pattern": r'(?:new\s+)?File\(\s*"[^"]*(?:/|\\\\)[^"]*"\s*\)|Path\.of\(\s*"[^"]*"\s*\)|Paths\.get\(\s*"[^"]*"',
        "reason": "文件路径为常量字符串",
        "confidence": 0.8,
    },
    {
        "name": "java_path_test_code",
        "rule_id_pattern": r"path.traversal|PATH_TRAVERSAL|file.read|file.access|path.travers",
        "file_pattern": r".*(?:test|Test|tests|Tests|mock|Mock|spec|Spec).*\.(?:java|kt)$",
        "reason": "测试代码中的文件路径，非生产风险",
        "confidence": 0.85,
    },
    {
        "name": "java_path_resource_loader",
        "rule_id_pattern": r"path.traversal|PATH_TRAVERSAL|file.read|file.access|path.travers",
        "code_pattern": r"ResourceLoader|ClassPathResource|ResourceUtils|getResource|classpath:|Resource\(\s*\"classpath:",
        "reason": "使用Spring ResourceLoader加载classpath资源",
        "confidence": 0.8,
    },

    # ================================================================
    # 反序列化误报规则（5条）
    # ================================================================
    {
        "name": "java_deser_filter",
        "rule_id_pattern": r"deserialization|DESERIALIZATION|object.input|unsafe.deserialization|deserializ",
        "code_pattern": r"ObjectInputFilter|SerializationFilter|whitelistClasses|setObjectInputFilter|Config\.setObjectInputFilter",
        "reason": "使用ObjectInputFilter白名单过滤",
        "confidence": 0.85,
    },
    {
        "name": "java_deser_trusted_source",
        "rule_id_pattern": r"deserialization|DESERIALIZATION|object.input|unsafe.deserialization|deserializ",
        "code_pattern": r"CacheManager|SessionManager|InternalCache|ClusterMessage|@Cacheable|RedisTemplate|session\.getAttribute",
        "reason": "反序列化数据来源为内部可信存储（缓存/Session/集群通信）",
        "confidence": 0.7,
    },
    {
        "name": "java_deser_test_code",
        "rule_id_pattern": r"deserialization|DESERIALIZATION|object.input|unsafe.deserialization|deserializ",
        "file_pattern": r".*(?:test|Test|tests|Tests|mock|Mock|spec|Spec).*\.(?:java|kt)$",
        "reason": "测试代码中的反序列化操作",
        "confidence": 0.85,
    },
    {
        "name": "java_deser_safe_input_stream",
        "rule_id_pattern": r"deserialization|DESERIALIZATION|object.input|unsafe.deserialization|deserializ",
        "code_pattern": r"SafeObjectInputStream|ValidatingObjectInputStream|ValidObjectInputStream|NotASerializedObject",
        "reason": "使用安全ObjectInputStream包装类",
        "confidence": 0.85,
    },
    {
        "name": "java_deser_jackson",
        "rule_id_pattern": r"deserialization|DESERIALIZATION|object.input|unsafe.deserialization|deserializ",
        "code_pattern": r"ObjectMapper|readValue|readTree|JsonParser|TypeReference|@JsonDeserialize|convertValue",
        "reason": "使用Jackson JSON库，默认不支持任意类反序列化",
        "confidence": 0.7,
    },

    # ================================================================
    # 加密误报规则（5条）
    # ================================================================
    {
        "name": "java_crypto_aes256",
        "rule_id_pattern": r"weak.crypto|WEAK_CRYPTO|insecure.crypto|weak.cipher|weak.encrypt|hardcoded.password|hardcoded.secret",
        "code_pattern": r"AES/.*256|AES_256|Cipher\.getInstance.*AES|AES/GCM|AES/CBC.*PKCS5",
        "reason": "使用AES-256加密算法",
        "confidence": 0.85,
    },
    {
        "name": "java_crypto_bcrypt_pbkdf2",
        "rule_id_pattern": r"weak.crypto|WEAK_CRYPTO|insecure.crypto|weak.cipher|weak.encrypt|hardcoded.password",
        "code_pattern": r"BCrypt|BCryptPasswordEncoder|PBKDF2|PBEKeySpec|SCrypt|SCryptPasswordEncoder|Argon2|MessageDigest\.getInstance.*SHA-256|SHA-512",
        "reason": "使用BCrypt/PBKDF2/SCrypt安全哈希算法",
        "confidence": 0.9,
    },
    {
        "name": "java_crypto_secure_random",
        "rule_id_pattern": r"weak.crypto|WEAK_CRYPTO|insecure.crypto|insecure.random|weak.random",
        "code_pattern": r"SecureRandom|java\.security\.SecureRandom|new SecureRandom",
        "reason": "使用SecureRandom安全随机数生成器",
        "confidence": 0.9,
    },
    {
        "name": "java_crypto_https",
        "rule_id_pattern": r"weak.crypto|WEAK_CRYPTO|insecure.ssl|insecure.http|cleartext",
        "code_pattern": r'https://|HttpClient.*https|HttpsURLConnection|SSLContext\.getInstance|TrustManager',
        "reason": "使用HTTPS协议或TLS配置",
        "confidence": 0.8,
    },
    {
        "name": "java_crypto_jca_provider",
        "rule_id_pattern": r"weak.crypto|WEAK_CRYPTO|insecure.crypto|weak.cipher|weak.encrypt",
        "code_pattern": r"KeyGenerator\.getInstance|KeyPairGenerator\.getInstance|Signature\.getInstance|Cipher\.getInstance|Mac\.getInstance|MessageDigest\.getInstance",
        "reason": "使用JCA标准Provider获取加密实例",
        "confidence": 0.7,
    },

    # ================================================================
    # 其他通用误报规则
    # ================================================================
    {
        "name": "java_hardcoded_test",
        "rule_id_pattern": r"hardcoded.password|hardcoded.secret|HARDCODED|hardcoded",
        "file_pattern": r".*(?:test|Test|tests|Tests|example|Example|demo|Demo|mock|Mock).*\.(?:java|kt)$",
        "reason": "测试/示例文件中的硬编码凭证",
        "confidence": 0.9,
    },
    {
        "name": "java_hardcoded_const",
        "rule_id_pattern": r"hardcoded.password|hardcoded.secret|HARDCODED|hardcoded",
        "code_pattern": r"(?:static\s+final|final\s+static|private\s+static\s+final)\s+String\s+\w+\s*=",
        "reason": "常量定义中可能包含配置值，需结合上下文判断",
        "confidence": 0.5,
    },
    {
        "name": "java_weak_crypto_tls13",
        "rule_id_pattern": r"weak.crypto|WEAK_CRYPTO|insecure.ssl",
        "code_pattern": r"TLSv1\.3|TLS_1_3|SSLContext\.getInstance.*TLSv1\.3",
        "reason": "使用TLS 1.3，安全",
        "confidence": 0.9,
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
        r"NamedParameterJdbcTemplate",
        r"JdbcTemplate",
        r"CriteriaBuilder",
        r"CriteriaQuery",
        r"LambdaQueryWrapper",
        r"R2dbcEntityTemplate",
        r"DatabaseClient",
        r"DSLContext",
    ],
    "xss": [
        r"htmlEscape",
        r"escapeHtml",
        r"HtmlUtils",
        r"StringEscapeUtils",
        r"Jsoup\.clean",
        r"Safelist",
        r"Whitelist",
        r"Encode\.forHtml",
        r"Encoder\.forHtml",
        r"@RestController",
        r"ResponseBody",
        r"c:out",
        r"th:text",
    ],
    "ssrf": [
        r"UriComponentsBuilder",
        r"URLEncoder\.encode",
        r"whitelist",
        r"allowlist",
        r"isValidUrl",
        r"UrlValidator",
        r"@FeignClient",
        r"isLoopback",
        r"isSiteLocalAddress",
        r"blockPrivate",
    ],
    "command_injection": [
        r"ProcessBuilder",
        r"allowedCommands",
        r"commandWhitelist",
        r"isAllowedCommand",
        r"@ShellComponent",
        r"@ShellMethod",
        r"CommandLine\.parse",
        r"DefaultExecutor",
        r"CommandEnum",
    ],
    "path_traversal": [
        r"normalize",
        r"toRealPath",
        r"getCanonicalPath",
        r"Path\.of.*normalize",
        r"FilenameUtils\.getName",
        r"ClassPathResource",
        r"ResourceLoader",
        r"ResourceUtils",
    ],
    "deserialization": [
        r"ObjectInputFilter",
        r"SerializationFilter",
        r"whitelistClasses",
        r"SafeObjectInputStream",
        r"ValidatingObjectInputStream",
        r"setObjectInputFilter",
    ],
    "security_guard": [
        # Spring Security 注解
        r"@PreAuthorize",
        r"@PostAuthorize",
        r"@Secured",
        r"@RolesAllowed",
        r"SecurityContext",
        r"AuthenticationManager",
        r"WebSecurityConfigurerAdapter",
        r"HttpSecurity",
        r"SecurityFilterChain",
        # Shiro 权限注解
        r"@RequiresPermissions",
        r"@RequiresRoles",
        r"@RequiresAuthentication",
        r"@RequiresUser",
        r"ShiroFilterFactoryBean",
        r"SecurityManager",
        r"Subject\.checkPermission",
        # 自定义权限检查
        r"hasPermission",
        r"checkPermission",
        r"authorize\(",
        r"isAuthorized",
        r"checkAccess",
        r"PermissionEvaluator",
        r"AccessDecisionVoter",
        # IP白名单
        r"ipWhitelist",
        r"ipAllowlist",
        r"allowedIps",
        r"IpFilter",
        r"clientIp.*whitelist",
        r"InetAddress\.isReachable",
        # Token验证
        r"JWT|JwtToken|JwtUtil|JwtProvider|JwtFilter",
        r"verifyToken|validateToken|parseToken|decodeToken",
        r"Bearer\s|Authorization",
        r"OAuth2|OAuthToken|AccessToken",
        # Rate limiting
        r"RateLimiter|RateLimit|@RateLimit",
        r"Bucket4j|Guava.*RateLimiter",
        r"Semaphore|Throttling|throttle",
        # CSRF
        r"csrf|CsrfToken|@EnableCsrf|CsrfFilter",
        r"_csrf|csrfProtection|csrf().disable",
    ],
}
