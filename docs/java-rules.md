# Java 误报规则

本文档详细描述玄鉴内置的 Java 误报规则集，以及如何添加自定义规则。

## 规则概述

玄鉴的 Java 误报规则分为两类：

1. **L1 规则过滤规则** — 基于正则匹配的快速过滤
2. **L2 安全守卫模式** — 基于上下文的深度分析

两类规则协同工作，L1 负责快速筛选，L2 负责上下文验证。

## L1 内置误报规则完整列表

### SQL 注入类

#### 1. `java_sql_prepared_statement`

| 属性 | 值 |
|------|-----|
| 匹配规则ID | `sql.injection\|sql-injection\|SQL_INJECTION` |
| 匹配代码 | `prepareStatement\|createQuery\|@Query\|@Select\|#{` |
| 原因 | 使用 PreparedStatement 或 ORM 参数化查询 |
| 置信度 | 0.85 |

**说明**：当代码中出现 `PreparedStatement`、JPA `createQuery`、Spring `@Query` 注解或 MyBatis `#{` 参数绑定时，SQL 注入风险极低。

#### 2. `java_sql_mybatis_hash`

| 属性 | 值 |
|------|-----|
| 匹配规则ID | `sql.injection\|sql-injection\|SQL_INJECTION` |
| 匹配代码 | `#[^}]+}` (MyBatis `#{}` 语法) |
| 原因 | MyBatis 使用 `#{}` 参数绑定，安全 |
| 置信度 | 0.9 |

**说明**：MyBatis 的 `#{}` 会自动进行参数化处理，等价于 PreparedStatement。注意区分 `${}` （字符串替换，不安全）。

#### 3. `java_sql_constant`

| 属性 | 值 |
|------|-----|
| 匹配规则ID | `sql.injection\|sql-injection\|SQL_INJECTION` |
| 匹配代码 | `final\s+String\s+\w+\s*=\s*"[^"]*"` |
| 原因 | SQL 语句为常量，非用户输入 |
| 置信度 | 0.8 |

**说明**：当 SQL 语句被声明为 `final String` 常量时，不存在用户输入拼接的可能。

### XSS 类

#### 4. `java_xss_escape`

| 属性 | 值 |
|------|-----|
| 匹配规则ID | `xss\|XSS\|cross.site` |
| 匹配代码 | `htmlEscape\|escapeHtml\|HtmlUtils\|StringEscapeUtils\|Jsoup\.clean\|Safelist` |
| 原因 | 使用 HTML 转义函数 |
| 置信度 | 0.85 |

**说明**：检测到常见的 HTML 转义函数调用，说明开发者已对输出进行了安全处理。

#### 5. `java_xss_json_response`

| 属性 | 值 |
|------|-----|
| 匹配规则ID | `xss\|XSS\|cross.site` |
| 匹配代码 | `@RestController\|produces.*application/json\|ResponseEntity` |
| 原因 | REST API 返回 JSON，不直接渲染 HTML |
| 置信度 | 0.7 |

**说明**：纯 JSON 响应的 REST API 不会触发浏览器 HTML 渲染，XSS 风险极低。

### SSRF 类

#### 6. `java_ssrf_whitelist`

| 属性 | 值 |
|------|-----|
| 匹配规则ID | `ssrf\|SSRF\|url.connection` |
| 匹配代码 | `whitelist\|allowlist\|allowedHosts\|isValidUrl\|validateUrl` |
| 原因 | 存在 URL 白名单验证 |
| 置信度 | 0.8 |

**说明**：当代码中存在 URL 白名单或验证逻辑时，SSRF 攻击面大幅缩小。

### 命令注入类

#### 7. `java_cmd_constant`

| 属性 | 值 |
|------|-----|
| 匹配规则ID | `command.injection\|COMMAND_INJECTION\|exec` |
| 匹配代码 | `Runtime\.getRuntime\(\)\.exec\(\s*"[^"]*"\s*\)` |
| 原因 | 命令为常量字符串 |
| 置信度 | 0.85 |

**说明**：`Runtime.exec()` 传入常量字符串时，不存在命令注入风险。

#### 8. `java_cmd_whitelist`

| 属性 | 值 |
|------|-----|
| 匹配规则ID | `command.injection\|COMMAND_INJECTION\|exec` |
| 匹配代码 | `allowedCommands\|commandWhitelist\|isAllowedCommand` |
| 原因 | 存在命令白名单验证 |
| 置信度 | 0.8 |

### 路径穿越类

#### 9. `java_path_normalize`

| 属性 | 值 |
|------|-----|
| 匹配规则ID | `path.traversal\|PATH_TRAVERSAL\|file.read` |
| 匹配代码 | `normalize()\|toRealPath()\|getCanonicalPath()` |
| 原因 | 使用路径规范化函数 |
| 置信度 | 0.75 |

**说明**：路径规范化可以消除 `../` 等穿越序列。建议配合 `startsWith` 基目录检查。

### 反序列化类

#### 10. `java_deser_filter`

| 属性 | 值 |
|------|-----|
| 匹配规则ID | `deserialization\|DESERIALIZATION\|object.input` |
| 匹配代码 | `ObjectInputFilter\|SerializationFilter\|whitelistClasses` |
| 原因 | 使用 ObjectInputFilter 过滤 |
| 置信度 | 0.8 |

**说明**：Java 9+ 的 `ObjectInputFilter` 可以限制可反序列化的类，有效防御反序列化攻击。

### 硬编码凭证类

#### 11. `java_hardcoded_test`

| 属性 | 值 |
|------|-----|
| 匹配规则ID | `hardcoded.password\|hardcoded.secret\|HARDCODED` |
| 匹配文件 | `.*(?:test\|Test\|tests\|Tests\|example\|Example).*` |
| 原因 | 测试/示例文件中的硬编码凭证 |
| 置信度 | 0.9 |

**说明**：测试文件中的硬编码密码通常是测试数据，不构成安全风险。

### 弱加密类

#### 12. `java_weak_crypto_tls13`

| 属性 | 值 |
|------|-----|
| 匹配规则ID | `weak.crypto\|WEAK_CRYPTO\|insecure.ssl` |
| 匹配代码 | `TLSv1\.3\|TLS_1_3\|SSLContext\.getInstance.*TLSv1\.3` |
| 原因 | 使用 TLS 1.3，安全 |
| 置信度 | 0.85 |

## L2 安全守卫检测模式

除了 L1 规则外，L2 上下文过滤器还会检测以下安全守卫模式：

### SQL 注入守卫

```python
JAVA_SECURITY_GUARD_PATTERNS["sql_injection"] = [
    "PreparedStatement", "prepareStatement", "createQuery",
    "createNamedQuery", "CriteriaBuilder", "#{",
    "setParameter", "bindValue", "JpaRepository", "CrudRepository",
]
```

### XSS 守卫

```python
JAVA_SECURITY_GUARD_PATTERNS["xss"] = [
    "htmlEscape", "escapeHtml", "HtmlUtils",
    "StringEscapeUtils", "Jsoup.clean", "Safelist", "Whitelist",
]
```

### SSRF 守卫

```python
JAVA_SECURITY_GUARD_PATTERNS["ssrf"] = [
    "UriComponentsBuilder", "URLEncoder.encode",
    "whitelist", "allowlist", "isValidUrl",
]
```

### 命令注入守卫

```python
JAVA_SECURITY_GUARD_PATTERNS["command_injection"] = [
    "ProcessBuilder", "allowedCommands", "commandWhitelist",
]
```

### 路径穿越守卫

```python
JAVA_SECURITY_GUARD_PATTERNS["path_traversal"] = [
    "normalize", "toRealPath", "getCanonicalPath", "Path.of.*normalize",
]
```

## 如何添加自定义规则

### 方法一：配置文件

在 `xuanjian.yaml` 中添加自定义规则：

```yaml
filters:
  rule_filter:
    enabled: true
    custom_rules:
      - name: "my_sql_safe_wrapper"
        rule_id_pattern: "sql.injection|sql-injection"
        code_pattern: "SafeQuery\\.execute|SqlBuilder\\.build"
        reason: "使用项目自定义的安全查询封装"
        confidence: 0.85

      - name: "my_auth_check"
        rule_id_pattern: "auth.bypass|missing.auth"
        code_pattern: "@RequiresAuth|@PreAuthorize|checkPermission"
        reason: "存在权限校验注解"
        confidence: 0.8

      - name: "ignore_generated_code"
        file_pattern: ".*\\/generated\\/.*|.*\\/gen\\/.*"
        reason: "自动生成的代码"
        confidence: 0.95
```

### 方法二：代码方式

```python
from fp_sentinel.filters import RuleFilter

config = {
    "custom_rules": [
        {
            "name": "my_custom_rule",
            "rule_id_pattern": "sql.injection",
            "code_pattern": "MySafeWrapper\\.query",
            "reason": "使用安全封装",
            "confidence": 0.8,
        }
    ]
}
rule_filter = RuleFilter(config)
```

### 规则字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | str | 推荐 | 规则名称，用于日志和报告 |
| `rule_id` | str/list | 否 | 精确匹配规则ID |
| `rule_id_pattern` | str | 否 | 正则匹配规则ID |
| `file_pattern` | str | 否 | 正则匹配文件路径 |
| `code_pattern` | str | 否 | 正则匹配代码片段 |
| `severity` | str/list | 否 | 匹配严重程度 |
| `tool` | str/list | 否 | 匹配扫描工具 |
| `reason` | str | 推荐 | 误报原因说明 |
| `confidence` | float | 否 | 置信度 0-1，默认 0.8 |

**注意**：当多个字段同时指定时，需要所有条件都满足才会匹配（AND 逻辑）。

### 路径白名单配置

```yaml
filters:
  rule_filter:
    path_whitelist:
      - ".*/test/.*"
      - ".*/generated/.*"
      - ".*/internal/.*"        # 自定义：内部工具代码
      - ".*/scripts/.*"         # 自定义：脚本目录
```

### 代码忽略标记

玄鉴支持以下代码内忽略标记：

| 标记 | 来源 |
|------|------|
| `# nosec` | Bandit |
| `# noqa` | Flake8 |
| `// NOSONAR` | SonarQube |
| `// nosec` | Gosec |
| `@SuppressWarnings` | Java |
| `// spotbugs: ignore` | SpotBugs |
| `// findbugs: ignore` | FindBugs |
| `# fp-sentinel-ignore` | 玄鉴专用 |
| `# auditshield-ignore` | 通用 |

## 规则配置示例

### 完整配置示例

```yaml
filters:
  rule_filter:
    enabled: true

    # 路径白名单
    path_whitelist:
      - ".*/test/.*"
      - ".*/tests/.*"
      - ".*/examples?/.*"
      - ".*/docs?/.*"
      - ".*/generated/.*"
      - ".*/vendor/.*"

    # 代码忽略模式
    code_ignore_patterns:
      - "#\\s*nosec"
      - "//\\s*NOSONAR"
      - "@SuppressWarnings"

    # 自定义规则
    custom_rules:
      # 项目特定的安全封装
      - name: "safe_db_query"
        rule_id_pattern: "sql.injection"
        code_pattern: "DbHelper\\.safeQuery|@SafeQuery"
        reason: "使用项目安全查询封装"
        confidence: 0.9

      # 内部 API 不检查认证
      - name: "internal_api"
        file_pattern: ".*/internal/api/.*"
        rule_id_pattern: "missing.auth"
        reason: "内部 API 通过网络隔离保护"
        confidence: 0.7

  context_filter:
    enabled: true
    false_positive_threshold: 0.5

  ml_filter:
    enabled: true
    confidence_threshold: 0.7
    baseline_path: ".fp_sentinel/baseline.json"
    similarity_threshold: 0.85
```
