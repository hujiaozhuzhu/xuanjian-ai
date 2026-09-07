# 玄鉴合规审计摘要 — app.js

> 生成时间: 2026-09-07 14:50:39 UTC  |  项目路径: C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\js-vuln-app\app.js  |  玄鉴 fp-sentinel v2.5.1

## ① 趋势对比

| 指标 | 本次 | 上次 | 变化 |
|------|------|------|------|
| 总发现数 | 8 | - | 首期基线 |
| CRITICAL | 3 | - | 首期基线 |
| HIGH | 5 | - | 首期基线 |
| MEDIUM | 0 | - | 首期基线 |
| LOW | 0 | - | 首期基线 |

*无历史扫描数据，本次结果记录为首期基线。*

## ② 需关注（按 ROI 排序：高危优先、低成本先修）

| ROI | 严重度 | 漏洞 | 位置 | 修复成本 | 参考 CVE |
|-----|--------|------|------|---------|----------|
| 1 | CRITICAL | eval 代码注入 | app.js:51 | 45min | CVE-2016-5636 |
| 2 | CRITICAL | SQL 注入（字符串拼接） | app.js:93 | 45min | CVE-2012-2122 |
| 3 | CRITICAL | 命令注入 | app.js:71 | 60min | CVE-2014-6271 |
| 4 | HIGH | XSS（未转义输出） | app.js:30 | 30min | CVE-2014-9031 |
| 5 | HIGH | 硬编码密钥 | app.js:20 | 30min | CVE-2018-0114 |
| 6 | HIGH | JWT 弱密钥/弱算法 | app.js:166 | 30min | CVE-2015-9235 |
| 7 | HIGH | 路径遍历 | app.js:139 | 45min | CVE-2020-17519 |
| 8 | HIGH | SSRF | app.js:112 | 60min | CVE-2021-21975 |

## ③ Diff 修复建议

*以下建议仅为 diff 字符串示意，玄鉴不会修改您的源文件。*

#### 1. eval 代码注入 — app.js:51
- 参考案例: CVE-2016-5636
- 预计工时: 45 分钟
- 事故背景: eval(用户输入) 直接等价于 RCE。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\js-vuln-app\app.js
+++ b/suggested-fix
@@ 修复建议 @@
-const result = eval(code);  // 🔴 漏洞
+/* 替换为安全实现 */
+result = ast.literal_eval(code)  # 或 JSON.parse
```

#### 2. SQL 注入（字符串拼接） — app.js:93
- 参考案例: CVE-2012-2122
- 预计工时: 45 分钟
- 事故背景: 拼接 SQL 曾导致大规模拖库（如 Heartland 2008，1.3 亿条记录泄露）。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\js-vuln-app\app.js
+++ b/suggested-fix
@@ 修复建议 @@
-const sql = "SELECT * FROM users WHERE id = " + userId;  // 🔴 漏洞
+/* 替换为安全实现 */
+cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

#### 3. 命令注入 — app.js:71
- 参考案例: CVE-2014-6271
- 预计工时: 60 分钟
- 事故背景: Shellshock（CVE-2014-6271）通过环境变量注入命令，波及数十万台服务器。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\js-vuln-app\app.js
+++ b/suggested-fix
@@ 修复建议 @@
-exec(cmd, (error, stdout, stderr) => {  // 🔴 漏洞
+/* 替换为安全实现 */
+subprocess.run(["ls", user_dir], shell=False)  # 参数数组 + 白名单
```

#### 4. XSS（未转义输出） — app.js:30
- 参考案例: CVE-2014-9031
- 预计工时: 30 分钟
- 事故背景: TweetDeck 2014 XSS 蠕虫令 3.8 万用户转发恶意推文。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\js-vuln-app\app.js
+++ b/suggested-fix
@@ 修复建议 @@
-document.getElementById('output').innerHTML = '${userInput}';
+/* 替换为安全实现 */
+el.textContent = userInput;  // 或 DOMPurify.sanitize(html)
```

#### 5. 硬编码密钥 — app.js:20
- 参考案例: CVE-2018-0114
- 预计工时: 30 分钟
- 事故背景: Uber 2016 年因硬编码 AWS 凭证泄露 5700 万用户数据。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\js-vuln-app\app.js
+++ b/suggested-fix
@@ 修复建议 @@
-const API_KEY = "sk-1234567890abcdef";  // 🔴 漏洞: 硬编码密钥
+/* 替换为安全实现 */
+SECRET_KEY = os.environ["SECRET_KEY"]  # 并轮换已泄露密钥
```

#### 6. JWT 弱密钥/弱算法 — app.js:166
- 参考案例: CVE-2015-9235
- 预计工时: 30 分钟
- 事故背景: CVE-2015-9235：algorithm 混淆允许 none/RS256→HS256 伪造 token。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\js-vuln-app\app.js
+++ b/suggested-fix
@@ 修复建议 @@
-const token = jwt.sign(payload, JWT_SECRET);  // 🔴 漏洞
+/* 替换为安全实现 */
+-const token = jwt.sign(payload, JWT_SECRET);
++const token = jwt.sign(payload, process.env.JWT_SECRET, { algorithm: 'HS256' });
```

#### 7. 路径遍历 — app.js:139
- 参考案例: CVE-2020-17519
- 预计工时: 45 分钟
- 事故背景: Apache Flink CVE-2020-17519 通过 ../ 读取任意文件。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\js-vuln-app\app.js
+++ b/suggested-fix
@@ 修复建议 @@
-const filepath = path.join(__dirname, 'uploads', filename);  // 🔴 漏洞
+/* 替换为安全实现 */
+realpath = os.path.realpath(filepath)
+-    if not realpath.startswith(base):
++    if not realpath.startswith(os.path.realpath(base)):
++        abort(403)
```

#### 8. SSRF — app.js:112
- 参考案例: CVE-2021-21975
- 预计工时: 60 分钟
- 事故背景: vRealize SSRF（CVE-2021-21975）被用于窃取凭证后内网横向。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\js-vuln-app\app.js
+++ b/suggested-fix
@@ 修复建议 @@
-const response = await axios.get(url);  // 🔴 漏洞
+/* 替换为安全实现 */
+-const response = await axios.get(url);
++if (!ALLOWED_HOSTS.some(h => url.startsWith(h))) return res.status(403).end();
++const response = await axios.get(url);
```

## ④ 声明

- 本报告由玄鉴 fp-sentinel 自动生成，仅用于防御性安全审计与合规自查。
- 修复建议以 diff 字符串形式给出，工具承诺不修改任何用户源文件（S2）。
- 报告文件仅写入 --output 指定的白名单目录（S7）。
