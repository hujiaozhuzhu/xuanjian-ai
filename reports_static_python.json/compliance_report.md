# 玄鉴合规审计摘要 — app.py

> 生成时间: 2026-09-07 14:50:36 UTC  |  项目路径: C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\python-vuln-app\app.py  |  玄鉴 fp-sentinel v2.5.1

## ① 趋势对比

| 指标 | 本次 | 上次 | 变化 |
|------|------|------|------|
| 总发现数 | 10 | - | 首期基线 |
| CRITICAL | 6 | - | 首期基线 |
| HIGH | 3 | - | 首期基线 |
| MEDIUM | 1 | - | 首期基线 |
| LOW | 0 | - | 首期基线 |

*无历史扫描数据，本次结果记录为首期基线。*

## ② 需关注（按 ROI 排序：高危优先、低成本先修）

| ROI | 严重度 | 漏洞 | 位置 | 修复成本 | 参考 CVE |
|-----|--------|------|------|---------|----------|
| 1 | CRITICAL | YAML 不安全加载 | app.py:141 | 15min | CVE-2017-18342 |
| 2 | CRITICAL | 硬编码密钥 | app.py:16 | 30min | CVE-2018-0114 |
| 3 | CRITICAL | SQL 注入（字符串拼接） | app.py:24 | 45min | CVE-2012-2122 |
| 4 | CRITICAL | eval 代码注入 | app.py:59 | 45min | CVE-2016-5636 |
| 5 | CRITICAL | 命令注入 | app.py:40 | 60min | CVE-2014-6271 |
| 6 | CRITICAL | Pickle 反序列化 | app.py:79 | 60min | CVE-2016-5636 |
| 7 | HIGH | 弱哈希（MD5/SHA1） | app.py:96 | 30min | CVE-2004-2761 |
| 8 | HIGH | 路径遍历 | app.py:113 | 45min | CVE-2020-17519 |
| 9 | HIGH | 路径遍历 | app.py:115 | 45min | CVE-2020-17519 |
| 10 | MEDIUM | 通用修复建议 | app.py:14 | 60min | - |

## ③ Diff 修复建议

*以下建议仅为 diff 字符串示意，玄鉴不会修改您的源文件。*

#### 1. YAML 不安全加载 — app.py:141
- 参考案例: CVE-2017-18342
- 预计工时: 15 分钟
- 事故背景: yaml.load 反序列化 RCE 是 Python 应用最常见 RCE 入口之一。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\python-vuln-app\app.py
+++ b/suggested-fix
@@ 修复建议 @@
-result = yaml.load(data)  # 🔴 漏洞
+/* 替换为安全实现 */
+result = yaml.safe_load(data)
```

#### 2. 硬编码密钥 — app.py:16
- 参考案例: CVE-2018-0114
- 预计工时: 30 分钟
- 事故背景: Uber 2016 年因硬编码 AWS 凭证泄露 5700 万用户数据。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\python-vuln-app\app.py
+++ b/suggested-fix
@@ 修复建议 @@
-SECRET_KEY = "hardcoded_secret_key_123"  # 🔴 漏洞: 硬编码密钥
+/* 替换为安全实现 */
+SECRET_KEY = os.environ["SECRET_KEY"]  # 并轮换已泄露密钥
```

#### 3. SQL 注入（字符串拼接） — app.py:24
- 参考案例: CVE-2012-2122
- 预计工时: 45 分钟
- 事故背景: 拼接 SQL 曾导致大规模拖库（如 Heartland 2008，1.3 亿条记录泄露）。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\python-vuln-app\app.py
+++ b/suggested-fix
@@ 修复建议 @@
-query = "SELECT * FROM users WHERE id = " + user_id  # 🔴 漏洞
+/* 替换为安全实现 */
+cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

#### 4. eval 代码注入 — app.py:59
- 参考案例: CVE-2016-5636
- 预计工时: 45 分钟
- 事故背景: eval(用户输入) 直接等价于 RCE。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\python-vuln-app\app.py
+++ b/suggested-fix
@@ 修复建议 @@
-result = eval(code)  # 🔴 漏洞
+/* 替换为安全实现 */
+result = ast.literal_eval(code)  # 或 JSON.parse
```

#### 5. 命令注入 — app.py:40
- 参考案例: CVE-2014-6271
- 预计工时: 60 分钟
- 事故背景: Shellshock（CVE-2014-6271）通过环境变量注入命令，波及数十万台服务器。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\python-vuln-app\app.py
+++ b/suggested-fix
@@ 修复建议 @@
-os.system(cmd)  # 🔴 漏洞
+/* 替换为安全实现 */
+subprocess.run(["ls", user_dir], shell=False)  # 参数数组 + 白名单
```

#### 6. Pickle 反序列化 — app.py:79
- 参考案例: CVE-2016-5636
- 预计工时: 60 分钟
- 事故背景: pickle.loads 等价于任意代码执行，历史上多次导致供应链 RCE。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\python-vuln-app\app.py
+++ b/suggested-fix
@@ 修复建议 @@
-obj = pickle.loads(data)  # 🔴 漏洞
+/* 替换为安全实现 */
+obj = json.loads(data)  # 禁止对不可信数据使用 pickle
```

#### 7. 弱哈希（MD5/SHA1） — app.py:96
- 参考案例: CVE-2004-2761
- 预计工时: 30 分钟
- 事故背景: MD5 碰撞成本已低于 1 美元，密码存储必须使用慢哈希。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\python-vuln-app\app.py
+++ b/suggested-fix
@@ 修复建议 @@
-hashed = hashlib.md5(password.encode()).hexdigest()  # 🔴 漏洞
+/* 替换为安全实现 */
+hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

#### 8. 路径遍历 — app.py:113
- 参考案例: CVE-2020-17519
- 预计工时: 45 分钟
- 事故背景: Apache Flink CVE-2020-17519 通过 ../ 读取任意文件。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\python-vuln-app\app.py
+++ b/suggested-fix
@@ 修复建议 @@
-filepath = os.path.join('uploads', filename)  # 🔴 漏洞
+/* 替换为安全实现 */
+realpath = os.path.realpath(filepath)
+-    if not realpath.startswith(base):
++    if not realpath.startswith(os.path.realpath(base)):
++        abort(403)
```

#### 9. 路径遍历 — app.py:115
- 参考案例: CVE-2020-17519
- 预计工时: 45 分钟
- 事故背景: Apache Flink CVE-2020-17519 通过 ../ 读取任意文件。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\python-vuln-app\app.py
+++ b/suggested-fix
@@ 修复建议 @@
-with open(filepath) as f:
+/* 替换为安全实现 */
+realpath = os.path.realpath(filepath)
+-    if not realpath.startswith(base):
++    if not realpath.startswith(os.path.realpath(base)):
++        abort(403)
```

#### 10. 通用修复建议 — app.py:14
- 参考案例: N/A
- 预计工时: 60 分钟
- 事故背景: 按对应 CWE 修复指引处理。
```diff
--- a/C:\Users\lenovo\xuanjian-ai\target-lab-temp\playground\python-vuln-app\app.py
+++ b/suggested-fix
@@ py.auth.no_csrf @@
-# 请参照规则文档修复该安全问题
+# 参考: OWASP Top 10 与对应 CWE 修复指引
+# 规则: py.auth.no_csrf
```

## ④ 声明

- 本报告由玄鉴 fp-sentinel 自动生成，仅用于防御性安全审计与合规自查。
- 修复建议以 diff 字符串形式给出，工具承诺不修改任何用户源文件（S2）。
- 报告文件仅写入 --output 指定的白名单目录（S7）。
