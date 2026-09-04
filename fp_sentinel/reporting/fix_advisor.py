"""
A6-1. Diff 修复建议生成器

- 按规则 ID 建映射表，覆盖高频 15 类规则，其余回退通用建议
- 输出统一 diff 字符串 —— **绝不修改用户源文件**（S2 红线）
- 附工时估计（分钟）+ 相关真实 CVE + 事故说明
本模块零网络、零写入。
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class FixSuggestion:
    """单条修复建议"""
    rule_id: str
    title: str
    diff: str                    # unified-diff 样式字符串（仅供参考，不落盘）
    effort_minutes: int          # 预计修复工时（分钟）
    reference_cve: str = ""
    incident_note: str = ""      # 事故说明
    generic: bool = False        # 是否为通用回退建议


@dataclass
class _FixRule:
    """内部规则模板"""
    key: str
    title: str
    bad_patterns: list = field(default_factory=list)   # 用于从 code_snippet 提取坏行
    good_example: str = ""
    effort_minutes: int = 60
    reference_cve: str = ""
    incident_note: str = ""


# ─────────────────────── 高频 15 类规则映射 ───────────────────────

_FIX_RULES: Dict[str, _FixRule] = {r.key: r for r in [
    _FixRule(
        key="sqli",
        title="SQL 注入（字符串拼接）",
        bad_patterns=["+ user_id", "+ uid", "% user", "% uid", ".format(", "f\"SELECT", "f'SELECT", "+ " + "{param}"],
        good_example='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        effort_minutes=45,
        reference_cve="CVE-2012-2122",
        incident_note="拼接 SQL 曾导致大规模拖库（如 Heartland 2008，1.3 亿条记录泄露）。",
    ),
    _FixRule(
        key="xss",
        title="XSS（未转义输出）",
        bad_patterns=["innerHTML", "document.write", "dangerouslySetInnerHTML", "v-html", "outerHTML"],
        good_example="el.textContent = userInput;  // 或 DOMPurify.sanitize(html)",
        effort_minutes=30,
        reference_cve="CVE-2014-9031",
        incident_note="TweetDeck 2014 XSS 蠕虫令 3.8 万用户转发恶意推文。",
    ),
    _FixRule(
        key="cmd",
        title="命令注入",
        bad_patterns=["os.system(", "exec(", "popen(", "child_process", "shell=True"],
        good_example='subprocess.run(["ls", user_dir], shell=False)  # 参数数组 + 白名单',
        effort_minutes=60,
        reference_cve="CVE-2014-6271",
        incident_note="Shellshock（CVE-2014-6271）通过环境变量注入命令，波及数十万台服务器。",
    ),
    _FixRule(
        key="path",
        title="路径遍历",
        bad_patterns=["os.path.join(", "path.join(", "open(filepath", "readFile("],
        good_example=(
            'realpath = os.path.realpath(filepath)\n'
            '-    if not realpath.startswith(base):\n'
            '+    if not realpath.startswith(os.path.realpath(base)):\n'
            '+        abort(403)'
        ),
        effort_minutes=45,
        reference_cve="CVE-2020-17519",
        incident_note="Apache Flink CVE-2020-17519 通过 ../ 读取任意文件。",
    ),
    _FixRule(
        key="secret",
        title="硬编码密钥",
        bad_patterns=["SECRET_KEY = \"", "API_KEY = \"", "PASSWORD = \"", "sk-"],
        good_example='SECRET_KEY = os.environ["SECRET_KEY"]  # 并轮换已泄露密钥',
        effort_minutes=30,
        reference_cve="CVE-2018-0114",
        incident_note="Uber 2016 年因硬编码 AWS 凭证泄露 5700 万用户数据。",
    ),
    _FixRule(
        key="jwt",
        title="JWT 弱密钥/弱算法",
        bad_patterns=["jwt.sign(payload, JWT_SECRET)", "jwt.sign(payload, secret)", "algorithm: 'none'"],
        good_example=(
            '-const token = jwt.sign(payload, JWT_SECRET);\n'
            '+const token = jwt.sign(payload, process.env.JWT_SECRET, { algorithm: \'HS256\' });'
        ),
        effort_minutes=30,
        reference_cve="CVE-2015-9235",
        incident_note="CVE-2015-9235：algorithm 混淆允许 none/RS256→HS256 伪造 token。",
    ),
    _FixRule(
        key="yaml",
        title="YAML 不安全加载",
        bad_patterns=["yaml.load(", "yaml.unsafe_load("],
        good_example="result = yaml.safe_load(data)",
        effort_minutes=15,
        reference_cve="CVE-2017-18342",
        incident_note="yaml.load 反序列化 RCE 是 Python 应用最常见 RCE 入口之一。",
    ),
    _FixRule(
        key="pickle",
        title="Pickle 反序列化",
        bad_patterns=["pickle.loads(", "pickle.load("],
        good_example="obj = json.loads(data)  # 禁止对不可信数据使用 pickle",
        effort_minutes=60,
        reference_cve="CVE-2016-5636",
        incident_note="pickle.loads 等价于任意代码执行，历史上多次导致供应链 RCE。",
    ),
    _FixRule(
        key="eval",
        title="eval 代码注入",
        bad_patterns=["eval(", "new Function(", "Function("],
        good_example="result = ast.literal_eval(code)  # 或 JSON.parse",
        effort_minutes=45,
        reference_cve="CVE-2016-5636",
        incident_note="eval(用户输入) 直接等价于 RCE。",
    ),
    _FixRule(
        key="os.system",
        title="os.system 命令执行",
        bad_patterns=["os.system("],
        good_example='subprocess.run(["ls", "-la"], shell=False, capture_output=True)',
        effort_minutes=45,
        reference_cve="CVE-2014-6271",
        incident_note="os.system 无法参数化，任何拼接都不可安全。",
    ),
    _FixRule(
        key="ssrf",
        title="SSRF",
        bad_patterns=["axios.get(url)", "requests.get(url)", "fetch(userUrl", "urlopen("],
        good_example=(
            '-const response = await axios.get(url);\n'
            '+if (!ALLOWED_HOSTS.some(h => url.startsWith(h))) return res.status(403).end();\n'
            '+const response = await axios.get(url);'
        ),
        effort_minutes=60,
        reference_cve="CVE-2021-21975",
        incident_note="vRealize SSRF（CVE-2021-21975）被用于窃取凭证后内网横向。",
    ),
    _FixRule(
        key="md5",
        title="弱哈希（MD5/SHA1）",
        bad_patterns=["hashlib.md5(", "hashlib.sha1(", "createHash('md5')", "createHash('sha1')"],
        good_example="hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
        effort_minutes=30,
        reference_cve="CVE-2004-2761",
        incident_note="MD5 碰撞成本已低于 1 美元，密码存储必须使用慢哈希。",
    ),
    _FixRule(
        key="ecb",
        title="ECB 模式加密",
        bad_patterns=["MODE_ECB", "'aes-ecb'", "mode: 'ecb'"],
        good_example="cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # 弃用 ECB",
        effort_minutes=60,
        reference_cve="CVE-2019-9502",
        incident_note="ECB 相同明文块输出相同密文块，图像加密可被直接还原轮廓。",
    ),
    _FixRule(
        key="debug",
        title="调试模式暴露",
        bad_patterns=["debug=True", "app.run(port", "--inspect"],
        good_example="app.run(port=3002, debug=False)  # 生产禁用 Werkzeug 调试控制台",
        effort_minutes=15,
        reference_cve="CVE-2019-1010083",
        incident_note="Werkzeug debug 控制台暴露即可 RCE（多种框架默认配置事故）。",
    ),
    _FixRule(
        key="redirect",
        title="开放重定向",
        bad_patterns=["redirect(url", "res.redirect(", "window.location = url", "location.href = url"],
        good_example=(
            '+from urllib.parse import urlparse\n'
            '+target = urlparse(url)\n'
            '+if target.netloc and target.netloc != ALLOWED_HOST:\n'
            '+    abort(403)\n'
            ' return redirect(url)'
        ),
        effort_minutes=30,
        reference_cve="CVE-2016-10735",
        incident_note="开放重定向常被用于钓鱼跳转与 OAuth code 窃取。",
    ),
]}


# ─────────────────────── 规则匹配 ───────────────────────

def _match_key(rule_id: str) -> Optional[str]:
    rid = (rule_id or "").lower()
    # os.system 优先于通用 cmd/eval 匹配
    if "os.system" in rid or "system(" in rid:
        return "os.system"
    if "ecb" in rid:
        return "ecb"
    ordered = [
        ("sql", "sqli"), ("injection.sql", "sqli"), ("sqli", "sqli"),
        ("format", "sqli"),
        ("xss", "xss"), ("innerhtml", "xss"),
        ("command", "cmd"), ("cmd", "cmd"), ("injection.command", "cmd"),
        ("path", "path"), ("traversal", "path"),
        ("secret", "secret"), ("hardcoded", "secret"), ("api-key", "secret"),
        ("jwt", "jwt"),
        ("yaml", "yaml"),
        ("pickle", "pickle"), ("marshal", "pickle"),
        ("eval", "eval"), ("function-constructor", "eval"),
        ("ssrf", "ssrf"), ("http-request", "ssrf"),
        ("md5", "md5"), ("sha1", "md5"), ("weak-hash", "md5"), ("weak_hash", "md5"),
        ("ecb", "ecb"),
        ("debug", "debug"),
        ("redirect", "redirect"),
    ]
    for pattern, key in ordered:
        if pattern in rid:
            return key
    return None


def _extract_bad_lines(code_snippet: str, bad_patterns: list) -> list:
    """从代码片段中提取命中坏模式的行（只读，不修改源文件）"""
    if not code_snippet:
        return []
    lines = code_snippet.splitlines()
    hits = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if any(p in line for p in bad_patterns):
            hits.append(stripped)
    return hits or [lines[0].strip()]


def _build_diff(filename: str, bad_lines: list, good_example: str) -> str:
    """构建 unified-diff 样式建议字符串（纯展示，不写任何文件）"""
    out = [f"--- a/{filename}", "+++ b/suggested-fix", "@@ 修复建议 @@"]

    def _indent(ln: str) -> str:
        # 保留原缩进
        m = re.match(r"^(\s*)", ln)
        return m.group(1) if m else ""

    for ln in bad_lines[:3]:
        out.append(f"-{ln}")
    out.append("+/* 替换为安全实现 */")
    for gl in good_example.splitlines():
        out.append(f"+{gl}")
    return "\n".join(out)


def suggest_fix(finding: Any) -> FixSuggestion:
    """
    生成修复建议。

    Args:
        finding: Finding 模型（或兼容对象/dict）

    Returns:
        FixSuggestion（diff 字符串形式，绝不修改用户源文件 —— S2）
    """
    def _get(k, d=None):
        if isinstance(finding, dict):
            return finding.get(k, d)
        return getattr(finding, k, d)

    rule_id = _get("rule_id", "unknown") or "unknown"
    file_path = _get("file_path", "") or ""
    code_snippet = _get("code_snippet", "") or ""

    key = _match_key(rule_id)
    if key is None:
        return FixSuggestion(
            rule_id=rule_id,
            title="通用修复建议",
            diff=(
                f"--- a/{file_path}\n"
                "+++ b/suggested-fix\n"
                f"@@ {rule_id} @@\n"
                "-# 请参照规则文档修复该安全问题\n"
                "+# 参考: OWASP Top 10 与对应 CWE 修复指引\n"
                f"+# 规则: {rule_id}"
            ),
            effort_minutes=60,
            incident_note="按对应 CWE 修复指引处理。",
            generic=True,
        )

    rule = _FIX_RULES[key]
    bad_lines = _extract_bad_lines(code_snippet, rule.bad_patterns)
    return FixSuggestion(
        rule_id=rule_id,
        title=rule.title,
        diff=_build_diff(file_path, bad_lines, rule.good_example),
        effort_minutes=rule.effort_minutes,
        reference_cve=rule.reference_cve,
        incident_note=rule.incident_note,
    )


def covered_categories() -> int:
    """已覆盖的规则类别数（高频 15 类）"""
    return len(_FIX_RULES)
