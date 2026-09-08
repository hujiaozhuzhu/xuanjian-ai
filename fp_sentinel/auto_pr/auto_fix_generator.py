"""
玄鉴 v3.0 — 自动修复代码生成器

基于漏洞类型自动生成可落地的修复代码，支持Diff预览、自定义修改

核心能力：
- 按漏洞类型匹配修复模板，生成精确的修复代码
- 输出统一 Diff 格式供预览和确认
- 支持对生成结果进行自定义修改
- 复用 fix_advisor 的 15 类高频规则覆盖，并扩展到完整 VulnerabilityType 枚举

安全红线：
- S2: 绝不修改用户源文件（仅生成修复建议）
- 零网络、零写入
"""

from __future__ import annotations

import hashlib
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    FixDiff,
    FixPatch,
    FixPreview,
    GenerateFixRequest,
    VulnerabilityType,
)


# ─────────────────────────── 规则匹配 ───────────────────────────

def _match_vuln_type(rule_id: str) -> VulnerabilityType:
    """将 rule_id 映射到 VulnerabilityType"""
    rid = (rule_id or "").lower()

    # 按优先级匹配（更具体的规则在前）
    mapping: List[Tuple[str, VulnerabilityType]] = [
        ("os.system", VulnerabilityType.OS_COMMAND),
        ("dangerous-os-system", VulnerabilityType.OS_COMMAND),
        ("dangerous.os.system", VulnerabilityType.OS_COMMAND),
        ("subprocess.os_system", VulnerabilityType.OS_COMMAND),
        ("injection.sql", VulnerabilityType.SQL_INJECTION),
        ("sql_injection", VulnerabilityType.SQL_INJECTION),
        ("sqli", VulnerabilityType.SQL_INJECTION),
        ("format.string.sql", VulnerabilityType.SQL_INJECTION),
        ("xss", VulnerabilityType.XSS),
        ("domxss", VulnerabilityType.XSS),
        ("reflected.xss", VulnerabilityType.XSS),
        ("stored.xss", VulnerabilityType.XSS),
        ("command-injection", VulnerabilityType.COMMAND_INJECTION),
        ("command.injection", VulnerabilityType.COMMAND_INJECTION),
        ("cmd.injection", VulnerabilityType.COMMAND_INJECTION),
        ("cmd-injection", VulnerabilityType.COMMAND_INJECTION),
        ("path.traversal", VulnerabilityType.PATH_TRAVERSAL),
        ("directory.traversal", VulnerabilityType.PATH_TRAVERSAL),
        ("hardcoded.credential", VulnerabilityType.HARDCODED_SECRET),
        ("hardcoded.secret", VulnerabilityType.HARDCODED_SECRET),
        ("api.key", VulnerabilityType.HARDCODED_SECRET),
        ("jwt", VulnerabilityType.JWT_WEAK),
        ("yaml.load", VulnerabilityType.YAML_UNSAFE),
        ("pickle.loads", VulnerabilityType.PICKLE_DESERIALIZE),
        ("eval", VulnerabilityType.EVAL_INJECTION),
        ("code.injection", VulnerabilityType.EVAL_INJECTION),
        ("ssrf", VulnerabilityType.SSRF),
        ("server.side.request", VulnerabilityType.SSRF),
        ("weak.hash", VulnerabilityType.WEAK_HASH),
        ("md5", VulnerabilityType.WEAK_HASH),
        ("ecb", VulnerabilityType.ECB_MODE),
        ("debug", VulnerabilityType.DEBUG_EXPOSURE),
        ("open.redirect", VulnerabilityType.OPEN_REDIRECT),
        ("unvalidated.redirect", VulnerabilityType.OPEN_REDIRECT),
        # v3.0: Java反序列化专项修复
        ("objectinputstream", VulnerabilityType.OBJECT_INPUT_STREAM),
        ("object-input-stream", VulnerabilityType.OBJECT_INPUT_STREAM),
        ("readobject", VulnerabilityType.OBJECT_INPUT_STREAM),
        ("fastjson-parseobject", VulnerabilityType.JAVA_FASTJSON_DESERIALIZE),
        ("fastjson-parse", VulnerabilityType.JAVA_FASTJSON_DESERIALIZE),
        ("jackson-defaulttyping", VulnerabilityType.JAVA_JACKSON_DESERIALIZE),
        ("jackson-readvalue", VulnerabilityType.JAVA_JACKSON_DESERIALIZE),
        ("shiro-rememberme", VulnerabilityType.SHIRO_REMEMBERME),
        ("shiro-hardcoded-key", VulnerabilityType.SHIRO_REMEMBERME),
        ("shiro-aes-cbc", VulnerabilityType.SHIRO_REMEMBERME),
        # v3.0: PHP反序列化专项修复
        ("php-unserialize", VulnerabilityType.PHP_UNSERIALIZE),
        ("unserialize", VulnerabilityType.PHP_UNSERIALIZE),
        ("php-phar", VulnerabilityType.PHP_PHAR_DESERIALIZE),
        ("php-pop", VulnerabilityType.PHP_PHAR_DESERIALIZE),
    ]

    for pattern, vuln_type in mapping:
        if pattern in rid:
            return vuln_type
    return VulnerabilityType.GENERIC


# ─────────────────────────── 修复模板 ───────────────────────────

class _FixTemplate:
    """修复模板定义"""
    def __init__(
        self,
        vuln_type: VulnerabilityType,
        title: str,
        bad_patterns: List[str],
        good_example: str,
        effort_minutes: int = 60,
        reference_cve: str = "",
        incident_note: str = "",
    ):
        self.vuln_type = vuln_type
        self.title = title
        self.bad_patterns = bad_patterns
        self.good_example = good_example
        self.effort_minutes = effort_minutes
        self.reference_cve = reference_cve
        self.incident_note = incident_note


_FIX_TEMPLATES: Dict[VulnerabilityType, _FixTemplate] = {
    VulnerabilityType.SQL_INJECTION: _FixTemplate(
        vuln_type=VulnerabilityType.SQL_INJECTION,
        title="SQL 注入修复（参数化查询）",
        bad_patterns=["+ user_id", "+ uid", "% user", "% uid", ".format(", "f\"SELECT", "f'SELECT", "+ " + "{param}"],
        good_example='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        effort_minutes=45,
        reference_cve="CVE-2012-2122",
        incident_note="拼接 SQL 曾导致大规模拖库（如 Heartland 2008，1.3 亿条记录泄露）。",
    ),
    VulnerabilityType.XSS: _FixTemplate(
        vuln_type=VulnerabilityType.XSS,
        title="XSS 修复（输出转义）",
        bad_patterns=["innerHTML", "document.write", "dangerouslySetInnerHTML", "v-html", "outerHTML"],
        good_example="el.textContent = userInput;  // 或 DOMPurify.sanitize(html)",
        effort_minutes=30,
        reference_cve="CVE-2014-9031",
        incident_note="TweetDeck 2014 XSS 蠕虫令 3.8 万用户转发恶意推文。",
    ),
    VulnerabilityType.COMMAND_INJECTION: _FixTemplate(
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        title="命令注入修复（参数化执行）",
        bad_patterns=["os.system(", "exec(", "popen(", "child_process", "shell=True"],
        good_example='subprocess.run(["ls", user_dir], shell=False)  # 参数数组 + 白名单',
        effort_minutes=60,
        reference_cve="CVE-2014-6271",
        incident_note="Shellshock（CVE-2014-6271）通过环境变量注入命令，波及数十万台服务器。",
    ),
    VulnerabilityType.PATH_TRAVERSAL: _FixTemplate(
        vuln_type=VulnerabilityType.PATH_TRAVERSAL,
        title="路径遍历修复（路径规范化+白名单）",
        bad_patterns=["os.path.join(", "path.join(", "open(filepath", "readFile("],
        good_example=(
            'realpath = os.path.realpath(filepath)\n'
            'if not realpath.startswith(os.path.realpath(base)):\n'
            '    abort(403)'
        ),
        effort_minutes=45,
        reference_cve="CVE-2020-17519",
        incident_note="Apache Flink CVE-2020-17519 通过 ../ 读取任意文件。",
    ),
    VulnerabilityType.HARDCODED_SECRET: _FixTemplate(
        vuln_type=VulnerabilityType.HARDCODED_SECRET,
        title="硬编码密钥修复（环境变量替代）",
        bad_patterns=["SECRET_KEY = \"", "API_KEY = \"", "PASSWORD = \"", "sk-"],
        good_example='SECRET_KEY = os.environ["SECRET_KEY"]  # 并轮换已泄露密钥',
        effort_minutes=30,
        reference_cve="CVE-2018-0114",
        incident_note="Uber 2016 年因硬编码 AWS 凭证泄露 5700 万用户数据。",
    ),
    VulnerabilityType.JWT_WEAK: _FixTemplate(
        vuln_type=VulnerabilityType.JWT_WEAK,
        title="JWT 弱密钥修复（强制算法验证）",
        bad_patterns=["jwt.sign(payload, JWT_SECRET)", "jwt.sign(payload, secret)", "algorithm: 'none'"],
        good_example=(
            'const token = jwt.sign(payload, process.env.JWT_SECRET, { algorithm: \'HS256\' });'
        ),
        effort_minutes=30,
        reference_cve="CVE-2015-9235",
        incident_note="CVE-2015-9235：algorithm 混淆允许 none/RS256→HS256 伪造 token。",
    ),
    VulnerabilityType.YAML_UNSAFE: _FixTemplate(
        vuln_type=VulnerabilityType.YAML_UNSAFE,
        title="YAML 不安全加载修复（safe_load替代）",
        bad_patterns=["yaml.load(", "yaml.unsafe_load("],
        good_example="result = yaml.safe_load(data)",
        effort_minutes=15,
        reference_cve="CVE-2017-18342",
        incident_note="yaml.load 反序列化 RCE 是 Python 应用最常见 RCE 入口之一。",
    ),
    VulnerabilityType.PICKLE_DESERIALIZE: _FixTemplate(
        vuln_type=VulnerabilityType.PICKLE_DESERIALIZE,
        title="Pickle 反序列化修复（JSON替代）",
        bad_patterns=["pickle.loads(", "pickle.load("],
        good_example="obj = json.loads(data)  # 禁止对不可信数据使用 pickle",
        effort_minutes=60,
        reference_cve="CVE-2016-5636",
        incident_note="pickle.loads 等价于任意代码执行，历史上多次导致供应链 RCE。",
    ),
    VulnerabilityType.EVAL_INJECTION: _FixTemplate(
        vuln_type=VulnerabilityType.EVAL_INJECTION,
        title="eval 代码注入修复（安全替代）",
        bad_patterns=["eval(", "new Function(", "Function("],
        good_example="result = ast.literal_eval(code)  # 或 JSON.parse",
        effort_minutes=45,
        reference_cve="CVE-2016-5636",
        incident_note="eval(用户输入) 直接等价于 RCE。",
    ),
    VulnerabilityType.OS_COMMAND: _FixTemplate(
        vuln_type=VulnerabilityType.OS_COMMAND,
        title="os.system 命令执行修复（subprocess参数化）",
        bad_patterns=["os.system("],
        good_example='subprocess.run(["ls", "-la"], shell=False, capture_output=True)',
        effort_minutes=45,
        reference_cve="CVE-2014-6271",
        incident_note="os.system 无法参数化，任何拼接都不可安全。",
    ),
    VulnerabilityType.SSRF: _FixTemplate(
        vuln_type=VulnerabilityType.SSRF,
        title="SSRF 修复（URL白名单校验）",
        bad_patterns=["axios.get(url)", "requests.get(url)", "fetch(userUrl", "urlopen("],
        good_example=(
            'if not ALLOWED_HOSTS.some(h => url.startsWith(h)):\n'
            '    return res.status(403).end();\n'
            'const response = await axios.get(url);'
        ),
        effort_minutes=60,
        reference_cve="CVE-2021-21975",
        incident_note="vRealize SSRF（CVE-2021-21975）被用于窃取凭证后内网横向。",
    ),
    VulnerabilityType.WEAK_HASH: _FixTemplate(
        vuln_type=VulnerabilityType.WEAK_HASH,
        title="弱哈希修复（bcrypt/argon2替代MD5）",
        bad_patterns=["hashlib.md5(", "hashlib.sha1(", "createHash('md5')", "createHash('sha1')"],
        good_example="hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
        effort_minutes=30,
        reference_cve="CVE-2004-2761",
        incident_note="MD5 碰撞成本已低于 1 美元，密码存储必须使用慢哈希。",
    ),
    VulnerabilityType.ECB_MODE: _FixTemplate(
        vuln_type=VulnerabilityType.ECB_MODE,
        title="ECB模式加密修复（GCM替代）",
        bad_patterns=["MODE_ECB", "'aes-ecb'", "mode: 'ecb'"],
        good_example="cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # 弃用 ECB",
        effort_minutes=60,
        reference_cve="CVE-2019-9502",
        incident_note="ECB 相同明文块输出相同密文块，图像加密可被直接还原轮廓。",
    ),
    VulnerabilityType.DEBUG_EXPOSURE: _FixTemplate(
        vuln_type=VulnerabilityType.DEBUG_EXPOSURE,
        title="调试模式暴露修复（生产禁用）",
        bad_patterns=["debug=True", "app.run(port", "--inspect"],
        good_example="app.run(port=3002, debug=False)  # 生产禁用调试控制台",
        effort_minutes=15,
        reference_cve="CVE-2019-1010083",
        incident_note="Werkzeug debug 控制台暴露即可 RCE。",
    ),
    VulnerabilityType.OPEN_REDIRECT: _FixTemplate(
        vuln_type=VulnerabilityType.OPEN_REDIRECT,
        title="开放重定向修复（域名白名单校验）",
        bad_patterns=["redirect(url", "res.redirect(", "window.location = url", "location.href = url"],
        good_example=(
            'from urllib.parse import urlparse\n'
            'target = urlparse(url)\n'
            'if target.netloc and target.netloc != ALLOWED_HOST:\n'
            '    abort(403)\n'
            'return redirect(url)'
        ),
        effort_minutes=30,
        reference_cve="CVE-2016-10735",
        incident_note="开放重定向常被用于钓鱼跳转与 OAuth code 窃取。",
    ),
    VulnerabilityType.GENERIC: _FixTemplate(
        vuln_type=VulnerabilityType.GENERIC,
        title="通用安全修复建议",
        bad_patterns=[],
        good_example="# 请参照规则文档修复该安全问题",
        effort_minutes=60,
        reference_cve="",
        incident_note="按对应 CWE 修复指引处理。",
    ),
    # v3.0: Java ObjectInputStream反序列化
    VulnerabilityType.OBJECT_INPUT_STREAM: _FixTemplate(
        vuln_type=VulnerabilityType.OBJECT_INPUT_STREAM,
        title="Java原生反序列化修复（ObjectInputFilter白名单）",
        bad_patterns=["readObject()", "new ObjectInputStream", ".readObject"],
        good_example=(
            '// 方案1: 使用 ObjectInputFilter 限制可反序列化类\n'
            'ObjectInputFilter filter = ObjectInputFilter.Config.setSerialFilter(\n'
            '    ObjectInputFilter.FilterInfo serialFilterInfo -> {\n'
            '        if (serialFilterInfo.serialClass() != null &&\n'
            '            ALLOWED_CLASSES.contains(serialFilterInfo.serialClass().getName())) {\n'
            '            return ObjectInputFilter.Status.ALLOWED;\n'
            '        }\n'
            '        return ObjectInputFilter.Status.REJECTED;\n'
            '    });\n\n'
            '// 方案2: 替换为JSON格式（推荐）\n'
            'Object result = objectMapper.readValue(data, ExpectedDto.class);'
        ),
        effort_minutes=90,
        reference_cve="CVE-2015-4852",
        incident_note="Java原生反序列化E是OWASP Top 10 A08核心风险。Apache Commons Collections gadget chain可使readObject()直接触发RCE。",
    ),
    # v3.0: Java Fastjson反序列化
    VulnerabilityType.JAVA_FASTJSON_DESERIALIZE: _FixTemplate(
        vuln_type=VulnerabilityType.JAVA_FASTJSON_DESERIALIZE,
        title="Fastjson反序列化修复（safeMode + ParserConfig）",
        bad_patterns=["JSON.parseObject(", "JSON.parse(", "JSON.parseObject"],
        good_example=(
            '// 方案1: 升级到 Fastjson 2.x（推荐）省略autoType\n'
            '// 方案2: 在Fastjson 1.x启用safeMode\n'
            'com.alibaba.fastjson.parser.ParserConfig.getGlobalInstance().setSafeMode(true);\n\n'
            '// 方案3: 使用指定类型解析@type攻击面\n'
            'ExpectedDto dto = JSON.parseObject(jsonData, ExpectedDto.class);'
        ),
        effort_minutes=60,
        reference_cve="CVE-2017-18349",
        incident_note="Fastjson <=1.2.68的autoType特性允许通过@type指定任意类，结合JNDI注入实现RCE。",
    ),
    # v3.0: Java Jackson反序列化
    VulnerabilityType.JAVA_JACKSON_DESERIALIZE: _FixTemplate(
        vuln_type=VulnerabilityType.JAVA_JACKSON_DESERIALIZE,
        title="Jackson多态反序列化修复（禁用defaultTyping）",
        bad_patterns=["enableDefaultTyping", "activateDefaultTyping"],
        good_example=(
            '// 移除enableDefaultTyping\n'
            '// 方案1: 使用@JsonTypeInfo限定类型\n'
            '@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")\n'
            '@JsonSubTypes({@JsonSubTypes.Type(value = SafeImpl.class, name = "safe")})\n'
            'public abstract class BaseDto { }\n\n'
            '// 方案2: 配置Jackson全局安全\n'
            'objectMapper.deactivateDefaultTyping();\n'
        ),
        effort_minutes=60,
        reference_cve="CVE-2017-7525",
        incident_note="Jackson enableDefaultTyping允许通过@class字段实例化任意类（CVE-2017-7525），可触发RCE。",
    ),
    # v3.0: Shiro RememberMe
    VulnerabilityType.SHIRO_REMEMBERME: _FixTemplate(
        vuln_type=VulnerabilityType.SHIRO_REMEMBERME,
        title="Shiro RememberMe反序列化修复（密钥轮替 + AES-GCM）",
        bad_patterns=["kPH+bIxk5D2deZiIxcaaaA==", "rememberMe", "AesCipherService"],
        good_example=(
            '// 1. 删除所有硬编码密钥\n'
            '// 2. 使用随机生成的256-bit密钥（存储在KMS/环境变量中）\n'
            '// 3. 升级Shiro到 >=1.7.1（使用AES-GCM替代AES-CBC）\n'
            '// 4. 替代方案: 禁用rememberMe功能\n'
            '// 5. 如需保持，覆盖AbstractRememberMeManager\n\n'
            '// pom.xml: 升级依赖\n'
            '<dependency>\n'
            '    <groupId>org.apache.shiro</groupId>\n'
            '    <artifactId>shiro-core</artifactId>\n'
            '    <version>1.13.0</version>\n'
            '</dependency>'
        ),
        effort_minutes=120,
        reference_cve="CVE-2016-4437",
        incident_note="Shiro默认密钥kPH+bIxk5D2deZiIxcaaaA==已公开，攻击者可通过Padding Oracle攻击解密cookie后构造反序列化payload实现RCE。",
    ),
    # v3.0: PHP unserialize
    VulnerabilityType.PHP_UNSERIALIZE: _FixTemplate(
        vuln_type=VulnerabilityType.PHP_UNSERIALIZE,
        title="PHP反序列化修复（json_decode + allowed_classes）",
        bad_patterns=["unserialize("],
        good_example=(
            '// 方案1: 使用JSON替代（推荐）\n'
            '$obj = json_decode($data, true); // 接收为数组\n\n'
            '// 方案2: 如必须使用，严格限制可序列化类\n'
            '$obj = unserialize($data, ["allowed_classes" => [SafeDTO::class]]);\n\n'
            '// 方案3: 签名验证确保数据完整性\n'
            '$expected = hash_hmac("sha256", $data, $secretKey);\n'
            'if (hash_equals($expected, $signature)) {\n'
            '    // 只有验证通过后才反序列化\n'
            '}'
        ),
        effort_minutes=60,
        reference_cve="CVE-2018-20427",
        incident_note="PHP unserialize()允许攻击者控制对象属性和类型，通过魔术方法链（POP chain）实现RCE。",
    ),
    # v3.0: PHP Phar反序列化
    VulnerabilityType.PHP_PHAR_DESERIALIZE: _FixTemplate(
        vuln_type=VulnerabilityType.PHP_PHAR_DESERIALIZE,
        title="PHP Phar反序列化修复（phar.readonly + 路径校验）",
        bad_patterns=["file_exists(", "is_file(", "file_get_contents(", "fopen("],
        good_example=(
            '// 1. php.ini配置（最重要）\n'
            '// phar.readonly = On\n\n'
            '// 2. 校验文件路径和使用白名单\n'
            '$allowedDir = realpath(__DIR__ . "/uploads/");\n'
            '$filePath = realpath($userInput);\n'
            'if ($filePath === false || strpos($filePath, $allowedDir) !== 0) {\n'
            '    die("非法路径");\n'
            '}\n\n'
            '// 3. 检查并拒绝phar://协议\n'
            'if (stripos($userInput, "phar://") === 0) {\n'
            '    die("不允许的流包装器");\n'
            '}'
        ),
        effort_minutes=45,
        reference_cve="CVE-2018-5711",
        incident_note="Phar文件操作自动反序列化元数据。攻击者上传伪造的Phar文件（如GIF89a头）通过file_exists()触发RCE。",
    ),
}


# ─────────────────────────── 核心生成器 ───────────────────────────

def _extract_bad_lines(code_snippet: str, bad_patterns: List[str]) -> List[str]:
    """从代码片段中提取命中坏模式的行"""
    if not code_snippet:
        return []
    lines = code_snippet.splitlines()
    hits = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if any(p in line for p in bad_patterns):
            hits.append(line)
    return hits or ([lines[0]] if lines else [])


def _build_unified_diff(file_path: str, bad_lines: List[str], good_example: str) -> str:
    """构建 unified-diff 格式文本"""
    out = [f"--- a/{file_path}", f"+++ b/{file_path}", "@@ 修复建议 @@"]
    for ln in bad_lines[:5]:  # 最多展示5行
        out.append(f"-{ln}")
    out.append("")
    out.append("  /* 替换为安全实现 */")
    for gl in good_example.splitlines():
        out.append(f"+{gl}")
    return "\n".join(out)


def _compute_finding_id(request: GenerateFixRequest) -> str:
    """生成 Finding ID（如果需要）"""
    return request.finding_id or hashlib.sha256(
        f"{request.rule_id}|{request.file_path}|{request.code_snippet[:50]}".encode()
    ).hexdigest()[:16]


class AutoFixGenerator:
    """自动修复代码生成器"""

    def __init__(self):
        self._patches: Dict[str, FixPatch] = {}  # patch_id -> patch
        self._previews: Dict[str, FixPreview] = {}  # finding_id -> preview

    def generate_fix_preview(self, request: GenerateFixRequest) -> FixPreview:
        """
        生成修复预览

        Args:
            request: 修复生成请求

        Returns:
            FixPreview 修复预览
        """
        vuln_type = _match_vuln_type(request.rule_id)
        template = _FIX_TEMPLATES.get(vuln_type, _FIX_TEMPLATES[VulnerabilityType.GENERIC])

        bad_lines = _extract_bad_lines(request.code_snippet, template.bad_patterns)
        unified_diff = _build_unified_diff(
            request.file_path or "unknown",
            bad_lines,
            template.good_example,
        )

        finding_id = _compute_finding_id(request)
        preview = FixPreview(
            finding_id=finding_id,
            rule_id=request.rule_id,
            severity=request.severity,
            file_path=request.file_path,
            vuln_type=vuln_type,
            unified_diff=unified_diff,
            title=template.title,
            effort_minutes=template.effort_minutes,
            reference_cve=template.reference_cve,
            can_customize=True,
        )
        self._previews[finding_id] = preview
        return preview

    def generate_patch(
        self,
        request: GenerateFixRequest,
        custom_fix_code: Optional[str] = None,
    ) -> FixPatch:
        """
        生成修复补丁

        Args:
            request: 修复生成请求
            custom_fix_code: 可选的自定义修复代码（替代自动生成）

        Returns:
            FixPatch 修复补丁
        """
        vuln_type = _match_vuln_type(request.rule_id)
        template = _FIX_TEMPLATES.get(vuln_type, _FIX_TEMPLATES[VulnerabilityType.GENERIC])
        finding_id = _compute_finding_id(request)

        bad_lines = _extract_bad_lines(request.code_snippet, template.bad_patterns)

        # 使用自定义代码或模板示例
        fixed_code = custom_fix_code if custom_fix_code else template.good_example

        fix_diff = FixDiff(
            file_path=request.file_path or "unknown",
            original_code="\n".join(bad_lines) if bad_lines else request.code_snippet,
            fixed_code=fixed_code,
            line_start=1,
            line_end=max(1, len(bad_lines)),
            description=template.title,
        )

        patch = FixPatch(
            finding_id=finding_id,
            vuln_type=vuln_type,
            title=template.title,
            diffs=[fix_diff],
            effort_minutes=template.effort_minutes,
            reference_cve=template.reference_cve,
            incident_note=template.incident_note,
            confidence=0.9 if not template.bad_patterns else 0.8,
            generic=(vuln_type == VulnerabilityType.GENERIC),
        )
        if custom_fix_code:
            patch.custom_modifications["fixed_code"] = custom_fix_code

        self._patches[patch.id] = patch
        return patch

    def customize_patch(self, patch_id: str, custom_code: str) -> Optional[FixPatch]:
        """
        自定义修改补丁

        Args:
            patch_id: 补丁ID
            custom_code: 自定义修复代码

        Returns:
            更新后的 FixPatch，未找到则返回 None
        """
        patch = self._patches.get(patch_id)
        if not patch:
            return None

        if patch.diffs:
            patch.diffs[0].fixed_code = custom_code
        patch.custom_modifications["fixed_code"] = custom_code
        return patch

    def get_patch(self, patch_id: str) -> Optional[FixPatch]:
        """获取补丁"""
        return self._patches.get(patch_id)

    def get_preview(self, finding_id: str) -> Optional[FixPreview]:
        """获取预览"""
        return self._previews.get(finding_id)

    def batch_generate_previews(
        self, requests: List[GenerateFixRequest]
    ) -> List[FixPreview]:
        """批量生成修复预览"""
        return [self.generate_fix_preview(req) for req in requests]

    def batch_generate_patches(
        self, requests: List[GenerateFixRequest]
    ) -> List[FixPatch]:
        """批量生成修复补丁"""
        return [self.generate_patch(req) for req in requests]


# ─────────────────────────── 便捷函数 ───────────────────────────

def generate_fix_preview(
    finding_id: str,
    rule_id: str,
    severity: str,
    file_path: str,
    code_snippet: str,
    message: str = "",
    category: str = "",
    language: str = "",
    cwe: str = "",
) -> FixPreview:
    """
    便捷函数：快速生成修复预览

    Args:
        finding_id: Finding ID
        rule_id: 规则ID
        severity: 严重度
        file_path: 文件路径
        code_snippet: 代码片段
        message: 漏洞描述
        category: 漏洞类别
        language: 编程语言
        cwe: CWE编号

    Returns:
        FixPreview
    """
    request = GenerateFixRequest(
        finding_id=finding_id,
        rule_id=rule_id,
        severity=severity,
        file_path=file_path,
        code_snippet=code_snippet,
        message=message,
        category=category,
        language=language,
        cwe=cwe,
    )
    generator = AutoFixGenerator()
    return generator.generate_fix_preview(request)
