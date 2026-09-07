"""
A5. 攻防报告生成器（Markdown）

章节固定（计划表 A5 增强版 v2.2.1）：
  ① 攻击面总览（ASCII 路径图）
  ② 攻防思路（利用场景、前置条件、攻击路径、影响范围）
  ③ 已验证漏洞表（漏洞/位置/利用难度/验证状态/影响）
  ④ 攻击路径详情（步骤 + PoC代码块 + 被攻破概率）
  ⑤ 本地验证PoC和EXP（仅localhost环境，标注仅用于防御验证）
  ⑥ 可能的问题（漏洞利用限制、现有防御绕过可能性、修复建议）
  ⑦ 攻击链串联思路（漏洞组合形成完整攻击链的路径与影响）
  ⑧ 需人工确认
  ⑨ 修复优先级（按概率排序 + 预计工时）
  ⑩ 安全声明（"PoC 仅用于防御验证" + 生成时间 + 30天清理提示 + 本地环境限制）

S7：报告文件只写入白名单目录（resolve 后必须落在允许根内）。
本模块零网络。
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


from ..attack.chain_orchestrator import AttackChainReport
from ..attack.exploitability import ExploitabilityResult
from ..attack.poc_templates import PocInstance
from ..attack.target_validator import VerifyResult, VerifyStatus

logger = logging.getLogger(__name__)


class ReportPathError(Exception):
    """报告输出路径越界（S7 白名单校验失败）"""


# ─────────────────────── S7 白名单校验 ───────────────────────

def resolve_output_path(
    output_dir: str,
    filename: str,
    allowed_roots: Optional[List[str]] = None,
) -> Path:
    """
    校验并解析报告输出路径。

    规则（S7）：
    - resolve 后必须在 allowed_roots 内（默认: cwd 与 output_dir 自身）
    - 拒绝路径穿越（../ 逃逸）

    Returns:
        Path: 允许的最终文件路径

    Raises:
        ReportPathError: 路径越界
    """
    out = Path(output_dir).resolve()
    candidate = Path(filename)
    # A filename argument must remain a filename. Absolute paths and drive/root
    # prefixes must never be allowed to replace the configured output directory.
    if candidate.is_absolute() or candidate.anchor:
        raise ReportPathError(
            f"[S7 安全红线] 报告文件名必须是相对路径: {filename}"
        )
    target = (out / candidate).resolve()

    roots = [Path(r).resolve() for r in (allowed_roots or [])] if allowed_roots else []
    if not roots:
        roots = [out]
    # 允许 cwd 作为兜底白名单根
    roots.append(Path.cwd().resolve())

    if not any(
        target == root or root in target.parents for root in roots
    ) or any(part == ".." for part in candidate.parts):
        raise ReportPathError(
            f"[S7 安全红线] 报告输出路径越界: {target} 不在允许目录内 {roots}"
        )
    return target


def write_report(content: str, output_dir: str, filename: str) -> Path:
    """白名单校验后写入报告文件（仅写入 --output 目录）"""
    path = resolve_output_path(output_dir, filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# ─────────────────────── 报告生成 ───────────────────────

STATUS_LABEL = {
    VerifyStatus.VERIFIED_LOCAL.value: "verified_local（Docker 靶场）",
    VerifyStatus.SIMULATED.value: "simulated（特征匹配模拟）",
    VerifyStatus.MANUAL_REQUIRED.value: "manual_required（需人工确认）",
}

_DIFFICULTY_LABEL = {
    "EASY": "低", "MEDIUM": "中", "HARD": "高", "VERY_HARD": "极高",
}

# 漏洞类型 → 攻防思路知识库（利用场景、前置条件、攻击路径、影响范围）
# 规则ID前缀 → 知识库键的映射（用于 _look_up_thinking 模糊匹配）
_RULE_ID_THINKING_MAP: Dict[str, str] = {
    "java-objectinputstream-readobject": "deser-java-native",
    "java-objectinputstream": "deser-java-native",
    "java-readobject": "deser-java-native",
    "java-fastjson-parseobject": "deser-java-fastjson",
    "java-fastjson": "deser-java-fastjson",
    "java-shiro-default-key": "deser-java-shiro",
    "java-shiro-rememberme": "deser-java-shiro",
    "java-jackson-enabledefaulttyping": "deser-java-jackson",
    "java-jackson": "deser-java-native",
    "php-unserialize-user-input": "deser-php-pop",
    "php-unserialize": "deser-php-pop",
    "php-phar-metadata-deserialization": "deser-php-phar",
    "php-phar": "deser-php-phar",
    "python-pickle-loads-untrusted": "deser-python-pickle",
    "python-pickle": "deser-python-pickle",
}

# 规则ID前缀 → 知识库键的映射（用于 _look_up_limitation 模糊匹配）
_RULE_ID_LIMITATION_MAP: Dict[str, str] = {
    "java-objectinputstream-readobject": "deser-java-native",
    "java-objectinputstream": "deser-java-native",
    "java-readobject": "deser-java-native",
    "java-fastjson-parseobject": "deser-java-fastjson",
    "java-fastjson": "deser-java-fastjson",
    "java-shiro-default-key": "deser-java-shiro",
    "java-shiro-rememberme": "deser-java-shiro",
    "java-jackson-enabledefaulttyping": "deser-java-jackson",
    "java-jackson": "deser-java-native",
    "php-unserialize-user-input": "deser-php-pop",
    "php-unserialize": "deser-php-pop",
    "php-phar-metadata-deserialization": "deser-php-phar",
    "php-phar": "deser-php-phar",
    "python-pickle-loads-untrusted": "deser-python-pickle",
    "python-pickle": "deser-python-pickle",
}


_ATTACK_THINKING_DB: Dict[str, Dict[str, str]] = {
    "sqli": {
        "scenario": "攻击者通过构造恶意 SQL 语句，绕过应用程序逻辑，直接操作数据库",
        "prerequisite": "用户输入未参数化拼接至 SQL 查询语句；数据库连接权限非最小化",
        "attack_path": "用户输入 → 拼接待执行 SQL → 数据库 UNION 注入/时间盲注 → 读取敏感数据或执行系统命令",
        "impact": "数据库全部数据泄露、数据篡改/删除、服务器被接管（通过 INTO OUTFILE 写 Webshell）",
    },
    "xss": {
        "scenario": "攻击者在页面注入恶意脚本，在受害者浏览器上下文中执行",
        "prerequisite": "用户输入未经转义直接输出至 HTML 响应或写入 DOM；缺少 CSP 或 HttpOnly 防护",
        "attack_path": "用户输入 → 拼接到 HTML 响应 / innerHTML 赋值 → 受害者浏览器解析执行 → 窃取 Cookie/会话",
        "impact": "会话劫持、钓鱼诱导、键盘记录、蠕虫传播、管理员后台接管",
    },
    "cmd": {
        "scenario": "攻击者通过注入 shell 元字符，在服务器上执行任意操作系统命令",
        "prerequisite": "用户输入传入 os.system / subprocess 等系统级函数；未做输入白名单过滤",
        "attack_path": "用户输入 → 拼接到 shell 命令字符串 → 系统解释器执行 → 获取反向 shell",
        "impact": "服务器完全被控制、内网横向移动、数据窃取、勒索加密",
    },
    "command": {
        "scenario": "攻击者通过注入 shell 元字符，在服务器上执行任意操作系统命令",
        "prerequisite": "用户输入传入 os.system / subprocess 等系统级函数；未做输入白名单过滤",
        "attack_path": "用户输入 → 拼接到 shell 命令字符串 → 系统解释器执行 → 获取反向 shell",
        "impact": "服务器完全被控制、内网横向移动、数据窃取、勒索加密",
    },
    "eval": {
        "scenario": "攻击者将恶意代码作为字符串传入 eval/Function 等动态执行函数",
        "prerequisite": "用户输入参与动态代码编译/执行上下文；缺少执行隔离",
        "attack_path": "用户输入 → 拼接到 eval/Function 字符串 → 解释器执行恶意代码 → RCE",
        "impact": "任意代码执行、权限提升、后门植入",
    },
    "path": {
        "scenario": "攻击者通过 ../ 序列穿越目录边界，读取服务器上的任意文件",
        "prerequisite": "用户输入参与文件路径拼接；缺少路径规范化与基准目录校验",
        "attack_path": "用户输入 → 拼接到文件路径 → 绕过目录边界 → 读取敏感文件（/etc/passwd、配置文件等）",
        "impact": "敏感凭证泄露（数据库密码、密钥）、源代码暴露、进一步提权",
    },
    "traversal": {
        "scenario": "攻击者通过 ../ 序列穿越目录边界，读取服务器上的任意文件",
        "prerequisite": "用户输入参与文件路径拼接；缺少路径规范化与基准目录校验",
        "attack_path": "用户输入 → 拼接到文件路径 → 绕过目录边界 → 读取敏感文件",
        "impact": "敏感凭证泄露、源代码暴露、进一步提权",
    },
    "ssrf": {
        "scenario": "攻击者利用服务端发起请求的功能，探测或访问内网/回环地址资源",
        "prerequisite": "服务端接受用户可控 URL 并主动发起 HTTP 请求；未做 URL 白名单校验",
        "attack_path": "用户输入恶意 URL → 服务端解析并发起请求 → 访问内网服务/云元数据接口 → 窃取敏感信息",
        "impact": "内网服务扫描与探测、云环境元数据窃取（AWS IAM 凭证）、Redis 未授权访问写入后门",
    },
    "deser": {
        "scenario": "攻击者通过构造恶意序列化数据，在反序列化时触发任意代码执行",
        "prerequisite": "服务端使用 pickle/yaml.load 等不安全方式反序列化不可信数据",
        "attack_path": "用户可控输入 → 构造恶意 pickle/yaml payload → 服务端反序列化 → __reduce__ 方法触发 RCE",
        "impact": "远程代码执行、服务器完全沦陷",
    },
    # R1-Fix: 细分类反序列化攻防思路
    "deser-java-native": {
        "scenario": "攻击者通过构造恶意 Java 序列化流（ObjectInputStream.readObject()），利用 Classpath 中的 gadget chain（如 CommonsCollections）实现远程代码执行",
        "prerequisite": "服务端直接使用 ObjectInputStream.readObject() 处理不可信输入；Classpath 中存在 CommonsCollections/CommonsBeanutils 等已知 gadget 依赖；无 ObjectInputFilter 白名单校验",
        "attack_path": "POST 不可信数据 → Base64 解码 → ObjectInputStream.readObject() → 自动调用 gadget 链（如 InvokerTransformer.transform()）→ Runtime.exec() → RCE",
        "impact": "服务器完全被控制、内网横向移动、数据窃取、勒索加密、持久化后门",
    },
    "deser-java-fastjson": {
        "scenario": "攻击者利用 Fastjson @type 字段指定危险类名，触发 JNDI 注入加载远程恶意类实现 RCE",
        "prerequisite": "Fastjson <= 1.2.24 且未关闭 AutoType；攻击者可搭建恶意 LDAP/RMI 服务；目标存在对应 gadget 类",
        "attack_path": "POST JSON with @type → Fastparser.parseObject() → JNDI lookup(ldap://attacker/Exploit) → 加载恶意 class → 静态代码块执行 → RCE",
        "impact": "远程代码执行、服务器沦陷、数据窃取",
    },
    "deser-java-jackson": {
        "scenario": "攻击者利用 Jackson enableDefaultTyping() 多态类型处理，在 JSON 中指定危险类名触发 RCE",
        "prerequisite": "ObjectMapper.enableDefaultTyping() 已启用；Classpath中存在可利用 gadget（如 ClassPathXmlApplicationContext）",
        "attack_path": "POST JSON with @class（enableDefaultTyping）→ Jackson readValue() → instantiate 指定类 → gadget chain 触发 → RCE",
        "impact": "远程代码执行、服务器沦陷",
    },
    "deser-java-shiro": {
        "scenario": "攻击者利用 Shiro 默认 AES 密钥（CVE-2016-4437）伪造 RememberMe cookie，实现反序列化 RCE",
        "prerequisite": "Shiro 使用默认密钥 kPH+bIxk5D2deZiIxcaaaA==；存在 CommonsCollections gadget",
        "attack_path": "ysoserial 生成 gadget → AES-CBC 加密（密钥 kPH+bIxk5D2deZiIxcaaaA==）→ Base64 → rememberMe Cookie → Shiro 解密 → readObject → RCE",
        "impact": "远程代码执行、服务器沦陷、持久化后门",
    },
    "deser-php-pop": {
        "scenario": "攻击者通过 PHP unserialize() 构造 POP 链（Property-Oriented Programming），利用魔术方法链（__destruct/__wakeup/__toString/__invoke）实现 RCE",
        "prerequisite": "unserialize() 处理用户输入；代码中存在可串联的魔术方法链（如 Logger.__destruct → CommandExecutor.__invoke → system）",
        "attack_path": "构造 POP 链 → base64_encode(serialize($obj)) → POST to unserialize endpoint → __destruct() 触发 → gadget chain 执行 → system() → RCE",
        "impact": "远程代码执行、服务器沦陷",
    },
    "deser-php-phar": {
        "scenario": "攻击者通过上传伪装成图片的 Phar 文件，利用 Phar 元数据自动反序列化触发 RCE",
        "prerequisite": "phar.readonly=0；存在文件上传功能；服务端代码使用 file_exists/fopen 等操作上传目录中的文件",
        "attack_path": "构造恶意 Phar（GIF89a 头 + CommandExecutor 元数据）→ 上传 → file_exists(phar://...) 触发 → 自动反序列化 metadata → __invoke → system() → RCE",
        "impact": "远程代码执行、服务器沦陷",
    },
    "deser-python-pickle": {
        "scenario": "攻击者通过构造恶意 pickle 数据，利用 __reduce__ 方法在反序列化时执行任意系统命令",
        "prerequisite": "pickle.loads() 处理不可信数据；无 HMAC 签名校验",
        "attack_path": "构造 __reduce__ gadget → pickle.dumps(EvilClass()) → base64 → POST → pickle.loads() → __reduce__ 返回 (os.system, ('id',)) → RCE",
        "impact": "远程代码执行、服务器沦陷",
    },
    "jwt": {
        "scenario": "攻击者利用弱密钥或 algorithm=none 伪造 JWT token，冒充任意用户身份",
        "prerequisite": "JWT 使用弱密钥（可被离线暴力破解）或接受 algorithm=none",
        "attack_path": "获取弱密钥/构造 none 算法 → 离线伪造 JWT → 替换 Authorization 头 → 权限提升为 admin",
        "impact": "身份伪造、权限提升、接管任意用户会话",
    },
    "xxe": {
        "scenario": "攻击者通过 XML 外部实体注入读取本地文件或发起 SSRF 请求",
        "prerequisite": "服务端解析外部可控的 XML 数据且启用了 DTD/外部实体解析",
        "attack_path": "用户可控 XML → 构造 DOCTYPE ENTITY → 解析器加载外部实体 → 读取本地文件或探测内网",
        "impact": "本地任意文件读取（含密钥）、内网端口扫描",
    },
}

# 漏洞类型 → 利用限制/防御绕过知识库
_LIMITATION_DB: Dict[str, Dict[str, str]] = {
    "sqli": {
        "limitation": "若服务端关闭了错误回显，盲注效率降低但不可靠性增加；部分 ORM 拦截了常见注入特征",
        "bypass": "现有 WAF 可通过编码变形（双重 URL 编码、十六进制、注释混淆）或分块传输绕过",
        "fix": "强制参数化查询（PreparedStatement）；账户最小权限；禁用数据库危险功能（如 FILE 权限）",
    },
    "xss": {
        "limitation": "CSP 头、HttpOnly Cookie、输入长度限制可缩小有效利用窗口",
        "bypass": "CSP 可通过允许的 CDN 域名加载外部脚本；若 CSP 配置了 'unsafe-inline' 则完全失效",
        "fix": "所有用户输出做 HTML 实体转义；启用严格 CSP (script-src 'self')；敏感 Cookie 设置 HttpOnly + Secure",
    },
    "cmd": {
        "limitation": "disable_functions、AppArmor/SELinux 可限制可执行范围；WAF 层通常检测常见注入模式",
        "bypass": "使用 ${IFS} 替代空格、八进制/十六进制编码命令、利用已有可执行文件间接执行",
        "fix": "使用 subprocess.run 参数数组（shell=False）+ 命令白名单；移除所有 os.system 调用",
    },
    "command": {
        "limitation": "disable_functions、AppArmor/SELinux 可限制可执行范围",
        "bypass": "使用 ${IFS} 替代空格、已有可执行文件间接执行",
        "fix": "使用参数数组 + 命令白名单；移除所有 os.system 调用",
    },
    "eval": {
        "limitation": "沙箱环境、disable_functions、open_basedir 可限制影响",
        "bypass": "反引号执行、文件包含 + eval 组合、动态传参执行",
        "fix": "彻底移除 eval/Function；若需动态计算使用 ast.literal_eval 或安全数学解析器",
    },
    "path": {
        "limitation": "chroot 环境、open_basedir、AppArmor 可限制访问范围；软链接可能被拦截",
        "bypass": "使用符号链接遍历、竞争条件（TOCTOU）、Win 路径截断（::$DATA）",
        "fix": "realpath 后校验基准目录；使用白名单映射而非直接使用用户输入路径",
    },
    "traversal": {
        "limitation": "chroot 环境、open_basedir 可限制访问范围",
        "bypass": "符号链接遍历、竞争条件、Win 路径截断",
        "fix": "realpath 后校验基准目录；使用白名单映射",
    },
    "ssrf": {
        "limitation": "网络层隔离、DNS 重绑定防护、云环境 IMDSv2 强制 token 可限制利用",
        "bypass": "DNS 重绑定攻击、302 跳转绕过、使用 file:/// gopher:// 等协议、IPv6 ::1",
        "fix": "严格 URL 白名单（域名+端口）；禁用 file/gopher 等危险协议；请求必须在隔离的 DNS 解析后进行",
    },
    "deser": {
        "limitation": "签名校验（HMAC）可防止 payload 被篡改；部分反序列化库支持 RestrictedUnpickler",
        "bypass": "通过已有 gadget chain（魔术方法）构造 RCE；JNDI 注入 + 反序列化组合",
        "fix": "禁止对不可信数据使用 pickle/yaml.load：改用 JSON；使用 safe_load；若必须用 pickle 则加 HMAC 签名",
    },
    # R1-Fix: 反序列化细分类防御/绕过知识库
    "deser-java-native": {
        "limitation": "ObjectInputFilter（JDK 9+）可限制反序列化的类；RMI 安全管理器可限制远程类加载",
        "bypass": "利用非标准 gadget 链（如 SignedObject 包装、JNDI 从反序列化内部触发）。 CommonsCollections 4.x 可绕过部分过滤。",
        "fix": "添加 ObjectInputFilter 白名单；升级到 commons-collections 3.2.2+/4.1+；使用 JSON 替代原生序列化",
    },
    "deser-java-fastjson": {
        "limitation": "AutoType 从 1.2.25 起默认关闭；safeMode 完全禁用 @type",
        "bypass": "AutoType 绕过（BypassAutoTypeCheck、期望类白名单技巧等，各版本独立）",
        "fix": "升级 Fastjson 到最新版本；启用 safeMode；关闭 AutoType；使用 JSON.parseObject(data, clazz) 显式指定类型",
    },
    "deser-java-shiro": {
        "limitation": "Shiro 1.2.5+ 已修复默认密钥问题；升级到 1.4.1+ 使用随机密钥",
        "bypass": "通过 BeanContextSupport 等新 gadget 链绕过；Padding Oracle 攻击猜测密钥",
        "fix": "替换默认强随机 AES 密钥；升级到最新版本 Shiro；删除反序列化前的 Cookie 值",
    },
    "deser-java-jackson": {
        "limitation": "Jackson 2.9.9+ 默认关闭 defaultTyping；2.10+ 使用 @JsonTypeInfo 显式声明",
        "bypass": "利用不同版本 Jackson 的变种 gadget（ROME, Jython, Spring 等）",
        "fix": "移除 enableDefaultTyping() 调用；使用 @JsonTypeInfo(use = Id.NAME, include = As.PROPERTY, property = \"type\") 限定类名",
    },
    "deser-php-pop": {
        "limitation": "PHP 7.4+ 的 allow_classes 选项限制 unserialize 可实例化的类；WAF 检测常见 POP 链特征",
        "bypass": "利用 phar:// 包装器触发反序列化绕过直接 unserialize 检测；文件包含+LFI组合",
        "fix": "使用 json_encode/json_decode；unserialize($data, ['allowed_classes' => false])；对不可信数据禁止反序列化",
    },
    "deser-php-phar": {
        "limitation": "phar.readonly=1 阻止 Phar 文件创建；open_basedir 限制路径",
        "bypass": "利用已有文件操作函数触发 phar:// . Muxin 出题技巧：phar 入 zip 伪装 PDF",
        "fix": "php.ini 设置 phar.readonly=1；调用 file_exists 等前检查 mime + 后缀；使用 stream_wrapper_unregister('phar')",
    },
    "deser-python-pickle": {
        "limitation": "HMAC 签名可防篡改；RestrictedUnpickler 可限制可加载类",
        "bypass": "利用 __reduce_ex__ 替代 __reduce__ ；__builtins__.__import__ 绕过模块限制",
        "fix": "使用 json/pickle 的安全替代方案（如 json.loads）；对必须 pickle 的数据加 HMAC 签名并校验",
    },
    "jwt": {
        "limitation": "强随机密钥（≥256bit）可防止离线暴力破解；RS256 比 HS256 更安全",
        "bypass": "algorithm 混淆攻击（RS256→HS256）、kid 路径遍历、空算法绕过",
        "fix": "使用 RS256 + 强密钥；服务端固定允许的算法列表；密钥必须从环境变量注入",
    },
    "xxe": {
        "limitation": "禁用外部实体 + DTD 可完全防护；XXE 仅在 XML 解析启用 DTD 时有效",
        "bypass": "通过 XInclude 注入、SVG 文件作为 XML 解析、SOAP 服务端注入",
        "fix": "XML 解析器配置禁用 DTD、外部实体、XInclude；使用 JSON 替代 XML",
    },
}


def _look_up_thinking(rule_id: str) -> Dict[str, str]:
    """根据 rule_id 检索攻防思路知识库条目（R1-Fix: 优先匹配更具体的键）"""
    rid = (rule_id or "").lower()

    # 先查映射表精确匹配（R1-Fix: 支持 Semgrep rule_id 直接定位）
    mapped_key = _RULE_ID_THINKING_MAP.get(rid)
    if mapped_key and mapped_key in _ATTACK_THINKING_DB:
        return _ATTACK_THINKING_DB[mapped_key]

    # 回退到原有的子串匹配逻辑
    best_entry: Dict[str, str] = {}
    best_key_len = 0
    for key, entry in _ATTACK_THINKING_DB.items():
        if key in rid and len(key) > best_key_len:
            best_entry = entry
            best_key_len = len(key)
    return best_entry


def _look_up_limitation(rule_id: str) -> Dict[str, str]:
    """根据 rule_id 检索可能性问题知识库条目（R1-Fix: 优先匹配更具体的键）"""
    rid = (rule_id or "").lower()

    # 先查映射表精确匹配（R1-Fix: 支持 Semgrep rule_id 直接定位）
    mapped_key = _RULE_ID_LIMITATION_MAP.get(rid)
    if mapped_key and mapped_key in _LIMITATION_DB:
        return _LIMITATION_DB[mapped_key]

    # 回退到原有的子串匹配逻辑
    best_entry: Dict[str, str] = {}
    best_key_len = 0
    for key, entry in _LIMITATION_DB.items():
        if key in rid and len(key) > best_key_len:
            best_entry = entry
            best_key_len = len(key)
    return best_entry


def _effort_minutes(probability: float, difficulty: str) -> int:
    """修复工时估计：概率越高、难度越低越优先（分钟）"""
    base = {"EASY": 30, "MEDIUM": 60, "HARD": 120, "VERY_HARD": 240}.get(difficulty, 60)
    if probability >= 70:
        return base
    if probability >= 40:
        return base * 2
    return base * 4


def _ascii_path_diagram(chain_report: AttackChainReport) -> str:
    """① 攻击面总览 ASCII 路径图"""
    lines: List[str] = []
    if not chain_report.paths:
        lines.append("（未发现多点攻击路径 —— 漏洞以单点形式存在，见③⑤）")
        return "\n".join(lines)

    for idx, path in enumerate(chain_report.paths[:8], 1):
        lines.append(f"[路径 {idx}] 严重度 {path.severity}  被攻破概率 {path.probability}%")
        prev_file = None
        for step in path.steps:
            if prev_file is not None and step.file_path == prev_file:
                connector = "    ↓ 同文件数据流"
            else:
                connector = "    ↓ 跨模块调用"
            if step.step_number > 1:
                lines.append(connector)
            lines.append(
                f"    [步骤 {step.step_number}] {step.vuln_type}"
                f"  ({Path(step.file_path).name}:{step.line})"
                f"  难度:{_DIFFICULTY_LABEL.get(step.difficulty, step.difficulty)}"
                f"  概率:{step.probability}%"
            )
            prev_file = step.file_path
        lines.append("")
    return "\n".join(lines).rstrip()


def _attack_thinking_section(
    findings: List[Any],
    exploit_results: List[ExploitabilityResult],
    chain_report: AttackChainReport,
) -> str:
    """② 攻防思路：利用场景、前置条件、攻击路径、影响范围"""
    lines: List[str] = []
    lines.append("> 本节仅描述漏洞的理论利用方式，所有验证均限制在本地环境（127.0.0.1/localhost）。\n")

    if not findings:
        lines.append("（本次扫描未发现漏洞，无需攻防思路分析）\n")
        return "\n".join(lines)

    # 按漏洞类型聚合，去重展示
    seen_types: set = set()
    idx = 0
    for f, er in zip(findings, exploit_results):
        rule = getattr(f, "rule_id", "?")
        fp = Path(getattr(f, "file_path", "?")).name
        line = getattr(f, "line_start", 0)

        thinking = _look_up_thinking(rule)
        type_key = rule.lower()
        if type_key in seen_types:
            continue
        seen_types.add(type_key)
        idx += 1

        lines.append(f"**{idx}. {rule}** @ `{fp}:{line}`")
        if er.probability > 0:
            lines.append(f"   - 被攻破概率: **{er.probability}%** | 可达性: {er.reachability}")
        if thinking:
            if thinking.get("scenario"):
                lines.append(f"   - 利用场景: {thinking['scenario']}")
            if thinking.get("prerequisite"):
                lines.append(f"   - 前置条件: {thinking['prerequisite']}")
            if thinking.get("attack_path"):
                lines.append(f"   - 攻击路径: {thinking['attack_path']}")
            if thinking.get("impact"):
                lines.append(f"   - 影响范围: {thinking['impact']}")
        else:
            lines.append(f"   - 该漏洞类型暂无内置攻防思路条目，建议结合 CWE 文档分析。")
        lines.append("")

    # 汇总攻击面评估
    total_active = sum(1 for er in exploit_results if er.probability > 0)
    total_paths = chain_report.path_count
    lines.append("**攻击面汇总**")
    lines.append(f"  - 活跃漏洞数量: {total_active}/{len(findings)}")
    lines.append(f"  - 串联攻击路径数: {total_paths}")
    if chain_report.max_probability > 0:
        lines.append(f"  - 最高被攻破概率: {chain_report.max_probability}%")
    lines.append("")

    return "\n".join(lines)


def _verified_table(
    findings: List[Any],
    verify_results: List[VerifyResult],
    exploit_results: List[ExploitabilityResult],
) -> str:
    """③ 已验证漏洞表"""
    header = (
        "| # | 漏洞类型 | 位置 | 利用难度 | 被攻破概率 | 验证状态 | 验证方式 |\n"
        "|---|---------|------|---------|-----------|---------|---------|"
    )
    rows = []
    for i, (f, vr, er) in enumerate(zip(findings, verify_results, exploit_results), 1):
        rule = getattr(f, "rule_id", "?")
        fp = Path(getattr(f, "file_path", "?")).name
        line = getattr(f, "line_start", 0)
        rows.append(
            f"| {i} | {rule} | {fp}:{line} "
            f"| {_DIFFICULTY_LABEL.get(_diff_from_severity(er.severity), '中')} "
            f"| {er.probability}% | {STATUS_LABEL.get(vr.status.value, vr.status.value)} "
            f"| {vr.method} |"
        )
    return header + "\n" + "\n".join(rows) + "\n"


def _diff_from_severity(severity: str) -> str:
    return {
        "CRITICAL": "EASY", "HIGH": "MEDIUM",
        "MEDIUM": "HARD", "LOW": "VERY_HARD",
    }.get(severity, "MEDIUM")


def _path_details(
    chain_report: AttackChainReport,
    poc_map: Dict[str, PocInstance],
) -> str:
    """④ 攻击路径详情：步骤 + PoC代码块 + 概率"""
    if not chain_report.paths:
        return "（无多点攻击路径）\n"

    blocks = []
    for idx, path in enumerate(chain_report.paths[:6], 1):
        lines = [f"### 路径 {idx}: {path.name}", ""]
        lines.append(f"- 严重度: {path.severity}")
        lines.append(f"- 整链被攻破概率: **{path.probability}%**")
        lines.append("")
        for step in path.steps:
            poc = poc_map.get(step.vuln_type)
            lines.append(
                f"**步骤 {step.step_number}** — {step.vuln_type} "
                f"({Path(step.file_path).name}:{step.line})，"
                f"难度 {_DIFFICULTY_LABEL.get(step.difficulty, step.difficulty)}"
            )
            if poc is not None:
                lines.append("")
                lines.append("```text")
                lines.append(poc.rendered)
                lines.append("```")
                if poc.reference_cve:
                    lines.append(f"参考案例: {poc.reference_cve}")
            lines.append("")
        if path.remediation:
            lines.append("链路修复建议: " + "；".join(sorted(set(path.remediation))))
            lines.append("")
        blocks.append("\n".join(lines))
    return "\n".join(blocks)


def _poc_and_exp_section(poc_map: Dict[str, PocInstance], chain_report: AttackChainReport) -> str:
    """⑤ 本地验证PoC和EXP：仅localhost环境，标注仅用于防御验证，不包含任何真实攻击载荷"""
    lines: List[str] = []
    lines.append("> **安全红线：** 本节所有 PoC/EXP 均为教科书级标准 payload，")
    lines.append("> **仅用于防御验证**，目标锁定为 `127.0.0.1` / `localhost`（S1 红线），")
    lines.append("> 不包含任何真实攻击载荷，禁止任何外网请求。\n")

    if not poc_map:
        lines.append("（无可生成的 PoC 模板 —— 确保传入非空的 poc_map 以生成本地验证代码）\n")
        return "\n".join(lines)

    # 优先展示链路径相关的 PoC
    priority_types = []
    for path in chain_report.paths[:6]:
        for step in path.steps:
            if step.vuln_type not in priority_types and step.vuln_type in poc_map:
                priority_types.append(step.vuln_type)
    # 再补充 map 中有但不在路径中的
    for vt in poc_map:
        if vt not in priority_types:
            priority_types.append(vt)

    shown = 0
    for vuln_type in priority_types[:10]:
        poc = poc_map.get(vuln_type)
        if poc is None:
            continue
        shown += 1
        lines.append(f"**{shown}. [{vuln_type}]** (CWE: {poc.cwe})")
        lines.append("")
        lines.append(f"- 目标: `{poc.target}` (仅限本地回环地址)")
        lines.append(f"- 模式: {'本地离线 crypto' if poc.mode == 'crypto' else '字符串模板'}")
        if poc.reference_cve:
            lines.append(f"- 参考: {poc.reference_cve}")
        if poc.safe_explanation:
            lines.append(f"- 防御说明: {poc.safe_explanation}")
        lines.append("")
        lines.append("```text")
        lines.append(poc.rendered)
        lines.append("```")
        lines.append("")

    if shown == 0:
        lines.append("（PoC 模板库中无对应条目）\n")

    return "\n".join(lines)


def _potential_issues_section(
    findings: List[Any],
    verify_results: List[VerifyResult],
    exploit_results: List[ExploitabilityResult],
) -> str:
    """⑥ 可能的问题：漏洞利用限制、现有防御绕过可能性、修复建议"""
    lines: List[str] = []
    lines.append("> 本节列出各漏洞利用时可能遇到的限制与防护措施，")
    lines.append("> 并提供对应的防御升级建议。\n")

    if not findings:
        lines.append("（本次扫描未发现漏洞）\n")
        return "\n".join(lines)

    seen_types: set = set()
    for f, er, vr in zip(findings, exploit_results, verify_results):
        rule = getattr(f, "rule_id", "?")
        type_key = rule.lower()
        if type_key in seen_types:
            continue
        seen_types.add(type_key)

        limitation = _look_up_limitation(rule)
        lines.append(f"- **{rule}**")
        if limitation:
            if limitation.get("limitation"):
                lines.append(f"  - 利用限制: {limitation['limitation']}")
            if limitation.get("bypass"):
                lines.append(f"  - 现有防御绕过可能性: {limitation['bypass']}")
            if limitation.get("fix"):
                lines.append(f"  - 修复建议: {limitation['fix']}")
        else:
            lines.append(f"  - 暂无内置的利用限制分析，建议参考 CWE 文档与 OWASP 修复指引。")

        # 根据实际验证状态补充说明
        if vr.status == VerifyStatus.SIMULATED:
            lines.append(f"  - 验证状态: simulated（特征匹配模拟），实际利用可能需要更多前置步骤。")
        elif vr.status == VerifyStatus.MANUAL_REQUIRED:
            lines.append(f"  - 验证状态: manual_required，需人工确认漏洞可达性后方可评估进一步利用。")

        if er.probability == 0:
            lines.append(f"  - 当前评估: theoretical（纯内部常量），暂无实际利用价值。")
        lines.append("")

    return "\n".join(lines)


def _attack_chain_thinking_section(chain_report: AttackChainReport) -> str:
    """⑦ 攻击链串联思路：漏洞如何组合形成完整攻击链"""
    lines: List[str] = []
    lines.append("> 本节分析多个漏洞如何协作形成更高级别的安全威胁。\n")

    if not chain_report.paths and not chain_report.single_points:
        lines.append("（无数据 —— 本次扫描未发现漏洞或未进行攻击链编排）\n")
        return "\n".join(lines)

    if not chain_report.paths:
        # 仅单点但有 single_points
        lines.append("**当前状态: 仅存在单点漏洞，未形成串联攻击链**\n")
        lines.append(f"- 单点漏洞数量: {len(chain_report.single_points)}")
        if chain_report.single_points:
            top = chain_report.single_points[0]
            lines.append(f"- 最高风险单点: `{top.rule_id}` @ {top.file_path}:{top.line} (概率 {top.probability}%)")
        lines.append("")
        lines.append("**潜在串联可能性提示**")
        lines.append("  - 单点漏洞虽然未在当前代码中直接串联，但若网络边界存在其他弱点（如 DNS 请求伪造、内网服务暴露），")
        lines.append("    可能被外部攻击者组合利用。建议结合网络拓扑与系统上下文进行进一步评估。")
        lines.append("")
        return "\n".join(lines)

    # 有路径时展示具体串联思路
    lines.append(f"**已发现 {chain_report.path_count} 条串联攻击路径**\n")

    for idx, path in enumerate(chain_report.paths[:8], 1):
        lines.append(f"**路径 {idx}:** `{path.name}`")
        lines.append(f"- 整链被攻破概率: **{path.probability}%** | 严重度: {path.severity}")
        lines.append(f"- 串联步骤:")

        for step in path.steps:
            lines.append(
                f"  - 步骤 {step.step_number}: `{step.vuln_type}` "
                f"({Path(step.file_path).name}:{step.line}) "
                f"[难度 {_DIFFICULTY_LABEL.get(step.difficulty, step.difficulty)}, "
                f"概率 {step.probability}%]"
            )

        # 串联影响范围
        lines.append(f"- 逐步影响:")
        step_impacts = []
        for step in path.steps:
            thinking = _look_up_thinking(step.vuln_type)
            if thinking and thinking.get("impact"):
                step_impacts.append(f"  步骤 {step.step_number}（{step.vuln_type}）→ {thinking['impact']}")
        if step_impacts:
            lines.extend(step_impacts[:5])
        else:
            lines.append(f"  逐步执行 {len(path.steps)} 个漏洞，累积达成最终攻击目标。")

        # 最终风险
        lines.append(f"- 最终风险: 完成全部 {len(path.steps)} 步串联后，攻击者可达成组合攻击效果，")
        lines.append(f"  整体成功率为 {path.probability}%（已考虑每步的独立失败概率）。")

        if path.remediation:
            lines.append(f"- 断链建议: " + "；".join(sorted(set(path.remediation))))
        lines.append("")

    return "\n".join(lines)


def _manual_section(verify_results: List[VerifyResult], findings: List[Any]) -> str:
    """⑧ 需人工确认"""
    rows = []
    for f, vr in zip(findings, verify_results):
        if vr.status == VerifyStatus.MANUAL_REQUIRED:
            rows.append(
                f"- `{getattr(f, 'rule_id', '?')}` @ "
                f"{getattr(f, 'file_path', '?')}:{getattr(f, 'line_start', 0)} — {vr.evidence}"
            )
    if not rows:
        return "（无需人工确认项 —— 全部完成模拟验证）\n"
    return "\n".join(rows) + "\n"


def _fix_priority(
    exploit_results: List[ExploitabilityResult],
    findings: List[Any],
) -> str:
    """⑨ 修复优先级（按概率排序 + 预计工时）"""
    items = sorted(
        zip(exploit_results, findings),
        key=lambda pair: pair[0].probability,
        reverse=True,
    )
    header = (
        "| 优先级 | 漏洞 | 位置 | 概率 | 预计工时 |\n"
        "|-------|------|------|------|---------|"
    )
    rows = []
    for i, (er, f) in enumerate(items[:15], 1):
        if er.probability <= 0:
            continue
        difficulty = _diff_from_severity(er.severity)
        minutes = _effort_minutes(er.probability, difficulty)
        hours = f"{minutes // 60}h{minutes % 60:02d}m" if minutes >= 60 else f"{minutes}m"
        rows.append(
            f"| P{i} | {er.rule_id} | {Path(er.file_path).name}:{er.line} "
            f"| {er.probability}% | {hours} |"
        )
    if not rows:
        return header + "\n| - | （全部为 theoretical，无活跃风险） | - | - | - |\n"
    return header + "\n" + "\n".join(rows) + "\n"


def _security_statement_section(now: str) -> str:
    """⑩ 安全声明：明确标注报告仅用于防御验证，本地环境，30天清理"""
    lines: List[str] = []
    lines.append(
        "- **仅用于防御验证**：本报告所有 PoC/EXP 均为教科书级标准 payload（参考 MITRE CWE 与 OWASP 官方文档），"
        "仅用于在本地环境（localhost / 127.0.0.1）验证漏洞可达性、培训安全团队与演练防御策略，"
        "**严禁用于任何未授权的真实系统测试**。\n"
    )
    lines.append(
        "- **本地环境限制**：所有验证目标均为本地回环地址（S1 红线强制开启），"
        "不包含任何真实基础设施地址、域名或外网 IP。报告生成过程零网络请求。\n"
    )
    lines.append(
        "- **无真实攻击载荷**：本报告生成的 payload 均为教学演示级别，"
        "不包含实际的恶意代码、后门、勒索软件或任何可用于破坏系统完整性/机密性的攻击载荷。\n"
    )
    lines.append(
        "- **30 天数据清理**：依据 S5 红线，PoC 与攻防数据默认保留 30 天，"
        "到期请执行 `fp-sentinel attack-purge` 清理（可通过 `--days` 参数调整保留周期）。\n"
    )
    lines.append(
        "- **法律与合规声明**：本报告内容与工具仅限在合法授权范围内使用，"
        "使用者须遵守当地法律法规。本工具未集成任何可用于绕过真实安全防护的攻击能力，"
        "所有发现均需人工在授权环境下复现确认。\n"
    )
    lines.append(f"> 报告生成时间: {now}  |  玄鉴 fp-sentinel v2.2.1\n")
    return "\n".join(lines)


def generate_attack_report(
    project: str,
    findings: List[Any],
    chain_report: AttackChainReport,
    verify_results: Optional[List[VerifyResult]] = None,
    exploit_results: Optional[List[ExploitabilityResult]] = None,
    poc_map: Optional[Dict[str, PocInstance]] = None,
    generated_at: Optional[str] = None,
) -> str:
    """
    生成 Markdown 攻防报告（10 章节固定）。

    Args:
        project: 项目名
        findings: Finding 列表
        chain_report: 攻击链编排结果
        verify_results: 每条 finding 的验证结果（与 findings 对齐）
        exploit_results: 每条 finding 的可利用性结果（与 findings 对齐）
        poc_map: {漏洞类型: PocInstance}
    """
    findings = list(findings or [])
    verify_results = verify_results or []
    exploit_results = exploit_results or []
    poc_map = poc_map or {}
    now = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 补齐对齐长度
    while len(verify_results) < len(findings):
        verify_results.append(VerifyResult(
            status=VerifyStatus.MANUAL_REQUIRED, method="fallback",
            evidence="缺少验证结果"))
    while len(exploit_results) < len(findings):
        from ..attack.exploitability import assess
        exploit_results.append(assess(findings[len(exploit_results)]))

    status_counts: Dict[str, int] = {}
    for vr in verify_results:
        status_counts[vr.status.value] = status_counts.get(vr.status.value, 0) + 1
    status_line = "、".join(
        f"{STATUS_LABEL.get(k, k)} ×{v}" for k, v in sorted(status_counts.items())
    ) or "无"

    sections = []
    sections.append(f"# 玄鉴攻防审计报告 — {project}\n")
    sections.append(f"> 生成时间: {now}  |  玄鉴 fp-sentinel v2.2.1")
    sections.append(f"> 验证状态分布: {status_line}\n")

    sections.append("## ① 攻击面总览\n")
    sections.append("```text")
    sections.append(_ascii_path_diagram(chain_report))
    sections.append("```\n")

    sections.append("## ② 攻防思路\n")
    sections.append(_attack_thinking_section(findings, exploit_results, chain_report))

    sections.append("## ③ 已验证漏洞表\n")
    if findings:
        sections.append(_verified_table(findings, verify_results, exploit_results))
    else:
        sections.append("（本次扫描未发现漏洞）\n")

    sections.append("## ④ 攻击路径详情\n")
    sections.append(_path_details(chain_report, poc_map))

    sections.append("## ⑤ 本地验证PoC和EXP\n")
    sections.append(_poc_and_exp_section(poc_map, chain_report))

    sections.append("## ⑥ 可能的问题\n")
    sections.append(_potential_issues_section(findings, verify_results, exploit_results))

    sections.append("## ⑦ 攻击链串联思路\n")
    sections.append(_attack_chain_thinking_section(chain_report))

    sections.append("## ⑧ 需人工确认\n")
    sections.append(_manual_section(verify_results, findings))

    sections.append("## ⑨ 修复优先级\n")
    sections.append(_fix_priority(exploit_results, findings))

    sections.append("## ⑩ 安全声明\n")
    sections.append(_security_statement_section(now))

    return "\n".join(sections) + "\n"
