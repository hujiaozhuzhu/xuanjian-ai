"""反分析检测规则(10 条) —— Root/模拟器/Frida/调试/篡改检测识别。

提示定位: 这些属于防护项(INFO/LOW), 输出的是"授权测试环境中的绕过技法指引"。

Round 3:
- NEW-08: AA-003 证据改为命中的具体片段（find_evidence_fragments），
  不再输出整段正则源码/长文本。
- NEW-07: AA-004 语义修正 —— 区分"实现 Xposed 模块（hook 他人=攻击方）"
  与"检测 Xposed 框架（被 hook 方=防御方）"两种截然相反的角色。
"""

from __future__ import annotations

from ..core.engine import Rule
from ..models.insight import DifficultyLevel, InsightCategory, Severity

_CAT = InsightCategory.ANTI_ANALYSIS
_REF_RES = ["https://mas.owasp.org/MASVS/05-masvs-maswe/"]

# NEW-07: Xposed 模块实现侧 API（hook 他人 = 攻击方）
_XPOSED_MODULE_RE = (
    r"de\.robv\.android\.xposed\.IXposedHook(LoadPackage|ZygoteInit)"
    r"|handleLoadPackage|XC_MethodHook|XposedHelpers\.(findAndHook|call)"
    r"|XposedBridge\.hook(Method|AllMethods)"
)


def _xposed_evidence(ctx) -> list:
    """AA-004 证据生成（NEW-07）: 按角色标注 [module=attack]/[detector=defense]。"""
    module_hits = ctx.find_evidence_fragments(_XPOSED_MODULE_RE, limit=3)
    out: list = []
    if module_hits:
        out.extend(f"[module=attack] {h}" for h in module_hits)
    detect_hits = ctx.find_evidence_fragments(
        r"de\.robv\.android\.xposed|XposedBridge|substrate|com\.saurik|lsposed|edxposed",
        limit=3,
    )
    for h in detect_hits:
        out.append(f"[detector=defense] {h}")
    return out[:5]

RULES = [
    Rule(
        id="AA-001",
        title="Root 检测(su 文件探测)",
        category=_CAT,
        severity=Severity.INFO,
        confidence=0.95,
        patterns=[r"/system/bin/su|/system/xbin/su|/sbin/su", r"Superuser\.apk|which\s+su"],
        description="检测到 su 二进制路径探测。授权测试中 Hook File.exists 返回 false 即可放行。",
        technical_context="root-bypass 套件已覆盖 File.exists/Runtime.exec/PackageManager 三层。",
        suggested_technique="root-bypass",
        next_steps=["统计检测点数量评估对抗强度", "用 root-bypass 组合模板验证"],
        cwe_ids=["CWE-693"],
        masvs_refs=["MASVS-RESILIENCE-1"],
        references=_REF_RES,
    ),
    Rule(
        id="AA-002",
        title="模拟器检测(Build 指纹/传感器)",
        category=_CAT,
        severity=Severity.INFO,
        confidence=0.9,
        patterns=[r"goldfish|ranchu|generic_x86|Build\.FINGERPRINT|isEmulator|genymotion"],
        description="检测到模拟器特征检测(Build 指纹/设备型号/传感器缺失)。",
        technical_context="return-modify 检测方法返回 false 或伪造 Build 字段即可绕过。",
        suggested_technique="return-modify(isEmulator)",
        next_steps=["枚举模拟器检测点", "在模拟器测试环境统一伪造"],
        cwe_ids=["CWE-693"],
        masvs_refs=["MASVS-RESILIENCE-1"],
        references=_REF_RES,
    ),
    Rule(
        id="AA-003",
        title="Frida 检测(端口/进程/内存特征)",
        category=_CAT,
        severity=Severity.INFO,
        confidence=0.9,
        patterns=[r"frida|gum-js-loop|linjector|frida-server", r"27042|27043|/proc/self/maps|/proc/net/tcp"],
        check=lambda ctx: (
            ctx.find_evidence_fragments(r"frida|gum-js-loop|linjector|2704[23]", limit=3)
            if ctx.has_signal(r"frida|gum-js-loop|linjector")
            and ctx.has_signal(r"2704[23]|/proc/self|/proc/net")
            else []
        ),
        description=(
            "检测到 Frida 特征检测(默认端口/线程名/内存映射扫描), 会阻断动态分析注入。"
            "证据为命中的具体特征片段。"
        ),
        technical_context="对抗路径: 定制 frida-server 改名换端口 / stalker 规避; 先定位检测实现再逐点绕过。",
        suggested_technique="basic-hook(检测方法 return false)",
        next_steps=["定位扫描 /proc 或端口的实现类", "评估是否需要定制 server"],
        cwe_ids=["CWE-693"],
        masvs_refs=["MASVS-RESILIENCE-2"],
        references=_REF_RES,
    ),
    Rule(
        id="AA-004",
        title="Xposed/Substrate 框架特征",
        category=_CAT,
        severity=Severity.INFO,
        confidence=0.9,
        patterns=[r"de\.robv\.android\.xposed|XposedBridge|substrate|com\.saurik", r"lsposed|edxposed"],
        check=lambda ctx: _xposed_evidence(ctx),
        description=(
            "检测到 Xposed/LSPosed/Substrate 相关特征。NEW-07 语义区分: "
            "[module=attack] 应用自身实现 Xposed 模块 API(hook 他人, 攻击方) vs "
            "[detector=defense] 应用检测 Xposed 框架是否加载(被 hook 方, 防御方)。"
            "两者修复/绕过方向相反: 前者是攻击能力清单, 后者是防护项需绕过。"
        ),
        technical_context=(
            "module 侧: Hook 点即应用声明的 XC_MethodHook/handleLoadPackage 实现, "
            "可直接复用其逻辑作为攻击技法; detector 侧: Hook File.exists/ClassLoader "
            "检测返回未加载即可。"
        ),
        suggested_technique="root-bypass",
        next_steps=[
            "按证据前缀区分 module(攻击方)/detector(防御方)",
            "module: 审计其 hook 目标是否包含敏感操作",
            "detector: 授权测试中统一放行",
        ],
        cwe_ids=["CWE-693"],
        masvs_refs=["MASVS-RESILIENCE-1"],
        references=_REF_RES,
    ),
    Rule(
        id="AA-005",
        title="调试器检测(Debug.isDebuggerConnected)",
        category=_CAT,
        severity=Severity.INFO,
        confidence=0.95,
        patterns=[r"isDebuggerConnected", r"android\.os\.Debug", r"Debug\.waittingForDebugger"],
        description="检测到调试器附着检测, 会阻断 JDB/IDEA 动态调试。",
        technical_context="return-modify isDebuggerConnected 返回 false 即可绕过。",
        suggested_technique="return-modify(isDebuggerConnected)",
        next_steps=["确认检测调用点", "测试环境统一伪造"],
        cwe_ids=["CWE-693"],
        masvs_refs=["MASVS-RESILIENCE-2"],
        references=_REF_RES,
    ),
    Rule(
        id="AA-006",
        title="签名自校验(PackageManager 签名比对)",
        category=_CAT,
        severity=Severity.INFO,
        confidence=0.85,
        patterns=[r"getPackageInfo", r"GET_SIGNING_CERTIFICATES|GET_SIGNATURES|signatures\[\]"],
        check=lambda ctx: (
            ctx.find_evidence(r"getPackageInfo|GET_SIGN", limit=3)
            if ctx.has_signal(r"getPackageInfo")
            and ctx.has_signal(r"GET_SIGNING_CERTIFICATES|GET_SIGNATURES|signatures\[\]")
            else []
        ),
        description="检测到运行时签名校验, 重打包后应用会拒绝运行, 阻断二次打包类测试。",
        technical_context="Hook PackageManager.getPackageInfo 返回原始签名即可绕过重打包校验。",
        suggested_technique="return-modify(getPackageInfo)",
        next_steps=["定位签名比对逻辑", "篡改后对比签名 hash 触发点"],
        cwe_ids=["CWE-494"],
        masvs_refs=["MASVS-RESILIENCE-1"],
        references=_REF_RES,
    ),
    Rule(
        id="AA-007",
        title="DEX/APK 完整性校验",
        category=_CAT,
        severity=Severity.INFO,
        confidence=0.8,
        patterns=[r"crc32|CRC32|checksum", r"getPackageCodePath|classes\.dex|sourceDir"],
        check=lambda ctx: (
            ctx.find_evidence(r"crc32|checksum|getPackageCodePath|sourceDir", limit=3)
            if ctx.has_signal(r"crc32|CRC32|checksum")
            and ctx.has_signal(r"getPackageCodePath|classes\.dex|sourceDir")
            else []
        ),
        description="检测到对自身 DEX/APK 的 CRC/Hash 完整性校验, 篡改后自毁退出。",
        technical_context="Hook MessageDigest.digest/CRC32 计算返回固定合法值。",
        suggested_technique="return-modify(完整性校验)",
        next_steps=["确认校验对象与时机", "篡改测试时同步 hook 校验点"],
        cwe_ids=["CWE-345"],
        masvs_refs=["MASVS-RESILIENCE-1"],
        references=_REF_RES,
    ),
    Rule(
        id="AA-008",
        title="Native 层反调试(ptrace)",
        category=_CAT,
        severity=Severity.INFO,
        confidence=0.85,
        patterns=[r"\bptrace\b", r"PTRACE_TRACEME", r"/proc/self/status.*TracerPid"],
        description="检测到 Native 层 ptrace 反调试(自 trace 占位或 TracerPid 检查)。",
        technical_context="so_hook 模板 Hook ptrace 返回 0, 或 inline_hook 其调用点。",
        suggested_technique="native-hook(ptrace)",
        next_steps=["定位调用 ptrace 的 so", "IDA 确认后用 so_hook/inline_hook 放行"],
        cwe_ids=["CWE-693"],
        masvs_refs=["MASVS-RESILIENCE-2"],
        references=_REF_RES,
        estimated_difficulty=DifficultyLevel.HIGH,
    ),
    Rule(
        id="AA-009",
        title="代码混淆检测(Proguard/R8)",
        category=_CAT,
        severity=Severity.INFO,
        confidence=0.7,
        patterns=[r"^L?(a|b|c)\.a\.b\.", r"R\$string|BuildConfig", r"proguard|mapping\.txt"],
        description="检测到混淆特征(短类名/映射痕迹)。混淆会降低静态分析可读性, 属防护项。",
        technical_context="对混淆类优先用字符串/调用栈动态定位(隐雾技法①+②), 静态搜索命中率低。",
        suggested_technique="hashmap-trace(混淆类定位)",
        next_steps=["以字符串常量为锚点回溯业务类", "必要时请求 mapping.txt 对照"],
        cwe_ids=["CWE-656"],
        masvs_refs=["MASVS-RESILIENCE-3"],
        references=_REF_RES,
    ),
    Rule(
        id="AA-010",
        title="Root 工具库集成(RootBeer 等)",
        category=_CAT,
        severity=Severity.INFO,
        confidence=0.9,
        patterns=[r"RootBeer|rootbeer", r"com\.scottyab\.rootbeer", r"isRooted|isRootAvailable", r"RootCloak"],
        description="检测到集成 Root 检测库(RootBeer 等), 检测点多且分层。",
        technical_context="直接 return-modify 库入口 isRooted 返回 false 覆盖全部检测点。",
        suggested_technique="return-modify(isRooted)",
        next_steps=["确认使用的检测库与版本", "hook 库入口方法统一放行"],
        cwe_ids=["CWE-693"],
        masvs_refs=["MASVS-RESILIENCE-1"],
        references=_REF_RES,
    ),
]
