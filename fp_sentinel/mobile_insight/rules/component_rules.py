"""组件安全规则(12 条) —— 四大组件导出/Intent 风险/WebView 桥。

Round 2（RD-003）: 组件导出类规则以 Manifest 解析结果为唯一事实源
（``exported_by_kind`` 结构化数据）；轻量降级模式下仅当存在业务包
（非框架/库）类名佐证时才报候选级提示，框架类名（如
android.view.ActionProvider）永不作为证据。
Round 3（NEW-03）: 候选级判定升级为业务类门控 —— 已知真实包名时只有
包名前缀类触发 HIGH；androidx.*/com.google.*/android.support.* 等库类
直接过滤；Kotlin/混淆形态类名打标。
"""

from __future__ import annotations

import re

from ..core.context import classify_class
from ..core.engine import Rule
from ..models.insight import DifficultyLevel, InsightCategory, Severity

_CAT = InsightCategory.COMPONENT
_REF_PLT = ["https://mas.owasp.org/MASVS/05-masvs-maswe/"]


def _exported_check(kind: str):
    """导出组件检查: Manifest 事实源优先, 业务类名降级佐证（RD-003/NEW-03）。"""

    def check(ctx) -> list:
        # 1) Manifest 精确解析结果（唯一事实源）。
        #    R3.1 确定性: androguard 组件枚举内部用 set，顺序随
        #    PYTHONHASHSEED 漂移 —— 证据选择前必须排序。
        structured = sorted(ctx.exported_by_kind.get(kind) or [])
        if structured:
            return [f"{name} (exported=true)" for name in structured[:5]]
        # 2) 字符串形态的导出组件（调用方手工注入）
        comps = sorted(
            c for c in ctx.exported_components if kind in c.lower()
        )
        if comps:
            return [c.strip() for c in comps[:5]]
        # 3) 轻量降级模式（NEW-03 业务类门控）: 仅当 manifest 注册了该类型
        #    组件 且 存在业务包类名佐证。框架/库类（androidx/com.google/
        #    android.support…）永不作为候选；已知真实包名时仅包名前缀类
        #    触发候选；混淆形态类名打标。
        if ctx.manifest_flags.get(f"has_{kind}") and ctx.classes:
            rx = re.compile(kind, re.IGNORECASE)
            out: list = []
            for c in sorted(ctx.classes):
                if not rx.search(c):
                    continue
                kind_cls = classify_class(c, ctx.package_name)
                if kind_cls in ("framework", "library"):
                    continue
                if ctx.package_name and not c.startswith(ctx.package_name):
                    continue
                tag = " (exported=未确认, 候选)"
                if kind_cls == "obfuscated":
                    tag = " (obfuscated, exported=未确认, 候选)"
                out.append(f"{c}{tag}")
                if len(out) >= 3:
                    break
            return out
        return []

    return check


RULES = [
    Rule(
        id="CP-001",
        title="Activity 组件导出",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.9,
        patterns=[r"exported.*activity", r"android\.app\.Activity"],
        check=_exported_check("activity"),
        description="存在导出 Activity, 可被第三方应用构造 Intent 唤起, 若未做鉴权校验可实现本地鉴权绕过。",
        technical_context="drozer/am start 唤起测试; 若目标检测登录态仅凭 getIntent extra 即可绕过。",
        suggested_technique="param-modify(Intent extra)",
        next_steps=["枚举导出 Activity 清单", "检查 onCreate 鉴权逻辑", "未必要导出的设置 exported=false"],
        cwe_ids=["CWE-926"],
        masvs_refs=["MASVS-PLATFORM-1"],
        references=_REF_PLT,
        code_level=False,
    ),
    Rule(
        id="CP-002",
        title="Service 组件导出",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.9,
        patterns=[r"exported.*service", r"android\.app\.Service"],
        check=_exported_check("service"),
        description="存在导出 Service, 第三方可 startService/bindService 调用受限功能。",
        technical_context="Hook onStartCommand/onBind 打印 Intent 内容确认可触达的操作。",
        suggested_technique="basic-hook(Service.onStartCommand)",
        next_steps=["枚举导出 Service", "校验调用方包名(getCallingPackage)"],
        cwe_ids=["CWE-926"],
        masvs_refs=["MASVS-PLATFORM-1"],
        references=_REF_PLT,
        code_level=False,
    ),
    Rule(
        id="CP-003",
        title="Broadcast Receiver 导出",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.9,
        patterns=[r"exported.*receiver", r"BroadcastReceiver"],
        check=_exported_check("receiver"),
        description="存在导出 Receiver, 可接收恶意广播触发敏感操作(隐雾组件安全章节典型案例)。",
        technical_context="InsecureBank 类靶场中常见 Receiver 可被 am broadcast 携带凭据触发。",
        suggested_technique="basic-hook(Receiver.onReceive)",
        next_steps=["枚举导出 Receiver 与 action", "修复: 设置权限或 exported=false"],
        cwe_ids=["CWE-926"],
        masvs_refs=["MASVS-PLATFORM-1"],
        references=_REF_PLT,
        code_level=False,
    ),
    Rule(
        id="CP-004",
        title="Content Provider 导出",
        category=_CAT,
        severity=Severity.HIGH,
        confidence=0.9,
        patterns=[r"exported.*provider", r"ContentProvider"],
        check=_exported_check("provider"),
        description="存在导出 ContentProvider, 未授权访问可读取/篡改私有数据。",
        technical_context="drozer app.provider.query 测试; 检查 openFile 是否存在路径穿越。",
        suggested_technique="basic-hook(Provider.query)",
        next_steps=["枚举导出 Provider 与 grantUriPermissions", "增加读写权限校验"],
        cwe_ids=["CWE-926"],
        masvs_refs=["MASVS-PLATFORM-1"],
        references=_REF_PLT,
        code_level=False,
    ),
    Rule(
        id="CP-005",
        title="PendingIntent 可变性(缺 FLAG_IMMUTABLE)",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.85,
        patterns=[r"PendingIntent\.getActivity|PendingIntent\.getBroadcast|PendingIntent\.getService", r"PendingIntent"],
        check=lambda ctx: (
            [
                e for e in ctx.find_evidence(
                    r"PendingIntent\.(getActivity|getBroadcast|getService|getForeground)",
                    limit=3,
                )
            ]
            if not ctx.has_signal(r"FLAG_IMMUTABLE")
            else []
        ),
        description="检测到 PendingIntent 使用但未见 FLAG_IMMUTABLE, Intent 可被填充/劫持(目标 S+ 强制)。",
        technical_context="Hook PendingIntent.getActivity 等工厂方法确认 flags 参数。",
        suggested_technique="basic-hook(PendingIntent 工厂)",
        next_steps=["确认 flags 取值", "修复: 显式添加 FLAG_IMMUTABLE"],
        cwe_ids=["CWE-927"],
        masvs_refs=["MASVS-PLATFORM-1"],
        references=_REF_PLT,
        auto_fixable=True,
        fix_hint="PendingIntent.getActivity(..., FLAG_IMMUTABLE)",
    ),
    Rule(
        id="CP-006",
        title="动态注册 Receiver 无权限保护",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.85,
        patterns=[r"registerReceiver"],
        check=lambda ctx: (
            ctx.find_evidence(r"registerReceiver", limit=3)
            if not ctx.has_signal(r"ReceiverPermission|setPackage")
            else []
        ),
        description="检测到动态注册广播但未见权限/包名约束, 存在隐式 Intent 劫持面。",
        technical_context="Hook registerReceiver 打印 IntentFilter 与 permission 参数。",
        suggested_technique="callstack-trace(registerReceiver)",
        next_steps=["确认注册的 action 与权限", "修复: registerReceiver 时指定权限或 LOCAL_BROADCAST"],
        cwe_ids=["CWE-925"],
        masvs_refs=["MASVS-PLATFORM-1"],
        references=_REF_PLT,
    ),
    Rule(
        id="CP-007",
        title="隐式 Intent 携带敏感数据",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.7,
        patterns=[r"new\s+Intent\s*\(\s*['\"][a-z]", r"setAction\s*\("],
        check=lambda ctx: (
            ctx.find_evidence(r"Intent", limit=3)
            if ctx.has_signal(r"(putExtra.{0,40}(token|password|session|secret))")
            else []
        ),
        description="疑似通过 Intent extra 传递敏感数据, 隐式 Intent 可被第三方截获。",
        technical_context="Hook Intent.putExtra 观察键值与目标组件。",
        suggested_technique="basic-hook(Intent.putExtra)",
        next_steps=["确认 Intent 显式/隐式", "修复: 显式 Intent + 不传敏感明文"],
        cwe_ids=["CWE-927"],
        masvs_refs=["MASVS-PLATFORM-1"],
        references=_REF_PLT,
    ),
    Rule(
        id="CP-008",
        title="WebView addJavascriptInterface 暴露",
        category=_CAT,
        severity=Severity.HIGH,
        confidence=0.9,
        patterns=[r"addJavascriptInterface"],
        description="WebView 注入 Java 对象, 在 API < 17 存在通用 RCE(JsToJavaBridge), 高版本仍暴露业务桥。",
        technical_context="Hook addJavascriptInterface 打印对象与名称; 结合 loadUrl 评估注入面。",
        suggested_technique="basic-hook(addJavascriptInterface)",
        next_steps=["枚举暴露的 JS 桥对象", "确认 @JavascriptInterface 方法是否含敏感操作"],
        cwe_ids=["CWE-749"],
        masvs_refs=["MASVS-PLATFORM-2"],
        references=_REF_PLT,
    ),
    Rule(
        id="CP-009",
        title="WebView 开启本地文件访问",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.85,
        patterns=[r"setAllowFileAccess\s*\(\s*true", r"setAllowFileAccessFromFileURLs\s*\(\s*true",
                  r"setAllowUniversalAccessFromFileURLs\s*\(\s*true"],
        description="WebView 允许 file:// 域访问本地文件, 恶意页面可读取应用私有文件。",
        technical_context="Hook WebSettings 相关 setter 确认配置组合。",
        suggested_technique="basic-hook(WebSettings)",
        next_steps=["确认三项 file 配置", "修复: 全部关闭 file 域访问"],
        cwe_ids=["CWE-552"],
        masvs_refs=["MASVS-PLATFORM-2"],
        references=_REF_PLT,
    ),
    Rule(
        id="CP-010",
        title="Deep Link 未校验来源",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.7,
        patterns=[r"getData\(\)", r"onNewIntent|onCreate.*getIntent"],
        check=lambda ctx: (
            ctx.find_evidence(r"getData|getIntent", limit=3)
            if ctx.has_signal(r"(scheme|deeplink|://)")
            else []
        ),
        description="检测到 Deep Link 参数读取, 若未校验 host/参数来源可被恶意页面拉起并注入参数。",
        technical_context="Hook Activity.getIntent/getData 打印外部传入 URI。",
        suggested_technique="basic-hook(Activity.getIntent)",
        next_steps=["枚举 intent-filter scheme", "修复: 校验 host + 参数白名单"],
        cwe_ids=["CWE-20"],
        masvs_refs=["MASVS-PLATFORM-1"],
        references=_REF_PLT,
    ),
    Rule(
        id="CP-011",
        title="Intent 重定向(startActivity 未校验组件)",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.7,
        patterns=[r"startActivity", r"getIntent|setComponent|setClassName|setClass"],
        check=lambda ctx: (
            ctx.find_evidence(r"startActivity|setComponent|setClassName", limit=3)
            if ctx.has_signal(r"startActivity")
            and ctx.has_signal(r"getIntent|setComponent|setClassName|setClass")
            else []
        ),
        description="疑似将外部传入的 Intent/组件直接用于 startActivity, 可被诱导跳转到任意组件(Intent Redirect)。",
        technical_context="Hook startActivity 打印 Intent 与调用栈确认重定向链。",
        suggested_technique="callstack-trace(startActivity)",
        next_steps=["定位重定向代码路径", "修复: 白名单组件校验"],
        cwe_ids=["CWE-940"],
        masvs_refs=["MASVS-PLATFORM-1"],
        references=_REF_PLT,
    ),
    Rule(
        id="CP-012",
        title="ContentProvider openFile 路径穿越",
        category=_CAT,
        severity=Severity.HIGH,
        confidence=0.8,
        patterns=[r"openFile", r"ContentProvider"],
        check=lambda ctx: (
            [
                e for e in ctx.find_evidence(r"openFile", limit=5)
                if "openFileOutput" not in e and "OpenFileActivityBuilder" not in e
            ]
            if ctx.has_signal(r"\.\./|\.\.\\\\|getExternalStorage|Environment\.getExternal")
            else []
        ),
        description="Provider openFile 与外部路径拼接同时出现, 疑似存在 Path Traversal 任意文件读取。",
        technical_context="构造 ../ 式 uri 即可验证; Hook openFile 打印解析后的路径。",
        suggested_technique="param-modify(Provider URI)",
        next_steps=["确认 path 规范化逻辑", "修复: 使用 getCanonicalPath + 目录白名单"],
        cwe_ids=["CWE-22"],
        masvs_refs=["MASVS-PLATFORM-1"],
        references=_REF_PLT,
    ),
]
