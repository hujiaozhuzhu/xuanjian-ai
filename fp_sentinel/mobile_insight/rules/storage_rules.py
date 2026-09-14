"""存储安全规则(11 条) —— 本地数据明文落盘/权限过宽/日志泄露/SQL 注入。

Round 2（RD-005）: 新增 ST-009 SQL 注入拼接; ST-007 硬编码凭证改为
"孤立字面量"检测（DEX 字符串池无 key=value 上下文）。
Round 3（NEW-01/05）: ST-007 重写为凭证证据分级（L3/L2/L1，动态定级）;
新增 ST-010 debuggable（CWE-486）与 ST-011 allowBackup（CWE-530）。
"""

from __future__ import annotations

from typing import List, Optional

from ..core.engine import Rule
from ..models.insight import DifficultyLevel, InsightCategory, Severity
from .context_filters import find_password_literals

_CAT = InsightCategory.STORAGE
_REF_STO = ["https://mas.owasp.org/MASVS/05-masvs-maswe/"]


def _credential_severity(evidence: List[str]) -> Optional[Severity]:
    """NEW-01: 依据 [LEVELn] 证据前缀动态定级 ST-007。

    任一 LEVEL3 证据 → CRITICAL; 否则 LEVEL2 → HIGH; 仅 LEVEL1 → MEDIUM;
    无已知前缀（不应发生，LEVEL0 不入证据）→ None 沿用静态级别。
    """
    levels = {
        "[LEVEL3]": Severity.CRITICAL,
        "[LEVEL2]": Severity.HIGH,
        "[LEVEL1]": Severity.MEDIUM,
    }
    for prefix, sev in levels.items():
        if any(prefix in item for item in evidence):
            return sev
    return None

RULES = [
    Rule(
        id="ST-001",
        title="SharedPreferences 明文存储敏感数据",
        category=_CAT,
        severity=Severity.HIGH,
        confidence=0.85,
        patterns=[r"getSharedPreferences", r"SharedPreferences"],
        check=lambda ctx: (
            ctx.find_evidence(r"SharedPreferences", limit=3)
            if ctx.has_signal(r"(password|passwd|token|secret|session)")
            else []
        ),
        description="SharedPreferences 与敏感字段同时出现, 未加密落盘可被 root 设备直接读取。",
        technical_context="Hook SharedPreferences.putString/getString 观察写入键值(只读)。",
        suggested_technique="basic-hook(SharedPreferences.putString)",
        next_steps=["确认写入的敏感键", "修复: 改用 EncryptedSharedPreferences"],
        cwe_ids=["CWE-312"],
        masvs_refs=["MASVS-STORAGE-1"],
        references=_REF_STO,
        auto_fixable=False,
        fix_hint="使用 androidx.security.crypto.EncryptedSharedPreferences",
    ),
    Rule(
        id="ST-002",
        title="MODE_WORLD_READABLE/WRITABLE 世界可读写",
        category=_CAT,
        severity=Severity.CRITICAL,
        confidence=0.95,
        patterns=[r"MODE_WORLD_READABLE", r"MODE_WORLD_WRITABLE"],
        description="文件以世界可读写模式创建, 任意应用可读取/篡改本应用数据。",
        technical_context="Hook Context.openFileOutput/SharedPreferences 模式参数确认。",
        suggested_technique="basic-hook(openFileOutput)",
        next_steps=["定位全部世界可读写文件操作", "修复: 使用 MODE_PRIVATE"],
        cwe_ids=["CWE-732"],
        masvs_refs=["MASVS-STORAGE-1"],
        references=_REF_STO,
        auto_fixable=True,
        fix_hint="MODE_WORLD_READABLE 已在 API 24+ 抛异常, 改用 MODE_PRIVATE",
    ),
    Rule(
        id="ST-003",
        title="SQLite 明文数据库存储敏感数据",
        category=_CAT,
        severity=Severity.HIGH,
        confidence=0.8,
        patterns=[r"SQLiteOpenHelper", r"SQLiteDatabase", r"rawQuery|execSQL"],
        check=lambda ctx: (
            ctx.find_evidence(r"SQLite", limit=3)
            if ctx.has_signal(r"(password|passwd|token|creditcard|card_no)")
            else []
        ),
        description="SQLite 与敏感字段同时出现, 疑似明文建表存储; root/备份提取即可读取。",
        technical_context="Hook execSQL/rawQuery 观察建表与查询语句(只读)。",
        suggested_technique="basic-hook(SQLiteDatabase.execSQL)",
        next_steps=["dump 数据库确认明文列", "修复: 使用 SQLCipher 或字段级加密"],
        cwe_ids=["CWE-312"],
        masvs_refs=["MASVS-STORAGE-2"],
        references=_REF_STO,
    ),
    Rule(
        id="ST-004",
        title="敏感数据写入外部存储",
        category=_CAT,
        severity=Severity.HIGH,
        confidence=0.85,
        patterns=[r"getExternalStorageDirectory", r"Environment\.getExternal", r"getExternalFilesDir"],
        check=lambda ctx: (
            ctx.find_evidence(r"getExternal", limit=3)
            if ctx.has_signal(r"(password|passwd|token|secret|log|dump)")
            else []
        ),
        description="疑似将数据落盘到外部存储; 外部存储在未 Root 设备上也可能被读取(共享存储)。",
        technical_context="Hook File 构造/写入点确认文件路径与内容。",
        suggested_technique="basic-hook(FileOutputStream)",
        next_steps=["枚举外部存储写入点", "修复: 敏感数据仅存内部存储并加密"],
        cwe_ids=["CWE-922"],
        masvs_refs=["MASVS-STORAGE-2"],
        references=_REF_STO,
    ),
    Rule(
        id="ST-005",
        title="调试日志输出敏感数据",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.85,
        patterns=[r"Log\.[dveiw]\s*\(", r"android\.util\.Log\.[dveiw]\b"],
        check=lambda ctx: (
            ctx.find_evidence(r"Log\.[dveiw]|android\.util\.Log\.[dveiw]", limit=3)
            if ctx.has_signal(r"(password|passwd|secret|token|session|cookie|username)")
            and ctx.has_signal(r"Log\.[dveiw]|android\.util\.Log\.[dveiw]")
            else []
        ),
        description="日志调用与敏感字段同时出现, logcat 输出可泄露 Token/口令。",
        technical_context="Hook android.util.Log 打印调用栈确认泄露点(隐雾技法④)。",
        suggested_technique="callstack-trace(Log.d)",
        next_steps=["确认日志是否输出敏感值", "修复: 发布版关闭日志/使用脱敏工具"],
        cwe_ids=["CWE-532"],
        masvs_refs=["MASVS-STORAGE-1"],
        references=_REF_STO,
    ),
    Rule(
        id="ST-006",
        title="敏感数据写入剪贴板",
        category=_CAT,
        severity=Severity.LOW,
        confidence=0.75,
        patterns=[r"ClipboardManager", r"setPrimaryClip", r"setText\s*\(.*clip"],
        check=lambda ctx: (
            ctx.find_evidence(r"Clipboard", limit=3)
            if ctx.has_signal(r"(password|passwd|token|card)")
            else []
        ),
        description="疑似将口令/卡号等写入剪贴板, 其它应用可读取剪贴板内容。",
        technical_context="Hook ClipboardManager.setPrimaryClip 观察写入内容。",
        suggested_technique="basic-hook(setPrimaryClip)",
        next_steps=["确认剪贴板写入内容", "修复: 避免复制敏感明文, 设置剪贴板过期"],
        cwe_ids=["CWE-200"],
        masvs_refs=["MASVS-STORAGE-1"],
        references=_REF_STO,
    ),
    Rule(
        id="ST-007",
        title="硬编码凭证(口令/API Key)",
        category=_CAT,
        severity=Severity.CRITICAL,
        confidence=0.85,
        patterns=[
            r"(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",
            r"(?i)(password|passwd|pwd|secret|credential|token)[A-Za-z0-9_@#$%!?*=./+-]{5,}",
        ],
        check=lambda ctx: find_password_literals(ctx),
        dynamic_severity=_credential_severity,
        description=(
            "检测到硬编码凭证形态字符串, 静态反编译即可提取。证据按可信度分级: "
            "LEVEL3=口令变量名+非占位明文赋值, LEVEL2=Base64 解码含敏感词, "
            "LEVEL1=已知密钥前缀(sk-/ghp_/AIza/eyJ…)。"
        ),
        technical_context="结合反编译字符串表逐条确认; 伪造凭证登录即可验证危害。",
        suggested_technique="string-dump(凭证构造点)",
        next_steps=["在源码中定位每处硬编码凭证", "修复: 凭证服务端化/使用 Keystore"],
        cwe_ids=["CWE-798"],
        masvs_refs=["MASVS-STORAGE-1"],
        references=_REF_STO,
    ),
    Rule(
        id="ST-008",
        title="Toast 输出敏感信息",
        category=_CAT,
        severity=Severity.LOW,
        confidence=0.7,
        patterns=[r"Toast\.makeText"],
        check=lambda ctx: (
            ctx.find_evidence(r"Toast", limit=3)
            if ctx.has_signal(r"(token|password|passwd|success|fail.*(login|auth))")
            else []
        ),
        description="Toast 与鉴权/敏感词同时出现, UI 提示可能泄露登录态或业务细节(亦是隐雾技法③的定位入口)。",
        technical_context="Hook Toast.makeText 打印调用栈可回溯业务逻辑(隐雾技法③)。",
        suggested_technique="callstack-trace(Toast.makeText)",
        next_steps=["确认 Toast 文案是否含敏感信息", "修复: 移除敏感细节提示"],
        cwe_ids=["CWE-532"],
        masvs_refs=["MASVS-STORAGE-1"],
        references=_REF_STO,
    ),
    Rule(
        id="ST-009",
        title="SQL 注入风险(字符串拼接 SQL)",
        category=_CAT,
        severity=Severity.HIGH,
        confidence=0.8,
        patterns=[r"rawQuery|execSQL|compileStatement", r"SELECT|INSERT|UPDATE|DELETE"],
        check=lambda ctx: (
            ctx.find_evidence(r"rawQuery|execSQL|compileStatement", limit=3)
            if ctx.has_signal(r"rawQuery|execSQL|compileStatement")
            and ctx.has_signal(r"\b(SELECT|INSERT|UPDATE|DELETE)\b")
            else []
        ),
        description="检测到 SQL 执行 API 与 SQL 关键字同时出现, 若语句由字符串拼接而成则存在注入面。",
        technical_context="Hook execSQL/rawQuery 打印实参 SQL, 确认是否拼接外部输入(如密码/用户名)。",
        suggested_technique="basic-hook(SQLiteDatabase.execSQL)",
        next_steps=["定位拼接点确认输入来源", "修复: 参数化查询(?占位符)"],
        cwe_ids=["CWE-89"],
        masvs_refs=["MASVS-STORAGE-2"],
        references=_REF_STO,
    ),
    Rule(
        id="ST-010",
        title="发布版应用开启 debuggable 调试标志",
        category=_CAT,
        severity=Severity.CRITICAL,
        confidence=0.98,
        patterns=[r"debuggable"],
        check=lambda ctx: (
            ['android:debuggable="true" (application flag)']
            if ctx.manifest_flags.get("debuggable")
            else []
        ),
        description=(
            "Manifest 中 application 节点 android:debuggable=true, 任意调试器"
            "(jdb/adb) 可附加进程, dump 内存/注入代码/绕过鉴权, 危害等同 ROOT。"
        ),
        technical_context="debuggable=true 时可直接 attach jdb: `adb shell run-as <pkg>`; "
                          "配合 JDWP 断点观察敏感计算与网络明文。",
        suggested_technique="jdb-attach(debuggable)",
        next_steps=["`adb jdwp` 确认进程可调试", "修复: 发布版移除 debuggable 或依赖 buildType 配置"],
        cwe_ids=["CWE-486"],
        masvs_refs=["MASVS-RESILIENCE-2"],
        references=_REF_STO,
        auto_fixable=True,
        fix_hint="移除 android:debuggable=true（release 构建默认 false）",
        code_level=False,
    ),
    Rule(
        id="ST-011",
        title="allowBackup 开启导致数据可被提取",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.9,
        patterns=[r"allow_backup|allowBackup"],
        check=lambda ctx: (
            ['android:allowBackup="true" (application flag)']
            if ctx.manifest_flags.get("allow_backup")
            else []
        ),
        description=(
            "Manifest 中 application 节点 android:allowBackup=true, adb backup/"
            "云备份可提取应用私有数据（SharedPreferences/SQLite 中的凭证、Token）。"
        ),
        technical_context="`adb backup -apk <pkg>` 或 Android 12+ `adb backup` 提取备份数据, "
                          "结合 ST-001/ST-003 明文存储问题危害放大。",
        suggested_technique="adb-backup(数据提取)",
        next_steps=["`adb backup` 验证数据可提取性", "修复: 设置 allowBackup=false 或配置 backup_rules"],
        cwe_ids=["CWE-530"],
        masvs_refs=["MASVS-STORAGE-1"],
        references=_REF_STO,
        auto_fixable=True,
        fix_hint="android:allowBackup=false，或用 fullBackupContent 限定可备份文件",
        code_level=False,
    ),
]
