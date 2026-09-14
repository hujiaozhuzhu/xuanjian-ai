"""隐私合规规则(9 条) —— 个人信息采集/超范围收集/短信外发（参照《常见类型移动互联网
应用程序必要个人信息范围规定》与 MASVS-PRIVACY）。

Round 2（RD-005/RD-014）: 新增 PV-009 短信外发敏感数据（SEND_SMS 权限 +
sendTextMessage 调用点）; PV-004 文案区分“接收”与“读取”。
"""

from __future__ import annotations

from ..core.engine import Rule
from ..models.insight import DifficultyLevel, InsightCategory, Severity

_CAT = InsightCategory.PRIVACY
_REF_PRV = ["https://mas.owasp.org/MASVS/05-masvs-maswe/"]

RULES = [
    Rule(
        id="PV-001",
        title="采集设备标识 IMEI/MEID",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.9,
        patterns=[r"getDeviceId|getImei|getMeid", r"TelephonyManager"],
        description="检测到设备唯一标识(IMEI/MEID)采集。Android 10+ 已限制, 且属个人信息保护法规范畴。",
        technical_context="Hook TelephonyManager.getDeviceId/getImei 观察采集时机与上报目标。",
        suggested_technique="basic-hook(getDeviceId)",
        next_steps=["确认采集与隐私政策一致性", "评估是否可用 Android ID 替代"],
        cwe_ids=["CWE-359"],
        masvs_refs=["MASVS-PRIVACY-1"],
        references=_REF_PRV,
    ),
    Rule(
        id="PV-002",
        title="采集精确位置信息",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.85,
        patterns=[r"getLastKnownLocation|requestLocationUpdates", r"LocationManager|FusedLocationProvider"],
        description="检测到位置信息采集, 需确认是否超出业务必要范围并取得明示同意。",
        technical_context="Hook LocationManager 观察采集频率与上报链路。",
        suggested_technique="basic-hook(requestLocationUpdates)",
        next_steps=["核对隐私政策位置条款", "评估采集频率合理性"],
        cwe_ids=["CWE-359"],
        masvs_refs=["MASVS-PRIVACY-1"],
        references=_REF_PRV,
    ),
    Rule(
        id="PV-003",
        title="读取通讯录",
        category=_CAT,
        severity=Severity.HIGH,
        confidence=0.95,
        patterns=[r"READ_CONTACTS", r"ContactsContract"],
        description="检测到通讯录读取能力与实现, 属高敏个人信息, 超范围收集是监管通报高频问题。",
        technical_context="Hook ContentResolver.query(ContactsContract) 确认实际读取行为。",
        suggested_technique="basic-hook(ContentResolver.query)",
        next_steps=["确认业务是否必需", "无明确必要场景建议移除"],
        cwe_ids=["CWE-359"],
        masvs_refs=["MASVS-PRIVACY-1"],
        references=_REF_PRV,
    ),
    Rule(
        id="PV-004",
        title="短信/通话记录权限申请(接收/读取)",
        category=_CAT,
        severity=Severity.HIGH,
        confidence=0.95,
        patterns=[r"READ_SMS|RECEIVE_SMS", r"READ_CALL_LOG|CallLog"],
        description="检测到短信/通话记录权限(RECEIVE_SMS 为接收, READ_SMS 为读取), 除验证码类场景外极易构成超范围收集。",
        technical_context="Hook SmsMessage/CallLog 相关读取点确认采集内容。",
        suggested_technique="basic-hook(SmsManager)",
        next_steps=["确认是否仅用于验证码自动填充", "移除非必要读取"],
        cwe_ids=["CWE-359"],
        masvs_refs=["MASVS-PRIVACY-1"],
        references=_REF_PRV,
    ),
    Rule(
        id="PV-005",
        title="摄像头/麦克风访问",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.85,
        patterns=[r"CAMERA", r"RECORD_AUDIO", r"Camera\.open|openCamera", r"MediaRecorder"],
        description="检测到摄像头/麦克风采集能力, 需与业务功能逐项对齐避免静默采集。",
        technical_context="Hook Camera.open/openCamera 与 MediaRecorder.start 确认调用时机。",
        suggested_technique="callstack-trace(openCamera)",
        next_steps=["确认权限使用场景", "检查前台服务采集提示"],
        cwe_ids=["CWE-359"],
        masvs_refs=["MASVS-PRIVACY-1"],
        references=_REF_PRV,
    ),
    Rule(
        id="PV-006",
        title="获取已安装应用列表",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.9,
        patterns=[r"getInstalledPackages|getInstalledApplications", r"QUERY_ALL_PACKAGES"],
        description="检测到已安装应用列表枚举能力, 属设备画像信息, 工信部通报高频项。",
        technical_context="Hook PackageManager.getInstalledPackages 观察调用目的。",
        suggested_technique="basic-hook(getInstalledPackages)",
        next_steps=["确认是否仅用于防多开/风控", "无必要场景移除 QUERY_ALL_PACKAGES"],
        cwe_ids=["CWE-359"],
        masvs_refs=["MASVS-PRIVACY-1"],
        references=_REF_PRV,
    ),
    Rule(
        id="PV-007",
        title="采集 MAC 地址",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.9,
        patterns=[r"getHardwareAddress|WifiManager.*connectionInfo|getAddress\(\)", r"BLUETOOTH.*getAddress"],
        description="检测到 MAC 地址采集路径, Android 6+ 已随机化但应用内仍可能通过特权接口获取。",
        technical_context="Hook WifiManager.getConnectionInfo 打印返回内容。",
        suggested_technique="basic-hook(getConnectionInfo)",
        next_steps=["确认采集用途", "改用 Android ID 并脱敏"],
        cwe_ids=["CWE-359"],
        masvs_refs=["MASVS-PRIVACY-1"],
        references=_REF_PRV,
    ),
    Rule(
        id="PV-008",
        title="过度权限申请(权限组合超范围)",
        category=_CAT,
        severity=Severity.MEDIUM,
        confidence=0.75,
        patterns=[r"android\.permission\.(CAMERA|RECORD_AUDIO|READ_CONTACTS|READ_SMS|ACCESS_FINE_LOCATION)"],
        check=lambda ctx: (
            ctx.find_evidence(r"android\.permission\.", limit=5)
            if len({p for p in ctx.permissions
                    if p in {"android.permission.CAMERA", "android.permission.RECORD_AUDIO",
                             "android.permission.READ_CONTACTS", "android.permission.READ_SMS",
                             "android.permission.ACCESS_FINE_LOCATION"}}) >= 3
            else []
        ),
        description="同时申请 3 项及以上高敏权限(相机/录音/通讯录/短信/精确定位), 疑似超出业务必要范围。",
        technical_context="对照《必要个人信息范围规定》逐项核对权限与功能映射。",
        suggested_technique="basic-hook(权限申请点)",
        next_steps=["生成权限-功能映射表", "移除无对应功能的权限声明"],
        cwe_ids=["CWE-250"],
        masvs_refs=["MASVS-PRIVACY-1"],
        references=_REF_PRV,
    ),
    Rule(
        id="PV-009",
        title="短信外发敏感数据(SEND_SMS + sendTextMessage)",
        category=_CAT,
        severity=Severity.HIGH,
        confidence=0.9,
        patterns=[r"sendTextMessage|SmsManager", r"SEND_SMS"],
        check=lambda ctx: (
            ctx.find_evidence(r"sendTextMessage|SmsManager", limit=3)
            if ctx.has_signal(r"sendTextMessage|SmsManager")
            and ("android.permission.SEND_SMS" in ctx.permissions
                 or ctx.has_signal(r"SEND_SMS"))
            else []
        ),
        description="检测到发送短信 API 与 SEND_SMS 权限同时存在, 若发送内容含凭据/验证码则存在凭据外发风险。",
        technical_context="Hook SmsManager.sendTextMessage 观察目的号码与正文内容(授权测试)。",
        suggested_technique="basic-hook(SmsManager.sendTextMessage)",
        next_steps=["定位短信发送点确认正文内容", "若含凭据: 改 HTTPS 上报并移除短信通道"],
        cwe_ids=["CWE-200", "CWE-359"],
        masvs_refs=["MASVS-PRIVACY-1"],
        references=_REF_PRV,
    ),
]
