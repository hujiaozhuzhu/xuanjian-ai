"""移动端安全报告回退数据模型。

共享数据模型 ``MobileSecurityReport`` 等可能由其他 Agent 并行开发于
``fp_sentinel.mobile_reporting.models``。本模块提供字段兼容的回退定义：

- 优先导入共享模型（若已存在则直接使用，保证单一事实来源）；
- 导入失败时使用本模块的 dataclass 定义；
- 生成器读取字段时全部通过 :func:`get_attr` 鸭子类型访问，两种来源均兼容。

同时提供 InsecureBankv2 靶场的示例报告构造器，供测试与演示使用。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

__all__ = [
    "Evidence",
    "ReproStep",
    "Screenshot",
    "Vulnerability",
    "TargetAppInfo",
    "MobileSecurityReport",
    "get_attr",
    "create_insecurebank_sample_report",
]


def get_attr(obj: Any, name: str, default: Any = None) -> Any:
    """以鸭子类型方式读取对象属性，``None`` 视为未提供并返回默认值。"""
    value = getattr(obj, name, default)
    return default if value is None else value


# ---------------------------------------------------------------------------
# 尝试导入并行开发的共享模型；失败时回退到本模块定义。
# ---------------------------------------------------------------------------
try:  # pragma: no cover - 取决于并行开发进度
    from ..models import (  # type: ignore[no-redef]  # noqa: F401
        Appendix,
        EnvironmentInfo,
        Evidence,
        ExpInfo,
        FindingReport,
        MobileSecurityReport,
        PocInfo,
        ReportMetadata,
        ReportStatistics,
        ReproStep,
        Screenshot,
        ScreenshotRef,
        TargetAppInfo,
        Vulnerability,
    )

    _USING_SHARED_MODELS = True
except ImportError:
    _USING_SHARED_MODELS = False

    @dataclass
    class Evidence:
        """漏洞证据：代码位置与内容。"""

        location: str = ""
        content: str = ""
        description: str = ""

    @dataclass
    class ReproStep:
        """复现步骤：操作 / 命令 / 期望结果 / 实际结果。"""

        action: str = ""
        command: str = ""
        expected: str = ""
        actual: str = ""

    @dataclass
    class Screenshot:
        """截图：文件路径与描述。"""

        path: str = ""
        description: str = ""

    @dataclass
    class Vulnerability:
        """单条移动安全漏洞。"""

        vuln_id: str = ""
        title: str = ""
        severity: str = "INFO"
        category: str = ""
        cwe: str = ""
        masvs: str = ""
        description: str = ""
        impact: str = ""
        components: List[str] = field(default_factory=list)
        evidence: List[Evidence] = field(default_factory=list)
        reproduction_steps: List[ReproStep] = field(default_factory=list)
        screenshots: List[Screenshot] = field(default_factory=list)
        poc: str = ""
        exp: str = ""
        fix_suggestions: List[str] = field(default_factory=list)
        references: List[str] = field(default_factory=list)

    @dataclass
    class TargetAppInfo:
        """目标应用基本信息。"""

        app_name: str = ""
        package_name: str = ""
        version_name: str = ""
        version_code: str = ""
        min_sdk: str = ""
        target_sdk: str = ""
        file_size: str = ""
        sha256: str = ""

    @dataclass
    class PocInfo:
        """POC 信息。"""

        id: str = ""
        name: str = ""
        type: str = "frida"
        script_path: str = ""
        script_content: str = ""
        safety_level: str = "SAFE"
        description: str = ""

    @dataclass
    class ExpInfo:
        """EXP 信息：前提 / 步骤 / 影响 / 缓解。"""

        id: str = ""
        name: str = ""
        preconditions: List[str] = field(default_factory=list)
        steps: List[str] = field(default_factory=list)
        impact: str = ""
        mitigation: str = ""

    @dataclass
    class EnvironmentInfo:
        """扫描环境信息。"""

        os: str = ""
        python_version: str = ""
        tool_versions: Dict[str, str] = field(default_factory=dict)
        target_app: Optional[TargetAppInfo] = None
        scan_time: str = ""
        scan_command: str = ""

    @dataclass
    class ReportStatistics:
        """报告统计：总数 / 严重度 / 分类 / 覆盖度 / 耗时。"""

        total_count: int = 0
        by_severity: Dict[str, int] = field(default_factory=dict)
        by_category: Dict[str, int] = field(default_factory=dict)
        coverage_metrics: Dict[str, Any] = field(default_factory=dict)
        scan_duration_seconds: float = 0.0

    @dataclass
    class ReportMetadata:
        """报告元信息：标题 / 作者 / 密级 / 版本 / 日期。"""

        title: str = "移动应用安全评估报告"
        author: str = "玄鉴AI (fp_sentinel)"
        classification: str = "内部资料"
        version: str = "V1.0"
        date: str = ""

    @dataclass
    class Appendix:
        """附录：术语表 / 工具链信息 / 原始日志引用。"""

        glossary: Dict[str, str] = field(default_factory=dict)
        toolchain_info: Dict[str, Any] = field(default_factory=dict)
        raw_logs_ref: str = ""

    @dataclass
    class MobileSecurityReport:
        """移动应用渗透测试报告聚合模型。"""

        title: str = "移动应用渗透测试报告"
        subtitle: str = "基于静态分析、动态调试与人工验证的综合性安全评估"
        company: str = "XX信息安全技术有限公司"
        classification: str = "内部资料"
        report_version: str = "V1.0"
        scan_date: str = ""
        test_start_time: str = ""
        test_end_time: str = ""
        project_background: str = ""
        test_scope: List[str] = field(default_factory=list)
        test_methods: List[str] = field(default_factory=list)
        target: Optional[TargetAppInfo] = None
        environment: Dict[str, str] = field(default_factory=dict)
        standard: str = "OWASP MASVS (Mobile Application Security Verification Standard) v2.0"
        vulnerabilities: List[Vulnerability] = field(default_factory=list)
        overall_assessment: str = ""
        cli_commands: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# InsecureBankv2 靶场示例报告（模拟数据，用于测试与演示）
# ---------------------------------------------------------------------------
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def create_insecurebank_sample_report() -> MobileSecurityReport:
    """构造 InsecureBankv2 靶场的模拟报告数据。

    Returns:
        MobileSecurityReport: 包含 5 条不同严重度漏洞的完整示例报告。
    """
    target = TargetAppInfo(
        app_name="InsecureBankv2",
        package_name="com.android.insecurebankv2",
        version_name="2.0",
        version_code="2",
        min_sdk="21",
        target_sdk="28",
        file_size="1.8 MB",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    vulns = [
        Vulnerability(
            vuln_id="VULN-001",
            title="硬编码凭据泄露",
            severity="CRITICAL",
            category="数据存储",
            cwe="CWE-798",
            masvs="MASVS-STORAGE-1",
            description=(
                "应用在反编译后的源码中存在硬编码的超级用户口令 superSecurePassword，"
                "攻击者无需任何权限即可从 APK 中提取该凭据并直接登录任意账户。"
            ),
            impact="任意攻击者可离线提取凭据并完全接管用户账户，造成资金损失与数据泄露。",
            components=["com.android.insecurebankv2.ChangePassword"],
            evidence=[
                Evidence(
                    location="com/android/insecurebankv2/ChangePassword.java:42",
                    content='private static final String PREF_SUPER_PASS = "superSecurePassword";',
                ),
            ],
            reproduction_steps=[
                ReproStep(
                    action="使用 apktool 反编译目标 APK",
                    command="apktool d InsecureBankv2.apk -o ib2_out",
                    expected="在 ib2_out/ 目录下生成 smali 与资源文件",
                    actual="反编译成功，生成 smali 目录",
                ),
                ReproStep(
                    action="全局搜索硬编码口令关键字",
                    command="grep -rn 'superSecurePassword' ib2_out/smali/",
                    expected="无敏感口令命中",
                    actual="在 ChangePassword.smali 中命中硬编码字符串",
                ),
            ],
            screenshots=[
                Screenshot(path="screenshots/vuln001_jadx.png", description="jadx 反编译视图中的硬编码口令"),
            ],
            poc=(
                "adb shell am start -n com.android.insecurebankv2/.LoginActivity\n"
                "# 使用提取的凭据登录\n"
                "# username: jack  password: Reset@123superSecurePassword"
            ),
            exp="",
            fix_suggestions=[
                "移除所有硬编码凭据，改用服务端认证",
                "引入 Android Keystore 安全存储口令派生密钥",
                "上线前使用自动化工具（如 MobSF）做硬编码扫描门禁",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/798.html",
                "https://mas.owasp.org/MASVS/05-MASVS-STORAGE/",
            ],
        ),
        Vulnerability(
            vuln_id="VULN-002",
            title="Content Provider 未授权访问",
            severity="HIGH",
            category="平台交互",
            cwe="CWE-926",
            masvs="MASVS-PLATFORM-1",
            description=(
                "TrackUserContentProvider 在 AndroidManifest.xml 中声明为 exported=true，"
                "且未设置任何权限保护，第三方应用可直接读写用户交易记录。"
            ),
            impact="恶意应用可静默读取用户轨迹数据，造成用户隐私批量泄露。",
            components=["com.android.insecurebankv2.TrackUserContentProvider"],
            evidence=[
                Evidence(
                    location="AndroidManifest.xml:31",
                    content=(
                        '<provider android:name="TrackUserContentProvider" '
                        'android:exported="true" />'
                    ),
                ),
            ],
            reproduction_steps=[
                ReproStep(
                    action="解析 AndroidManifest 确认 provider 导出状态",
                    command=(
                        "aapt dump xmltree InsecureBankv2.apk AndroidManifest.xml"
                        " | grep provider"
                    ),
                    expected="业务 provider 未导出或受权限保护",
                    actual="TrackUserContentProvider exported=true 且无 permission 属性",
                ),
            ],
            screenshots=[
                Screenshot(
                    path="screenshots/vuln002_provider.png",
                    description="Manifest 中 provider 导出配置",
                ),
            ],
            poc=(
                "adb shell content query --uri "
                "content://com.android.insecurebankv2."
                "TrackUserContentProvider/trackerdata"
            ),
            exp="",
            fix_suggestions=[
                "将 android:exported 显式置为 false",
                "如必须导出，为 provider 配置 signature 级权限",
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/926.html",
            ],
        ),
        Vulnerability(
            vuln_id="VULN-003",
            title="弱加密算法（AES/ECB 模式）",
            severity="MEDIUM",
            category="密码学",
            cwe="CWE-327",
            masvs="MASVS-CRYPTO-1",
            description=(
                "CryptoClass 使用 AES/ECB/PKCS5Padding 模式加密敏感数据，"
                "相同明文块加密后产生相同密文，可被密文模式分析攻击恢复明文。"
            ),
            impact="攻击者可在已知部分明文的条件下推断其余加密字段内容。",
            components=["com.android.insecurebankv2.CryptoClass"],
            evidence=[
                Evidence(
                    location="com/android/insecurebankv2/CryptoClass.java:18",
                    content='Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");',
                ),
            ],
            reproduction_steps=[
                ReproStep(
                    action="搜索 Cipher.getInstance 调用点",
                    command="grep -rn 'Cipher.getInstance' ib2_out/smali/",
                    expected="全部使用 GCM/CBC 等安全模式",
                    actual="命中 ECB 模式调用",
                ),
            ],
            screenshots=[],
            poc="frida -U -f com.android.insecurebankv2 -l hook_cipher.js",
            exp="",
            fix_suggestions=["改用 AES/GCM/NoPadding 并随机生成 IV"],
            references=["https://cwe.mitre.org/data/definitions/327.html"],
        ),
        Vulnerability(
            vuln_id="VULN-004",
            title="应用可调试（debuggable=true）",
            severity="LOW",
            category="应用配置",
            cwe="CWE-489",
            masvs="MASVS-RESILIENCE-2",
            description="发布版 APK 的 AndroidManifest 中 android:debuggable 属性为 true，攻击者可附加调试器篡改运行时逻辑。",
            impact="降低逆向与运行时篡改的攻击成本，放大其他漏洞的危害。",
            components=["AndroidManifest.xml"],
            evidence=[
                Evidence(
                    location="AndroidManifest.xml:7",
                    content='android:debuggable="true"',
                ),
            ],
            reproduction_steps=[
                ReproStep(
                    action="检查 Manifest 的 debuggable 属性",
                    command="aapt dump badging InsecureBankv2.apk | grep debuggable",
                    expected="无 debuggable 标记",
                    actual="package: ... debuggable",
                ),
            ],
            screenshots=[],
            poc="adb shell run-as com.android.insecurebankv2 ls databases/",
            exp="",
            fix_suggestions=["发布构建中移除 debuggable 或使用 release 签名配置"],
            references=["https://cwe.mitre.org/data/definitions/489.html"],
        ),
        Vulnerability(
            vuln_id="VULN-005",
            title="日志信息泄露",
            severity="INFO",
            category="数据存储",
            cwe="CWE-532",
            masvs="MASVS-STORAGE-3",
            description="应用在 Log.d/Log.i 中输出用户名与登录状态等敏感信息，可被同一设备上的恶意应用读取（API<16）或通过 logcat 泄露。",
            impact="敏感信息经由系统日志外泄，辅助攻击者完成账户枚举与会话劫持。",
            components=["com.android.insecurebankv2.LoginActivity"],
            evidence=[
                Evidence(
                    location="com/android/insecurebankv2/LoginActivity.java:57",
                    content='Log.d("LoginActivity", "User logged in: " + username);',
                ),
            ],
            reproduction_steps=[
                ReproStep(
                    action="监听设备日志并触发登录",
                    command="adb logcat -s LoginActivity",
                    expected="日志中无敏感字段",
                    actual="日志输出用户名与登录成功状态",
                ),
            ],
            screenshots=[],
            poc="adb logcat -d | grep -E 'password|username'",
            exp="",
            fix_suggestions=["发布版关闭全部日志输出（ProGuard 移除或封装日志开关）"],
            references=["https://cwe.mitre.org/data/definitions/532.html"],
        ),
    ]
    vulns.sort(key=lambda v: _SEVERITY_RANK.get(get_attr(v, "severity", "INFO").upper(), 99))
    return MobileSecurityReport(
        vulnerabilities=vulns,
        title="InsecureBankv2 移动应用渗透测试报告",
        subtitle="基于静态分析、动态调试与人工验证的综合性安全评估",
        company="玄鉴信息安全技术有限公司",
        classification="内部资料",
        report_version="V4.0",
        scan_date="2025-01-15",
        test_start_time="2025-01-13 09:00",
        test_end_time="2025-01-15 18:00",
        project_background=(
            "InsecureBankv2 为内部移动安全培训靶场应用。本次测试旨在验证玄鉴 v4.0 "
            "移动端自动化渗透测试能力，并对靶场已知漏洞进行全量覆盖检出与风险评估。"
        ),
        test_scope=[
            "com.android.insecurebankv2（APK 静态与动态分析）",
            "AndroidManifest.xml 组件导出配置",
            "应用数据存储与网络通信安全",
        ],
        test_methods=["静态分析（反编译 + 规则/语义扫描）", "动态调试（Frida Hook + logcat 监控）", "人工验证（证据归因与复现）"],
        target=target,
        environment={
            "操作系统": "Windows 10 Pro 22H2 (Build 19045)",
            "Python": "3.12.13",
            "apktool": "2.9.3",
            "jadx": "1.4.7",
            "Frida": "16.5.6",
            "MobSF": "3.9.2",
        },
        overall_assessment=(
            "本次测试共发现 5 个安全问题，其中严重 1 个、高危 1 个、中危 1 个、"
            "低危 1 个、提示 1 个。目标应用存在硬编码凭据与未授权 Content Provider "
            "等可直接利用的高风险问题，总体风险评级为高风险，建议立即启动修复。"
        ),
        cli_commands=[
            "fp_sentinel insight scan test_apps/InsecureBankv2.apk --sensitive",
            "fp_sentinel mobile-hook scan test_apps/InsecureBankv2.apk --keyword password",
            "fp_sentinel mobile-poc gen --apk test_apps/InsecureBankv2.apk --vuln VULN-001",
            "fp_sentinel mobile-shell dump test_apps/InsecureBankv2.apk --tool blackdex",
        ],
    )
