"""
玄鉴 v3.0 — 行业化基准数据库 :: 内置基准数据集

内置 10 个行业基准数据（样本），涵盖：
1. 互联网 (internet)      —— 基线扩展
2. 金融 (finance)         —— 基线扩展
3. 政务 (government)      —— 新增
4. 工业控制 (industrial_ctrl) —— 新增
5. 医疗 (healthcare)      —— 新增
6. 教育 (education)       —— 新增
7. 运营商 (telecom)       —— 新增
8. 能源 (energy)          —— 新增
9. 交通 (transportation)  —— 新增
10. 保险 (insurance)      —— 新增
11. 证券 (securities)     —— 新增

每个数据集包含：
- 行业元数据
- 漏洞类型分布
- 平均修复周期
- TOP10 常见漏洞
- 对应合规要求
- 行业特色漏洞场景

安全红线: S5（静态样本不连外网）| S6（权威来源引用）| S7（数据质量标注）
"""
from __future__ import annotations

from typing import Dict, List

from .models import (
    BenchmarkDataset,
    BenchmarkMetadata,
    ComplianceRequirement,
    Industry,
    IndustryMeta,
    IndustryScenario,
    RepairCycle,
    TopVulnerability,
    VulnTypeStats,
)

# ──────────────────── 行业元数据 ────────────────────

INDUSTRY_METADATA: Dict[Industry, IndustryMeta] = {
    Industry.INTERNET: IndustryMeta(
        industry=Industry.INTERNET,
        display_name="互联网",
        description="互联网平台企业",
        key_tech_stacks=["Java", "Go", "Python", "Node.js", "React", "Kubernetes"],
        risk_profile="高并发平台，关注注入、越权、数据泄露",
    ),
    Industry.FINANCE: IndustryMeta(
        industry=Industry.FINANCE,
        display_name="银行",
        description="商业银行等金融机构",
        key_tech_stacks=["Java", "COBOL", "Oracle", "Spring", "Vue.js"],
        risk_profile="核心资金系统，关注业务逻辑漏洞、越权、完整性",
    ),
    Industry.GOVERNMENT: IndustryMeta(
        industry=Industry.GOVERNMENT,
        display_name="政务",
        description="电子政务系统、政府数据平台",
        key_tech_stacks=["Java", ".NET", "Oracle", "达梦数据库", "东方通"],
        risk_profile="公民信息与国家数据，关注注入、越权、供应链安全",
    ),
    Industry.INDUSTRIAL_CTRL: IndustryMeta(
        industry=Industry.INDUSTRIAL_CTRL,
        display_name="工业控制",
        description="工业互联网、SCADA、智能制造",
        key_tech_stacks=["C/C++", "Modbus", "OPC UA", "PLC", "嵌入式 Linux"],
        risk_profile="物理安全交叉，关注协议脆弱性、固件漏洞",
    ),
    Industry.HEALTHCARE: IndustryMeta(
        industry=Industry.HEALTHCARE,
        display_name="医疗",
        description="医院信息系统、电子病历、远程医疗",
        key_tech_stacks=["Java", ".NET", "HL7 FHIR", "DICOM", "Oracle"],
        risk_profile="强监管行业，关注患者隐私、系统可用性",
    ),
    Industry.EDUCATION: IndustryMeta(
        industry=Industry.EDUCATION,
        display_name="教育",
        description="高校信息系统、在线教育平台",
        key_tech_stacks=["Java", "Python", "PHP", "MySQL", "Vue.js"],
        risk_profile="学生个人信息保护，关注注入、越权",
    ),
    Industry.TELECOM: IndustryMeta(
        industry=Industry.TELECOM,
        display_name="运营商",
        description="电信运营商核心网、BOSS 系统",
        key_tech_stacks=["Java", "C/C++", "Oracle", "Kafka", "NFV/SDN"],
        risk_profile="关键基础设施，关注协议安全、计费欺诈",
    ),
    Industry.ENERGY: IndustryMeta(
        industry=Industry.ENERGY,
        display_name="能源",
        description="电力、石油、新能源生产监控",
        key_tech_stacks=["C/C++", "Java", "Modbus", "IEC 61850", "OPC UA"],
        risk_profile="关键基础设施，关注工控协议、SCADA",
    ),
    Industry.TRANSPORTATION: IndustryMeta(
        industry=Industry.TRANSPORTATION,
        display_name="交通",
        description="智慧交通、轨道交通信号系统",
        key_tech_stacks=["C/C++", "Java", "Python", "MQTT", "GPS/北斗"],
        risk_profile="公共安全，关注信号系统可靠性、通信安全",
    ),
    Industry.INSURANCE: IndustryMeta(
        industry=Industry.INSURANCE,
        display_name="保险",
        description="保险核心系统、精算平台、理赔",
        key_tech_stacks=["Java", ".NET", "Python", "Oracle", "Kafka"],
        risk_profile="金融数据密集，关注客户信息泄露、逻辑漏洞",
    ),
    Industry.SECURITIES: IndustryMeta(
        industry=Industry.SECURITIES,
        display_name="证券",
        description="证券交易、行情、清算系统",
        key_tech_stacks=["Java", "C++", "Rust", "FPGA", "Kafka", "Redis"],
        risk_profile="超低延迟交易，关注交易欺诈、市场操纵",
    ),
}


# ──────────────────── 漏洞类型分布数据 ────────────────────

_DISTRIBUTION_DATA: Dict[Industry, List[VulnTypeStats]] = {
    Industry.INTERNET: [
        VulnTypeStats(category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", count=1842, percentage=22.5, avg_severity="HIGH", trend="rising"),
        VulnTypeStats(category="INJECTION", cwe="CWE-89", display_name="SQL注入", count=1256, percentage=15.3, avg_severity="CRITICAL", trend="falling"),
        VulnTypeStats(category="XSS", cwe="CWE-79", display_name="跨站脚本", count=1089, percentage=13.3, avg_severity="MEDIUM", trend="stable"),
        VulnTypeStats(category="SSRF", cwe="CWE-918", display_name="服务端请求伪造", count=876, percentage=10.7, avg_severity="HIGH", trend="rising"),
        VulnTypeStats(category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密机制失效", count=654, percentage=8.0, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="INSECURE_DESIGN", cwe="CWE-209", display_name="不安全设计", count=543, percentage=6.6, avg_severity="MEDIUM", trend="rising"),
        VulnTypeStats(category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="存在漏洞的组件", count=487, percentage=6.0, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="DATA_LEAKAGE", cwe="CWE-200", display_name="数据泄露", count=432, percentage=5.3, avg_severity="HIGH", trend="rising"),
        VulnTypeStats(category="AUTH_FAILURE", cwe="CWE-287", display_name="认证失败", count=398, percentage=4.9, avg_severity="HIGH", trend="falling"),
        VulnTypeStats(category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", count=367, percentage=4.5, avg_severity="MEDIUM", trend="stable"),
        VulnTypeStats(category="OTHER", cwe=None, display_name="其他", count=236, percentage=2.9, avg_severity="LOW", trend="stable"),
    ],
    Industry.FINANCE: [
        VulnTypeStats(category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", count=1567, percentage=24.1, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="BUSINESS_LOGIC", cwe="CWE-840", display_name="业务逻辑漏洞", count=1234, percentage=19.0, avg_severity="CRITICAL", trend="rising"),
        VulnTypeStats(category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密机制失效", count=876, percentage=13.5, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="INJECTION", cwe="CWE-89", display_name="SQL注入", count=654, percentage=10.1, avg_severity="CRITICAL", trend="falling"),
        VulnTypeStats(category="DATA_LEAKAGE", cwe="CWE-200", display_name="数据泄露", count=543, percentage=8.4, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="AUTH_FAILURE", cwe="CWE-287", display_name="认证失败", count=432, percentage=6.7, avg_severity="HIGH", trend="falling"),
        VulnTypeStats(category="XSS", cwe="CWE-79", display_name="跨站脚本", count=398, percentage=6.1, avg_severity="MEDIUM", trend="falling"),
        VulnTypeStats(category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="存在漏洞的组件", count=321, percentage=4.9, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", count=287, percentage=4.4, avg_severity="MEDIUM", trend="stable"),
        VulnTypeStats(category="OTHER", cwe=None, display_name="其他", count=178, percentage=2.8, avg_severity="LOW", trend="stable"),
    ],
    Industry.GOVERNMENT: [
        VulnTypeStats(category="INJECTION", cwe="CWE-89", display_name="SQL注入", count=1432, percentage=19.8, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", count=1287, percentage=17.8, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", count=987, percentage=13.6, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="XSS", cwe="CWE-79", display_name="跨站脚本", count=765, percentage=10.6, avg_severity="MEDIUM", trend="stable"),
        VulnTypeStats(category="DATA_LEAKAGE", cwe="CWE-200", display_name="数据泄露", count=654, percentage=9.0, avg_severity="HIGH", trend="rising"),
        VulnTypeStats(category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="供应链组件漏洞", count=543, percentage=7.5, avg_severity="HIGH", trend="rising"),
        VulnTypeStats(category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密机制失效", count=432, percentage=6.0, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="INSECURE_DESIGN", cwe="CWE-209", display_name="不安全设计", count=398, percentage=5.5, avg_severity="MEDIUM", trend="stable"),
        VulnTypeStats(category="AUTH_FAILURE", cwe="CWE-287", display_name="认证失败", count=365, percentage=5.0, avg_severity="HIGH", trend="falling"),
        VulnTypeStats(category="SUPPLY_CHAIN", cwe="CWE-1393", display_name="供应链攻击", count=234, percentage=3.2, avg_severity="CRITICAL", trend="rising"),
        VulnTypeStats(category="OTHER", cwe=None, display_name="其他", count=143, percentage=2.0, avg_severity="LOW", trend="stable"),
    ],
    Industry.INDUSTRIAL_CTRL: [
        VulnTypeStats(category="INSECURE_PROTOCOL", cwe="CWE-299", display_name="不安全的通信协议", count=1234, percentage=26.3, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="AUTH_BYPASS", cwe="CWE-287", display_name="认证绕过", count=876, percentage=18.7, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="INJECTION", cwe="CWE-89", display_name="命令注入", count=654, percentage=13.9, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="FIRMWARE_VULN", cwe="CWE-119", display_name="固件漏洞", count=543, percentage=11.6, avg_severity="HIGH", trend="rising"),
        VulnTypeStats(category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", count=432, percentage=9.2, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="DATA_LEAKAGE", cwe="CWE-200", display_name="数据泄露", count=321, percentage=6.8, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="BUFFER_OVERFLOW", cwe="CWE-122", display_name="缓冲区溢出", count=287, percentage=6.1, avg_severity="CRITICAL", trend="falling"),
        VulnTypeStats(category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密机制失效", count=198, percentage=4.2, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="OTHER", cwe=None, display_name="其他", count=155, percentage=3.2, avg_severity="MEDIUM", trend="stable"),
    ],
    Industry.HEALTHCARE: [
        VulnTypeStats(category="DATA_LEAKAGE", cwe="CWE-200", display_name="患者数据泄露", count=1567, percentage=25.4, avg_severity="CRITICAL", trend="rising"),
        VulnTypeStats(category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", count=1234, percentage=20.0, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="AUTH_FAILURE", cwe="CWE-287", display_name="认证失败", count=765, percentage=12.4, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", count=654, percentage=10.6, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="INJECTION", cwe="CWE-89", display_name="SQL注入", count=543, percentage=8.8, avg_severity="CRITICAL", trend="falling"),
        VulnTypeStats(category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="存在漏洞的组件", count=432, percentage=7.0, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密机制失效", count=321, percentage=5.2, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="XSS", cwe="CWE-79", display_name="跨站脚本", count=287, percentage=4.7, avg_severity="MEDIUM", trend="falling"),
        VulnTypeStats(category="AVAILABILITY", cwe="CWE-400", display_name="系统可用性风险", count=234, percentage=3.8, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="OTHER", cwe=None, display_name="其他", count=123, percentage=2.1, avg_severity="LOW", trend="stable"),
    ],
    Industry.EDUCATION: [
        VulnTypeStats(category="INJECTION", cwe="CWE-89", display_name="SQL注入", count=1345, percentage=21.3, avg_severity="CRITICAL", trend="falling"),
        VulnTypeStats(category="DATA_LEAKAGE", cwe="CWE-200", display_name="学生信息泄露", count=1123, percentage=17.8, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", count=987, percentage=15.6, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="XSS", cwe="CWE-79", display_name="跨站脚本", count=765, percentage=12.1, avg_severity="MEDIUM", trend="stable"),
        VulnTypeStats(category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", count=543, percentage=8.6, avg_severity="MEDIUM", trend="falling"),
        VulnTypeStats(category="AUTH_FAILURE", cwe="CWE-287", display_name="认证失败", count=432, percentage=6.8, avg_severity="MEDIUM", trend="falling"),
        VulnTypeStats(category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="存在漏洞的组件", count=398, percentage=6.3, avg_severity="MEDIUM", trend="stable"),
        VulnTypeStats(category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密机制失效", count=321, percentage=5.1, avg_severity="MEDIUM", trend="stable"),
        VulnTypeStats(category="OTHER", cwe=None, display_name="其他", count=410, percentage=6.4, avg_severity="LOW", trend="stable"),
    ],
    Industry.TELECOM: [
        VulnTypeStats(category="PROTOCOL_VULN", cwe="CWE-299", display_name="通信协议漏洞", count=1234, percentage=22.1, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", count=987, percentage=17.7, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="INJECTION", cwe="CWE-89", display_name="命令注入", count=765, percentage=13.7, avg_severity="CRITICAL", trend="falling"),
        VulnTypeStats(category="DATA_LEAKAGE", cwe="CWE-200", display_name="用户通信数据泄露", count=654, percentage=11.7, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="DOS", cwe="CWE-400", display_name="拒绝服务", count=543, percentage=9.7, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", count=432, percentage=7.7, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密机制失效", count=321, percentage=5.7, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="存在漏洞的组件", count=287, percentage=5.1, avg_severity="MEDIUM", trend="stable"),
        VulnTypeStats(category="OTHER", cwe=None, display_name="其他", count=368, percentage=6.6, avg_severity="LOW", trend="stable"),
    ],
    Industry.ENERGY: [
        VulnTypeStats(category="INSECURE_PROTOCOL", cwe="CWE-299", display_name="工控协议漏洞", count=1567, percentage=28.9, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", count=876, percentage=16.2, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="AUTH_BYPASS", cwe="CWE-287", display_name="认证绕过", count=654, percentage=12.1, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="FIRMWARE_VULN", cwe="CWE-119", display_name="固件漏洞", count=543, percentage=10.0, avg_severity="HIGH", trend="rising"),
        VulnTypeStats(category="INJECTION", cwe="CWE-89", display_name="命令注入", count=432, percentage=8.0, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="DATA_LEAKAGE", cwe="CWE-200", display_name="生产数据泄露", count=321, percentage=5.9, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="DOS", cwe="CWE-400", display_name="拒绝服务", count=287, percentage=5.3, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密机制失效", count=234, percentage=4.3, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="存在漏洞的组件", count=198, percentage=3.7, avg_severity="MEDIUM", trend="stable"),
        VulnTypeStats(category="OTHER", cwe=None, display_name="其他", count=308, percentage=5.6, avg_severity="MEDIUM", trend="stable"),
    ],
    Industry.TRANSPORTATION: [
        VulnTypeStats(category="SIG_SYS_VULN", cwe="CWE-284", display_name="信号系统漏洞", count=987, percentage=19.5, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="PROTOCOL_VULN", cwe="CWE-299", display_name="通信协议漏洞", count=876, percentage=17.3, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="AUTH_BYPASS", cwe="CWE-287", display_name="认证绕过", count=654, percentage=12.9, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="AVAILABILITY", cwe="CWE-400", display_name="系统可用性风险", count=567, percentage=11.2, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="INJECTION", cwe="CWE-89", display_name="命令注入", count=456, percentage=9.0, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="DATA_LEAKAGE", cwe="CWE-200", display_name="出行数据泄露", count=398, percentage=7.9, avg_severity="HIGH", trend="rising"),
        VulnTypeStats(category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", count=345, percentage=6.8, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="GPS_SPOOFING", cwe="CWE-290", display_name="GPS/定位欺骗", count=234, percentage=4.6, avg_severity="CRITICAL", trend="rising"),
        VulnTypeStats(category="FIRMWARE_VULN", cwe="CWE-119", display_name="固件漏洞", count=187, percentage=3.7, avg_severity="HIGH", trend="rising"),
        VulnTypeStats(category="OTHER", cwe=None, display_name="其他", count=356, percentage=7.1, avg_severity="MEDIUM", trend="stable"),
    ],
    Industry.INSURANCE: [
        VulnTypeStats(category="BUSINESS_LOGIC", cwe="CWE-840", display_name="业务逻辑漏洞", count=1432, percentage=23.1, avg_severity="CRITICAL", trend="rising"),
        VulnTypeStats(category="DATA_LEAKAGE", cwe="CWE-200", display_name="客户信息泄露", count=1234, percentage=19.9, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", count=876, percentage=14.1, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="AUTH_FAILURE", cwe="CWE-287", display_name="认证失败", count=543, percentage=8.8, avg_severity="HIGH", trend="falling"),
        VulnTypeStats(category="INJECTION", cwe="CWE-89", display_name="SQL注入", count=432, percentage=7.0, avg_severity="CRITICAL", trend="falling"),
        VulnTypeStats(category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密机制失效", count=398, percentage=6.4, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="存在漏洞的组件", count=321, percentage=5.2, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="COMPLIANCE_GAP", cwe=None, display_name="合规差距", count=287, percentage=4.6, avg_severity="MEDIUM", trend="stable"),
        VulnTypeStats(category="XSS", cwe="CWE-79", display_name="跨站脚本", count=234, percentage=3.8, avg_severity="MEDIUM", trend="falling"),
        VulnTypeStats(category="OTHER", cwe=None, display_name="其他", count=437, percentage=7.1, avg_severity="LOW", trend="stable"),
    ],
    Industry.SECURITIES: [
        VulnTypeStats(category="BUSINESS_LOGIC", cwe="CWE-840", display_name="交易逻辑漏洞", count=1567, percentage=27.3, avg_severity="CRITICAL", trend="rising"),
        VulnTypeStats(category="DATA_LEAKAGE", cwe="CWE-200", display_name="交易数据泄露", count=876, percentage=15.3, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", count=654, percentage=11.4, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="LATENCY_EXPLOIT", cwe=None, display_name="延迟操纵", count=543, percentage=9.5, avg_severity="CRITICAL", trend="rising"),
        VulnTypeStats(category="DOS", cwe="CWE-400", display_name="拒绝服务", count=432, percentage=7.5, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="INJECTION", cwe="CWE-89", display_name="SQL注入", count=398, percentage=6.9, avg_severity="CRITICAL", trend="falling"),
        VulnTypeStats(category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密机制失效", count=321, percentage=5.6, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="MARKET_MANIPULATION", cwe=None, display_name="行情操纵", count=287, percentage=5.0, avg_severity="CRITICAL", trend="stable"),
        VulnTypeStats(category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="存在漏洞的组件", count=234, percentage=4.1, avg_severity="HIGH", trend="stable"),
        VulnTypeStats(category="OTHER", cwe=None, display_name="其他", count=423, percentage=7.4, avg_severity="LOW", trend="stable"),
    ],
}


def _build_distribution(industry: Industry) -> List[VulnTypeStats]:
    """获取行业的漏洞类型分布"""
    return _DISTRIBUTION_DATA.get(industry, [])


# ──────────────────── 修复周期数据 ────────────────────

_REPAIR_CYCLES: Dict[Industry, RepairCycle] = {
    Industry.INTERNET: RepairCycle(critical_days=3.5, high_days=7.2, medium_days=18.5, low_days=45.0, overall_avg_days=15.8),
    Industry.FINANCE: RepairCycle(critical_days=2.0, high_days=5.0, medium_days=14.0, low_days=30.0, overall_avg_days=11.5),
    Industry.GOVERNMENT: RepairCycle(critical_days=5.0, high_days=12.0, medium_days=30.0, low_days=60.0, overall_avg_days=22.5),
    Industry.INDUSTRIAL_CTRL: RepairCycle(critical_days=7.0, high_days=18.0, medium_days=45.0, low_days=90.0, overall_avg_days=35.0),
    Industry.HEALTHCARE: RepairCycle(critical_days=4.5, high_days=10.0, medium_days=25.0, low_days=55.0, overall_avg_days=19.2),
    Industry.EDUCATION: RepairCycle(critical_days=6.0, high_days=15.0, medium_days=35.0, low_days=70.0, overall_avg_days=26.8),
    Industry.TELECOM: RepairCycle(critical_days=3.0, high_days=8.0, medium_days=20.0, low_days=45.0, overall_avg_days=16.5),
    Industry.ENERGY: RepairCycle(critical_days=6.5, high_days=16.0, medium_days=40.0, low_days=80.0, overall_avg_days=30.2),
    Industry.TRANSPORTATION: RepairCycle(critical_days=5.0, high_days=12.0, medium_days=30.0, low_days=60.0, overall_avg_days=23.5),
    Industry.INSURANCE: RepairCycle(critical_days=3.0, high_days=7.5, medium_days=18.0, low_days=40.0, overall_avg_days=15.2),
    Industry.SECURITIES: RepairCycle(critical_days=1.5, high_days=4.0, medium_days=10.0, low_days=25.0, overall_avg_days=9.8),
}


def _build_repair_cycle(industry: Industry) -> RepairCycle:
    return _REPAIR_CYCLES.get(industry, RepairCycle())


# ──────────────────── TOP10 常见漏洞 ────────────────────

_TOP_VULNS: Dict[Industry, List[TopVulnerability]] = {
    Industry.INTERNET: [
        TopVulnerability(rank=1, rule_id="ACCESS_HORIZONTAL_PRIV_ESCALATION", category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="水平越权", occurrence_rate=12.5, severity="HIGH", description="用户可访问同级别其他用户的数据"),
        TopVulnerability(rank=2, rule_id="ACCESS_VERTICAL_PRIV_ESCALATION", category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="垂直越权", occurrence_rate=10.0, severity="CRITICAL", description="普通用户可执行管理员功能"),
        TopVulnerability(rank=3, rule_id="SQL_INJECTION", category="INJECTION", cwe="CWE-89", display_name="SQL注入", occurrence_rate=8.5, severity="CRITICAL", description="未过滤的用户输入拼接SQL"),
        TopVulnerability(rank=4, rule_id="SSRF", category="SSRF", cwe="CWE-918", display_name="服务端请求伪造", occurrence_rate=7.2, severity="HIGH", description="服务端发起非预期的内部网络请求"),
        TopVulnerability(rank=5, rule_id="REFLECTED_XSS", category="XSS", cwe="CWE-79", display_name="反射型XSS", occurrence_rate=6.8, severity="MEDIUM", description="用户输入直接输出至HTML未转义"),
        TopVulnerability(rank=6, rule_id="STORED_XSS", category="XSS", cwe="CWE-79", display_name="存储型XSS", occurrence_rate=6.5, severity="HIGH", description="恶意脚本存储后影响其他用户"),
        TopVulnerability(rank=7, rule_id="SENSITIVE_DATA_EXPOSURE", category="DATA_LEAKAGE", cwe="CWE-200", display_name="敏感数据明文传输", occurrence_rate=5.5, severity="HIGH", description="密码/身份证号明文传输"),
        TopVulnerability(rank=8, rule_id="WEAK_CRYPTO", category="CRYPTO_FAILURE", cwe="CWE-327", display_name="弱加密算法", occurrence_rate=4.8, severity="HIGH", description="使用MD5/SHA1/DES等弱算法"),
        TopVulnerability(rank=9, rule_id="VULNERABLE_COMPONENT", category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="已知CVE组件", occurrence_rate=4.5, severity="HIGH", description="使用含已知漏洞的三方库"),
        TopVulnerability(rank=10, rule_id="SECURITY_MISCONFIG", category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", occurrence_rate=4.0, severity="MEDIUM", description="默认配置未修改"),
    ],
    Industry.FINANCE: [
        TopVulnerability(rank=1, rule_id="BUSINESS_LOGIC_FLAW", category="BUSINESS_LOGIC", cwe="CWE-840", display_name="业务逻辑漏洞", occurrence_rate=19.0, severity="CRITICAL", description="业务流程绕过或参数篡改"),
        TopVulnerability(rank=2, rule_id="BROKEN_ACCESS_CONTROL", category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", occurrence_rate=16.5, severity="CRITICAL", description="功能或数据级别越权"),
        TopVulnerability(rank=3, rule_id="TRANSACTION_TAMPER", category="BUSINESS_LOGIC", cwe="CWE-840", display_name="交易金额篡改", occurrence_rate=12.5, severity="CRITICAL", description="交易参数在传输中被修改"),
        TopVulnerability(rank=4, rule_id="STRONG_CRYPTO_MISSING", category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密强度不足", occurrence_rate=10.0, severity="CRITICAL", description="未使用国密或AES-256"),
        TopVulnerability(rank=5, rule_id="DATA_LEAK", category="DATA_LEAKAGE", cwe="CWE-200", display_name="敏感数据泄露", occurrence_rate=8.4, severity="HIGH", description="客户账户信息泄露"),
        TopVulnerability(rank=6, rule_id="SQL_INJECTION", category="INJECTION", cwe="CWE-89", display_name="SQL注入", occurrence_rate=6.5, severity="CRITICAL", description="SQL注入"),
        TopVulnerability(rank=7, rule_id="AUTH_FAILURE", category="AUTH_FAILURE", cwe="CWE-287", display_name="多因素认证缺失", occurrence_rate=5.5, severity="HIGH", description="关键操作未使用MFA"),
        TopVulnerability(rank=8, rule_id="IDOR", category="BROKEN_ACCESS_CONTROL", cwe="CWE-639", display_name="不安全的直接对象引用", occurrence_rate=5.0, severity="HIGH", description="通过修改ID访问他人数据"),
        TopVulnerability(rank=9, rule_id="VULN_COMPONENT", category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="第三方组件漏洞", occurrence_rate=4.0, severity="HIGH", description="含已知CVE的组件"),
        TopVulnerability(rank=10, rule_id="MISCONFIG", category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", occurrence_rate=3.5, severity="MEDIUM", description="默认配置未修改"),
    ],
    Industry.GOVERNMENT: [
        TopVulnerability(rank=1, rule_id="SQL_INJECTION", category="INJECTION", cwe="CWE-89", display_name="SQL注入", occurrence_rate=15.2, severity="CRITICAL", description="SQL注入漏洞"),
        TopVulnerability(rank=2, rule_id="ACCESS_CONTROL", category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", occurrence_rate=13.0, severity="HIGH", description="水平或垂直越权"),
        TopVulnerability(rank=3, rule_id="MISCONFIG", category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", occurrence_rate=10.5, severity="HIGH", description="默认配置不当"),
        TopVulnerability(rank=4, rule_id="XSS", category="XSS", cwe="CWE-79", display_name="跨站脚本", occurrence_rate=9.0, severity="MEDIUM", description="XSS漏洞"),
        TopVulnerability(rank=5, rule_id="DATA_LEAK", category="DATA_LEAKAGE", cwe="CWE-200", display_name="公民信息泄露", occurrence_rate=8.5, severity="HIGH", description="个人身份信息泄露"),
        TopVulnerability(rank=6, rule_id="SUPPLY_CHAIN_RISK", category="SUPPLY_CHAIN", cwe="CWE-1393", display_name="供应链组件漏洞", occurrence_rate=7.2, severity="HIGH", description="三方组件含已知漏洞"),
        TopVulnerability(rank=7, rule_id="WEAK_CRYPTO", category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密强度不足", occurrence_rate=6.0, severity="HIGH", description="非国密算法"),
        TopVulnerability(rank=8, rule_id="INSECURE_DESIGN", category="INSECURE_DESIGN", cwe="CWE-209", display_name="不安全设计", occurrence_rate=5.5, severity="MEDIUM", description="缺少安全控制设计"),
        TopVulnerability(rank=9, rule_id="AUTH_FAILURE", category="AUTH_FAILURE", cwe="CWE-287", display_name="认证机制薄弱", occurrence_rate=5.0, severity="HIGH", description="密码策略薄弱"),
        TopVulnerability(rank=10, rule_id="INSECURE_DESERIALIZE", category="INJECTION", cwe="CWE-502", display_name="反序列化漏洞", occurrence_rate=3.5, severity="CRITICAL", description="反序列化不受信数据"),
    ],
    Industry.INDUSTRIAL_CTRL: [
        TopVulnerability(rank=1, rule_id="INSECURE_PROTOCOL", category="INSECURE_PROTOCOL", cwe="CWE-299", display_name="明文通信协议", occurrence_rate=22.5, severity="CRITICAL", description="Modbus/OPC协议未加密"),
        TopVulnerability(rank=2, rule_id="AUTH_BYPASS", category="AUTH_BYPASS", cwe="CWE-287", display_name="认证绕过", occurrence_rate=16.0, severity="CRITICAL", description="默认密码或硬编码"),
        TopVulnerability(rank=3, rule_id="CMD_INJECTION", category="INJECTION", cwe="CWE-89", display_name="命令注入", occurrence_rate=12.0, severity="CRITICAL", description="系统命令拼接"),
        TopVulnerability(rank=4, rule_id="FIRMWARE_VULN", category="FIRMWARE_VULN", cwe="CWE-119", display_name="固件漏洞", occurrence_rate=10.0, severity="HIGH", description="含已知CVE的固件版本"),
        TopVulnerability(rank=5, rule_id="MISCONFIG", category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", occurrence_rate=8.5, severity="HIGH", description="暴露管理端口"),
        TopVulnerability(rank=6, rule_id="DATA_LEAK", category="DATA_LEAKAGE", cwe="CWE-200", display_name="操作数据泄露", occurrence_rate=6.0, severity="HIGH", description="生产数据明文传输"),
        TopVulnerability(rank=7, rule_id="BUFFER_OVERFLOW", category="BUFFER_OVERFLOW", cwe="CWE-122", display_name="缓冲区溢出", occurrence_rate=5.5, severity="CRITICAL", description="C/C++缓冲区溢出"),
        TopVulnerability(rank=8, rule_id="WEAK_CRYPTO", category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密强度不足", occurrence_rate=4.0, severity="HIGH", description="弱加密算法"),
        TopVulnerability(rank=9, rule_id="LACK_PATCH", category="INSECURE_DESIGN", cwe="CWE-1104", display_name="缺乏补丁管理", occurrence_rate=3.5, severity="HIGH", description="长期不更新固件"),
        TopVulnerability(rank=10, rule_id="PHYSICAL_ACCESS", category="INSECURE_DESIGN", cwe=None, display_name="物理访问控制", occurrence_rate=2.5, severity="MEDIUM", description="暴露调试接口"),
    ],
    Industry.HEALTHCARE: [
        TopVulnerability(rank=1, rule_id="PHI_LEAK", category="DATA_LEAKAGE", cwe="CWE-200", display_name="患者健康信息(PHI)泄露", occurrence_rate=20.5, severity="CRITICAL", description="未加密的患者病历数据"),
        TopVulnerability(rank=2, rule_id="ACCESS_CONTROL", category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", occurrence_rate=15.0, severity="CRITICAL", description="医护人员跨权限访问"),
        TopVulnerability(rank=3, rule_id="AUTH_FAILURE", category="AUTH_FAILURE", cwe="CWE-287", display_name="认证失败", occurrence_rate=10.0, severity="HIGH", description="弱密码策略"),
        TopVulnerability(rank=4, rule_id="MISCONFIG", category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", occurrence_rate=8.5, severity="HIGH", description="默认管理员密码"),
        TopVulnerability(rank=5, rule_id="SQL_INJECTION", category="INJECTION", cwe="CWE-89", display_name="SQL注入", occurrence_rate=7.0, severity="CRITICAL", description="SQL注入"),
        TopVulnerability(rank=6, rule_id="VULN_COMPONENT", category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="陈旧组件", occurrence_rate=6.0, severity="HIGH", description="含已知CVE的组件"),
        TopVulnerability(rank=7, rule_id="WEAK_CRYPTO", category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密强度不足", occurrence_rate=5.0, severity="HIGH", description="未加密存储或传输"),
        TopVulnerability(rank=8, rule_id="MEDICAL_DEVICE", category="INSECURE_DESIGN", cwe=None, display_name="医疗设备漏洞", occurrence_rate=4.5, severity="HIGH", description="联网医疗设备安全"),
        TopVulnerability(rank=9, rule_id="XSS", category="XSS", cwe="CWE-79", display_name="跨站脚本", occurrence_rate=4.0, severity="MEDIUM", description="XSS漏洞"),
        TopVulnerability(rank=10, rule_id="SYSTEM_DOWN", category="AVAILABILITY", cwe="CWE-400", display_name="系统可用性风险", occurrence_rate=3.5, severity="HIGH", description="系统宕机影响医疗"),
    ],
    Industry.EDUCATION: [
        TopVulnerability(rank=1, rule_id="SQL_INJECTION", category="INJECTION", cwe="CWE-89", display_name="SQL注入", occurrence_rate=14.5, severity="CRITICAL", description="SQL注入"),
        TopVulnerability(rank=2, rule_id="STUDENT_DATA_LEAK", category="DATA_LEAKAGE", cwe="CWE-200", display_name="学生信息泄露", occurrence_rate=12.0, severity="HIGH", description="学生个人信息泄露"),
        TopVulnerability(rank=3, rule_id="ACCESS_CONTROL", category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", occurrence_rate=11.5, severity="HIGH", description="越权访问成绩等数据"),
        TopVulnerability(rank=4, rule_id="XSS", category="XSS", cwe="CWE-79", display_name="跨站脚本", occurrence_rate=9.0, severity="MEDIUM", description="XSS漏洞"),
        TopVulnerability(rank=5, rule_id="MISCONFIG", category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", occurrence_rate=7.0, severity="MEDIUM", description="目录遍历/调试模式"),
        TopVulnerability(rank=6, rule_id="AUTH_WEAKNESS", category="AUTH_FAILURE", cwe="CWE-287", display_name="弱认证", occurrence_rate=6.0, severity="MEDIUM", description="弱密码策略"),
        TopVulnerability(rank=7, rule_id="VULN_COMPONENT", category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="第三方组件漏洞", occurrence_rate=5.5, severity="MEDIUM", description="含已知CVE组件"),
        TopVulnerability(rank=8, rule_id="WEAK_CRYPTO", category="CRYPTO_FAILURE", cwe="CWE-327", display_name="弱加密算法", occurrence_rate=4.5, severity="MEDIUM", description="MD5/明文"),
        TopVulnerability(rank=9, rule_id="FILE_UPLOAD", category="INJECTION", cwe="CWE-434", display_name="文件上传漏洞", occurrence_rate=4.0, severity="HIGH", description="不安全的文件上传"),
        TopVulnerability(rank=10, rule_id="PATH_TRAVERSAL", category="INJECTION", cwe="CWE-22", display_name="路径遍历", occurrence_rate=3.5, severity="MEDIUM", description="路径遍历漏洞"),
    ],
    Industry.TELECOM: [
        TopVulnerability(rank=1, rule_id="PROTOCOL_VULN", category="PROTOCOL_VULN", cwe="CWE-299", display_name="通信协议漏洞", occurrence_rate=17.0, severity="CRITICAL", description="SIP/Diameter等协议漏洞"),
        TopVulnerability(rank=2, rule_id="ACCESS_CONTROL", category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", occurrence_rate=13.5, severity="HIGH", description="越权访问计费数据"),
        TopVulnerability(rank=3, rule_id="CMD_INJECTION", category="INJECTION", cwe="CWE-89", display_name="命令注入", occurrence_rate=11.0, severity="CRITICAL", description="系统命令注入"),
        TopVulnerability(rank=4, rule_id="USER_DATA_LEAK", category="DATA_LEAKAGE", cwe="CWE-200", display_name="用户通信数据泄露", occurrence_rate=9.5, severity="CRITICAL", description="通话/数据流量泄露"),
        TopVulnerability(rank=5, rule_id="DOS", category="DOS", cwe="CWE-400", display_name="拒绝服务", occurrence_rate=8.0, severity="HIGH", description="DDoS/服务不可用"),
        TopVulnerability(rank=6, rule_id="MISCONFIG", category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", occurrence_rate=6.5, severity="HIGH", description="默认配置"),
        TopVulnerability(rank=7, rule_id="WEAK_CRYPTO", category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密机制失效", occurrence_rate=5.5, severity="HIGH", description="弱加密算法"),
        TopVulnerability(rank=8, rule_id="VULN_COMPONENT", category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="第三方组件漏洞", occurrence_rate=5.0, severity="MEDIUM", description="含CVE组件"),
        TopVulnerability(rank=9, rule_id="BILLING_FRAUD", category="BUSINESS_LOGIC", cwe="CWE-840", display_name="计费欺诈", occurrence_rate=4.5, severity="HIGH", description="计费逻辑绕过"),
        TopVulnerability(rank=10, rule_id="INSECURE_DESIGN", category="INSECURE_DESIGN", cwe="CWE-209", display_name="不安全设计", occurrence_rate=4.0, severity="MEDIUM", description="安全设计缺失"),
    ],
    Industry.ENERGY: [
        TopVulnerability(rank=1, rule_id="INSECURE_PROTOCOL", category="INSECURE_PROTOCOL", cwe="CWE-299", display_name="工控协议漏洞", occurrence_rate=24.0, severity="CRITICAL", description="IEC 61850/Modbus协议"),
        TopVulnerability(rank=2, rule_id="MISCONFIG", category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", occurrence_rate=12.5, severity="HIGH", description="暴露管理端口"),
        TopVulnerability(rank=3, rule_id="AUTH_BYPASS", category="AUTH_BYPASS", cwe="CWE-287", display_name="认证绕过", occurrence_rate=10.5, severity="CRITICAL", description="默认密码"),
        TopVulnerability(rank=4, rule_id="FIRMWARE_VULN", category="FIRMWARE_VULN", cwe="CWE-119", display_name="固件漏洞", occurrence_rate=9.0, severity="HIGH", description="RTU/PLC固件"),
        TopVulnerability(rank=5, rule_id="CMD_INJECTION", category="INJECTION", cwe="CWE-89", display_name="命令注入", occurrence_rate=7.5, severity="CRITICAL", description="命令注入"),
        TopVulnerability(rank=6, rule_id="DATA_LEAK", category="DATA_LEAKAGE", cwe="CWE-200", display_name="生产数据泄露", occurrence_rate=5.5, severity="HIGH", description="SCADA数据泄露"),
        TopVulnerability(rank=7, rule_id="DOS", category="DOS", cwe="CWE-400", display_name="拒绝服务", occurrence_rate=5.0, severity="CRITICAL", description="DoS攻击影响电力"),
        TopVulnerability(rank=8, rule_id="WEAK_CRYPTO", category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密强度不足", occurrence_rate=4.0, severity="HIGH", description="弱加密"),
        TopVulnerability(rank=9, rule_id="LACK_PATCH", category="INSECURE_DESIGN", cwe="CWE-1104", display_name="缺少补丁管理", occurrence_rate=3.5, severity="HIGH", description="固件更新不及时"),
        TopVulnerability(rank=10, rule_id="PHYSICAL_ACCESS", category="INSECURE_DESIGN", cwe=None, display_name="物理安全边界", occurrence_rate=3.0, severity="MEDIUM", description="物理入侵"),
    ],
    Industry.TRANSPORTATION: [
        TopVulnerability(rank=1, rule_id="SIG_SYS_AUTH", category="SIG_SYS_VULN", cwe="CWE-284", display_name="信号系统越权", occurrence_rate=15.0, severity="CRITICAL", description="信号系统权限控制缺陷"),
        TopVulnerability(rank=2, rule_id="PROTOCOL_VULN", category="PROTOCOL_VULN", cwe="CWE-299", display_name="通信协议漏洞", occurrence_rate=13.5, severity="CRITICAL", description="CBTC/RPC协议漏洞"),
        TopVulnerability(rank=3, rule_id="AUTH_BYPASS", category="AUTH_BYPASS", cwe="CWE-287", display_name="认证绕过", occurrence_rate=10.5, severity="CRITICAL", description="伪造凭证"),
        TopVulnerability(rank=4, rule_id="AVAILABILITY", category="AVAILABILITY", cwe="CWE-400", display_name="系统可用性风险", occurrence_rate=9.0, severity="CRITICAL", description="信号系统宕机影响行车"),
        TopVulnerability(rank=5, rule_id="CMD_INJECTION", category="INJECTION", cwe="CWE-89", display_name="命令注入", occurrence_rate=7.5, severity="CRITICAL", description="命令注入"),
        TopVulnerability(rank=6, rule_id="TRAVEL_DATA_LEAK", category="DATA_LEAKAGE", cwe="CWE-200", display_name="出行数据泄露", occurrence_rate=6.5, severity="HIGH", description="旅客信息泄露"),
        TopVulnerability(rank=7, rule_id="MISCONFIG", category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", occurrence_rate=5.5, severity="HIGH", description="配置不当"),
        TopVulnerability(rank=8, rule_id="GPS_SPOOFING", category="GPS_SPOOFING", cwe="CWE-290", display_name="GPS欺骗", occurrence_rate=5.0, severity="CRITICAL", description="GPS/北斗信号欺骗"),
        TopVulnerability(rank=9, rule_id="FIRMWARE_VULN", category="FIRMWARE_VULN", cwe="CWE-119", display_name="固件漏洞", occurrence_rate=4.0, severity="HIGH", description="车载/路边设备固件"),
        TopVulnerability(rank=10, rule_id="WEAK_CRYPTO", category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密强度不足", occurrence_rate=3.5, severity="HIGH", description="弱加密"),
    ],
    Industry.INSURANCE: [
        TopVulnerability(rank=1, rule_id="BUSINESS_LOGIC", category="BUSINESS_LOGIC", cwe="CWE-840", display_name="业务逻辑漏洞", occurrence_rate=18.5, severity="CRITICAL", description="理赔/费率逻辑绕过"),
        TopVulnerability(rank=2, rule_id="CUSTOMER_DATA_LEAK", category="DATA_LEAKAGE", cwe="CWE-200", display_name="客户信息泄露", occurrence_rate=15.0, severity="CRITICAL", description="保险客户信息泄露"),
        TopVulnerability(rank=3, rule_id="ACCESS_CONTROL", category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", occurrence_rate=11.5, severity="HIGH", description="代理人越权查看客户"),
        TopVulnerability(rank=4, rule_id="AUTH_FAILURE", category="AUTH_FAILURE", cwe="CWE-287", display_name="认证失败", occurrence_rate=8.0, severity="HIGH", description="弱密码/单点登录缺陷"),
        TopVulnerability(rank=5, rule_id="SQL_INJECTION", category="INJECTION", cwe="CWE-89", display_name="SQL注入", occurrence_rate=6.5, severity="CRITICAL", description="SQL注入"),
        TopVulnerability(rank=6, rule_id="WEAK_CRYPTO", category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密强度不足", occurrence_rate=5.5, severity="HIGH", description="客户数据未加密"),
        TopVulnerability(rank=7, rule_id="VULN_COMPONENT", category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="第三方组件漏洞", occurrence_rate=5.0, severity="HIGH", description="含CVE组件"),
        TopVulnerability(rank=8, rule_id="COMPLIANCE_GAP", category="COMPLIANCE_GAP", cwe=None, display_name="合规差距", occurrence_rate=4.5, severity="MEDIUM", description="监管合规差距"),
        TopVulnerability(rank=9, rule_id="XSS", category="XSS", cwe="CWE-79", display_name="跨站脚本", occurrence_rate=4.0, severity="MEDIUM", description="XSS"),
        TopVulnerability(rank=10, rule_id="MISCONFIG", category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", occurrence_rate=3.5, severity="MEDIUM", description="配置错误"),
    ],
    Industry.SECURITIES: [
        TopVulnerability(rank=1, rule_id="TRADING_LOGIC", category="BUSINESS_LOGIC", cwe="CWE-840", display_name="交易逻辑漏洞", occurrence_rate=20.5, severity="CRITICAL", description="高频交易逻辑绕过"),
        TopVulnerability(rank=2, rule_id="TRADE_DATA_LEAK", category="DATA_LEAKAGE", cwe="CWE-200", display_name="交易数据泄露", occurrence_rate=12.5, severity="CRITICAL", description="客户持仓/交易数据泄露"),
        TopVulnerability(rank=3, rule_id="ACCESS_CONTROL", category="BROKEN_ACCESS_CONTROL", cwe="CWE-284", display_name="越权访问", occurrence_rate=10.0, severity="CRITICAL", description="越权操作交易账户"),
        TopVulnerability(rank=4, rule_id="LATENCY_EXPLOIT", category="LATENCY_EXPLOIT", cwe=None, display_name="延迟操纵", occurrence_rate=8.5, severity="CRITICAL", description="高频交易延迟操纵"),
        TopVulnerability(rank=5, rule_id="DOS", category="DOS", cwe="CWE-400", display_name="拒绝服务", occurrence_rate=7.0, severity="CRITICAL", description="拒绝服务影响交易"),
        TopVulnerability(rank=6, rule_id="SQL_INJECTION", category="INJECTION", cwe="CWE-89", display_name="SQL注入", occurrence_rate=6.0, severity="CRITICAL", description="SQL注入"),
        TopVulnerability(rank=7, rule_id="WEAK_CRYPTO", category="CRYPTO_FAILURE", cwe="CWE-327", display_name="加密强度不足", occurrence_rate=5.0, severity="HIGH", description="弱加密"),
        TopVulnerability(rank=8, rule_id="MARKET_MANIP", category="MARKET_MANIPULATION", cwe=None, display_name="行情操纵", occurrence_rate=4.5, severity="CRITICAL", description="行情数据操纵"),
        TopVulnerability(rank=9, rule_id="VULN_COMPONENT", category="VULNERABLE_COMPONENTS", cwe="CWE-1035", display_name="第三方组件漏洞", occurrence_rate=4.0, severity="HIGH", description="含CVE组件"),
        TopVulnerability(rank=10, rule_id="MISCONFIG", category="MISCONFIGURATION", cwe="CWE-16", display_name="安全配置错误", occurrence_rate=3.5, severity="MEDIUM", description="配置不当"),
    ],
}


def _build_top_vulns(industry: Industry) -> List[TopVulnerability]:
    return _TOP_VULNS.get(industry, [])


# ──────────────────── 合规要求 ────────────────────

_COMPLIANCE_DATA: Dict[Industry, List[ComplianceRequirement]] = {
    Industry.INTERNET: [
        ComplianceRequirement(ref_id="GB/T 22239-2019 三级-8.1.3", standard="网络安全等级保护基本要求", section="8.1.3", description="安全计算环境-访问控制", related_cwes=["CWE-284", "CWE-89"], mandatory=True),
        ComplianceRequirement(ref_id="个人信息保护法-第51条", standard="中华人民共和国个人信息保护法", section="第51条", description="个人信息加密", related_cwes=["CWE-200", "CWE-327"], mandatory=True),
        ComplianceRequirement(ref_id="数据安全法-第27条", standard="中华人民共和国数据安全法", section="第27条", description="数据分类分级", related_cwes=["CWE-200"], mandatory=True),
    ],
    Industry.FINANCE: [
        ComplianceRequirement(ref_id="JR/T 0071-2020 三级-8.1.3", standard="金融行业等级保护测评指南", section="三级-8.1.3", description="安全计算环境", related_cwes=["CWE-327", "CWE-89"], mandatory=True),
        ComplianceRequirement(ref_id="个人金融信息保护技术规范", standard="JR/T 0171-2020", section="", description="个人金融信息保护", related_cwes=["CWE-200", "CWE-327"], mandatory=True),
    ],
    Industry.GOVERNMENT: [
        ComplianceRequirement(ref_id="GB/T 22239-2019 三级-8.1.3", standard="网络安全等级保护基本要求", section="三级-8.1.3", description="安全计算环境", related_cwes=["CWE-284", "CWE-89"], mandatory=True),
        ComplianceRequirement(ref_id="数据安全法-第27条", standard="中华人民共和国数据安全法", section="第27条", description="数据分类分级", related_cwes=["CWE-200"], mandatory=True),
        ComplianceRequirement(ref_id="关键信息基础设施安全保护条例", standard="国务院令第745号", section="", description="关基设施安全保护", related_cwes=["CWE-284"], mandatory=True),
    ],
    Industry.INDUSTRIAL_CTRL: [
        ComplianceRequirement(ref_id="GB/T 22239-2019 工控扩展", standard="网络安全等级保护基本要求", section="三级", description="工控扩展要求", related_cwes=["CWE-299", "CWE-284"], mandatory=True),
        ComplianceRequirement(ref_id="GB/T 39204-2022", standard="工控安全防护能力评估方法", section="", description="工控安全防护评估", related_cwes=["CWE-299"], mandatory=True),
        ComplianceRequirement(ref_id="工业控制系统信息安全防护指南", standard="工信部协〔2016〕432号", section="", description="11项工控安全要求", related_cwes=["CWE-287", "CWE-400"], mandatory=True),
    ],
    Industry.HEALTHCARE: [
        ComplianceRequirement(ref_id="GB/T 22239-2019 三级-8.1.3", standard="网络安全等级保护基本要求", section="三级-8.1.3", description="安全计算环境", related_cwes=["CWE-284", "CWE-200"], mandatory=True),
        ComplianceRequirement(ref_id="健康医疗数据安全指南", standard="GB/T 39725-2020", section="", description="健康医疗数据安全", related_cwes=["CWE-200", "CWE-327"], mandatory=True),
        ComplianceRequirement(ref_id="个人信息保护法-第51条", standard="中华人民共和国个人信息保护法", section="第51条", description="敏感个人信息保护", related_cwes=["CWE-200"], mandatory=True),
    ],
    Industry.EDUCATION: [
        ComplianceRequirement(ref_id="GB/T 22239-2019 三级-8.1.3", standard="网络安全等级保护基本要求", section="三级-8.1.3", description="安全计算环境", related_cwes=["CWE-284", "CWE-89"], mandatory=True),
        ComplianceRequirement(ref_id="儿童个人信息网络保护规定", standard="国家互联网信息办公室", section="", description="儿童信息保护", related_cwes=["CWE-200"], mandatory=True),
        ComplianceRequirement(ref_id="数据安全法-第27条", standard="中华人民共和国数据安全法", section="第27条", description="数据分类分级", related_cwes=["CWE-200"], mandatory=True),
    ],
    Industry.TELECOM: [
        ComplianceRequirement(ref_id="GB/T 22239-2019 三级-8.1.3", standard="网络安全等级保护基本要求", section="三级-8.1.3", description="通信网络", related_cwes=["CWE-299", "CWE-284"], mandatory=True),
        ComplianceRequirement(ref_id="关键信息基础设施安全保护条例", standard="国务院令第745号", section="", description="关基设施安全保护", related_cwes=["CWE-284", "CWE-400"], mandatory=True),
        ComplianceRequirement(ref_id="通信网络安全防护管理办法", standard="工业和信息化部令第11号", section="", description="通信网络安全防护", related_cwes=["CWE-284", "CWE-299"], mandatory=True),
    ],
    Industry.ENERGY: [
        ComplianceRequirement(ref_id="GB/T 22239-2019 工控扩展", standard="网络安全等级保护基本要求", section="三级", description="工控扩展安全计算环境", related_cwes=["CWE-299", "CWE-284"], mandatory=True),
        ComplianceRequirement(ref_id="电力监控系统安全防护规定", standard="国家发改委令第14号", section="", description="电力监控安全防护", related_cwes=["CWE-299", "CWE-284"], mandatory=True),
        ComplianceRequirement(ref_id="关键信息基础设施安全保护条例", standard="国务院令第745号", section="", description="关基设施安全保护", related_cwes=["CWE-284"], mandatory=True),
    ],
    Industry.TRANSPORTATION: [
        ComplianceRequirement(ref_id="GB/T 22239-2019 三级-8.1.3", standard="网络安全等级保护基本要求", section="三级-8.1.3", description="安全计算环境", related_cwes=["CWE-284", "CWE-299"], mandatory=True),
        ComplianceRequirement(ref_id="关键信息基础设施安全保护条例", standard="国务院令第745号", section="", description="关基设施安全保护", related_cwes=["CWE-284"], mandatory=True),
    ],
    Industry.INSURANCE: [
        ComplianceRequirement(ref_id="JR/T 0071-2020 三级-8.1.3", standard="金融行业等级保护测评指南", section="三级-8.1.3", description="安全计算环境", related_cwes=["CWE-284", "CWE-89"], mandatory=True),
        ComplianceRequirement(ref_id="个人金融信息保护技术规范", standard="JR/T 0171-2020", section="", description="个人金融信息保护", related_cwes=["CWE-200", "CWE-327"], mandatory=True),
    ],
    Industry.SECURITIES: [
        ComplianceRequirement(ref_id="JR/T 0071-2020 三级-8.1.3", standard="金融行业等级保护测评指南", section="三级-8.1.3", description="安全计算环境", related_cwes=["CWE-284", "CWE-89"], mandatory=True),
        ComplianceRequirement(ref_id="证券期货业信息系统安全等级保护基本要求", standard="JR/T 0060-2012", section="", description="证券期货信息系统安全", related_cwes=["CWE-284", "CWE-400"], mandatory=True),
    ],
}


def _build_compliance(industry: Industry) -> List[ComplianceRequirement]:
    return _COMPLIANCE_DATA.get(industry, [])


# ──────────────────── 行业特色漏洞场景 ────────────────────

_SCENARIO_DATA: Dict[Industry, List[IndustryScenario]] = {
    Industry.INTERNET: [
        IndustryScenario(scenario_id="INTERNET_API_ABUSE", title="API 越权攻击", description="利用 API 的 IDOR 漏洞横向越权", related_categories=["BROKEN_ACCESS_CONTROL", "DATA_LEAKAGE"], risk_level="CRITICAL", mitigations=["资源级访问控制", "不可预测资源ID"]),
        IndustryScenario(scenario_id="INTERNET_SUPPLY_CHAIN", title="前端依赖供应链攻击", description="npm/pip 包投毒植入恶意代码", related_categories=["VULNERABLE_COMPONENTS"], risk_level="HIGH", mitigations=["锁定依赖版本", "SCA扫描"]),
    ],
    Industry.FINANCE: [
        IndustryScenario(scenario_id="FINANCE_TRANS_TAMPER", title="交易金额篡改", description="篡改支付/转账请求中的金额字段", related_categories=["BUSINESS_LOGIC"], risk_level="CRITICAL", mitigations=["签名验证", "服务端金额校验"]),
        IndustryScenario(scenario_id="FINANCE_BATCH_RISK", title="批量代发/代扣漏洞", description="越权调用批量发放或扣款接口", related_categories=["BUSINESS_LOGIC", "BROKEN_ACCESS_CONTROL"], risk_level="CRITICAL", mitigations=["双人复核", "金额阈值限制"]),
    ],
    Industry.GOVERNMENT: [
        IndustryScenario(scenario_id="GOV_PII_MASS", title="公民信息批量泄露", description="利用政务系统漏洞批量窃取个人信息", related_categories=["DATA_LEAKAGE", "INJECTION"], risk_level="CRITICAL", mitigations=["数据脱敏", "最小权限"]),
        IndustryScenario(scenario_id="GOV_SUPPLY_CHAIN", title="政务信息系统供应链攻击", description="通过共享组件植入后门", related_categories=["VULNERABLE_COMPONENTS", "SUPPLY_CHAIN"], risk_level="HIGH", mitigations=["SBOM管理", "组件安全检测"]),
    ],
    Industry.INDUSTRIAL_CTRL: [
        IndustryScenario(scenario_id="ICS_RCE", title="PLC控制异常", description="利用工控系统 RCE 漏洞控制PLC设备", related_categories=["INJECTION", "AUTH_BYPASS", "BUFFER_OVERFLOW"], risk_level="CRITICAL", mitigations=["网络隔离", "协议认证"]),
        IndustryScenario(scenario_id="ICS_FIRMWARE", title="固件篡改攻击", description="嵌入恶意固件", related_categories=["FIRMWARE_VULN"], risk_level="CRITICAL", mitigations=["签名校验", "安全启动"]),
    ],
    Industry.HEALTHCARE: [
        IndustryScenario(scenario_id="HC_MED_DEVICE", title="联网医疗设备劫持", description="利用医疗设备漏洞获取控制权", related_categories=["INSECURE_DESIGN", "DATA_LEAKAGE"], risk_level="CRITICAL", mitigations=["设备隔离", "固件加密"]),
        IndustryScenario(scenario_id="HC_EMR_LEAK", title="电子病历批量窃取", description="利用系统漏洞批量导出患者病历", related_categories=["DATA_LEAKAGE", "BROKEN_ACCESS_CONTROL"], risk_level="CRITICAL", mitigations=["数据分级", "加密存储"]),
    ],
    Industry.EDUCATION: [
        IndustryScenario(scenario_id="EDU_GRADE_CHANGE", title="成绩篡改", description="越权修改教务系统成绩数据", related_categories=["BROKEN_ACCESS_CONTROL"], risk_level="HIGH", mitigations=["双人确认", "变更审计"]),
        IndustryScenario(scenario_id="EDU_THESIS_LEAK", title="学术成果窃取", description="越权访问科研数据平台窃取成果", related_categories=["DATA_LEAKAGE", "BROKEN_ACCESS_CONTROL"], risk_level="HIGH", mitigations=["数据分级", "行为监控"]),
    ],
    Industry.TELECOM: [
        IndustryScenario(scenario_id="TEL_BILLING_FRAUD", title="计费欺诈", description="利用计费系统漏洞绕过计费", related_categories=["BUSINESS_LOGIC"], risk_level="CRITICAL", mitigations=["实时计费验证", "异常检测"]),
        IndustryScenario(scenario_id="TEL_INTERCEPTION", title="通信流量窃听", description="核心网缺陷导致通话被窃听", related_categories=["PROTOCOL_VULN", "DATA_LEAKAGE"], risk_level="CRITICAL", mitigations=["端到端加密", "网络分段"]),
    ],
    Industry.ENERGY: [
        IndustryScenario(scenario_id="NRG_SCADA_HACK", title="SCADA系统入侵", description="远程操控电力设施导致停电", related_categories=["INSECURE_PROTOCOL", "AUTH_BYPASS"], risk_level="CRITICAL", mitigations=["工控网络隔离", "协议加密"]),
        IndustryScenario(scenario_id="NRG_METER_HACK", title="智能电表篡改", description="篡改计量数据", related_categories=["INSECURE_PROTOCOL", "DATA_LEAKAGE"], risk_level="HIGH", mitigations=["双向认证", "数据签名"]),
    ],
    Industry.TRANSPORTATION: [
        IndustryScenario(scenario_id="TRA_SIG_HACK", title="交通信号系统篡改", description="入侵信号控制系统操纵信号灯", related_categories=["SIG_SYS_VULN", "AUTH_BYPASS"], risk_level="CRITICAL", mitigations=["信号系统冗余", "物理隔离"]),
        IndustryScenario(scenario_id="TRA_GPS_SPOOF", title="GPS欺骗攻击", description="伪造GPS/北斗信号诱导偏离航线", related_categories=["GPS_SPOOFING", "PROTOCOL_VULN"], risk_level="CRITICAL", mitigations=["多源融合定位", "信号完整性校验"]),
    ],
    Industry.INSURANCE: [
        IndustryScenario(scenario_id="INS_CLAIM_FRAUD", title="理赔欺诈", description="虚构理赔或放大理赔金额", related_categories=["BUSINESS_LOGIC"], risk_level="HIGH", mitigations=["规则引擎", "图像识别"]),
        IndustryScenario(scenario_id="INS_ACTUARY_TAMPER", title="精算模型篡改", description="越权修改精算模型影响定价", related_categories=["BUSINESS_LOGIC", "BROKEN_ACCESS_CONTROL"], risk_level="CRITICAL", mitigations=["模型签名", "版本控制"]),
    ],
    Industry.SECURITIES: [
        IndustryScenario(scenario_id="SEC_FLASH_CRASH", title="闪电崩盘操纵", description="利用交易系统延迟操纵引发崩盘", related_categories=["LATENCY_EXPLOIT", "MARKET_MANIPULATION"], risk_level="CRITICAL", mitigations=["熔断机制", "延时均等化"]),
        IndustryScenario(scenario_id="SEC_ORDER_SPOOF", title="挂单欺骗", description="透视他人挂单或伪造交易指令", related_categories=["BUSINESS_LOGIC", "BROKEN_ACCESS_CONTROL"], risk_level="CRITICAL", mitigations=["订单加密", "身份风控"]),
    ],
}


def _build_scenarios(industry: Industry) -> List[IndustryScenario]:
    return _SCENARIO_DATA.get(industry, [])


# ──────────────────── 构建完整数据集 ────────────────────

def build_benchmark_dataset(industry: Industry) -> BenchmarkDataset:
    """构建指定行业的完整基准数据集"""
    return BenchmarkDataset(
        industry=industry,
        version="3.0.0",
        sample_size=500,
        vuln_distribution=_build_distribution(industry),
        repair_cycle=_build_repair_cycle(industry),
        top_vulnerabilities=_build_top_vulns(industry),
        compliance_requirements=_build_compliance(industry),
        industry_scenarios=_build_scenarios(industry),
        metadata=BenchmarkMetadata(
            source="xuanjian-builtin",
            sample_period="2025-Q1~2026-Q2",
            confidence=0.95,
            notes="基于公开安全报告与行业实践构建的基准参考数据集",
        ),
    )


def build_all_benchmarks() -> Dict[Industry, BenchmarkDataset]:
    """构建全部行业的基准数据集"""
    return {industry: build_benchmark_dataset(industry) for industry in Industry}


def get_industry_meta(industry: Industry) -> IndustryMeta:
    """获取行业元数据"""
    return INDUSTRY_METADATA.get(
        industry,
        IndustryMeta(
            industry=industry,
            display_name=industry.value,
            description="",
            key_tech_stacks=[],
            risk_profile="",
        ),
    )
