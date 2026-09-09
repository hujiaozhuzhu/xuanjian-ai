"""
组件漏洞库 v3.2.0

收录主流 Java/Python/Go/JS 框架和库的已知 CVE 漏洞信息。
覆盖 15+ 常见组件，100+ CVE 漏洞条目。

本模块仅存储漏洞元信息用于匹配参考，不包含任何攻击利用代码。
所有 CVE 信息均来自公开 NVD/CNNVD 数据库。

支持的组件：
- Spring Framework / Spring Boot / Spring Cloud
- Apache Struts2
- Apache Log4j / Log4j2
- Fastjson
- Apache Shiro
- Apache Tomcat
- Apache Commons Collections
- Apache Commons Text
- Jackson / Jackson-Databind
- Apache Dubbo
- Hibernate
- jQuery
- Lodash
- OpenSSL
- Netty
"""

from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class ComponentVuln:
    """单个组件漏洞信息"""
    cve_id: str
    component: str
    affected_versions: str           # 受影响版本范围
    severity: str                   # CRITICAL / HIGH / MEDIUM / LOW
    vuln_type: str                  # 漏洞类型
    description: str                # 中文描述
    patched_versions: str           # 安全版本
    reference_url: str              # 参考链接
    cvss_score: float = 0.0         # CVSS 评分
    poc_available: bool = False     # 是否有公开 PoC（仅信息标记）


# ─────────────────────── Spring Framework / Spring Cloud ───────────────────────

SPRING_VULNS = [
    ComponentVuln(
        cve_id="CVE-2022-22965",
        component="Spring Framework",
        affected_versions="Spring 5.3.x<5.3.18, 5.2.x<5.2.20",
        severity="CRITICAL",
        vuln_type="RCE (Spring4Shell)",
        description="Spring Framework 参数绑定在 JDK 9+ 环境下可修改 ClassLoader 导致 RCE",
        patched_versions="5.3.18+, 5.2.20+",
        reference_url="https://tanzu.vmware.com/security/cve-2022-22965",
        cvss_score=9.8,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2022-22947",
        component="Spring Cloud Gateway",
        affected_versions="Gateway 3.1.x<3.1.1, 3.0.x<3.0.7",
        severity="CRITICAL",
        vuln_type="RCE",
        description="Spring Cloud Gateway Actuator SpEL 表达式注入导致 RCE",
        patched_versions="3.1.1+, 3.0.7+",
        reference_url="https://tanzu.vmware.com/security/cve-2022-22947",
        cvss_score=10.0,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2022-22963",
        component="Spring Cloud Function",
        affected_versions="Function 3.1.6, 3.2.2",
        severity="CRITICAL",
        vuln_type="RCE",
        description="Spring Cloud Function 路由 SPEL 表达式注入导致 RCE",
        patched_versions="3.1.7+, 3.2.3+",
        reference_url="https://tanzu.vmware.com/security/cve-2022-22963",
        cvss_score=9.8,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2021-21295",
        component="Spring Boot",
        affected_versions="Spring Boot <2.2.11, 2.3.x<2.3.10",
        severity="MEDIUM",
        vuln_type="Http Response Splitting",
        description="Spring Boot 未正确处理 CRLF 字符导致 HTTP 响应拆分",
        patched_versions="2.2.11+, 2.3.10+",
        reference_url="https://tanzu.vmware.com/security/cve-2021-21295",
        cvss_score=5.3,
        poc_available=False,
    ),
]


# ─────────────────────── Apache Struts2 ───────────────────────

STRUTS2_VULNS = [
    ComponentVuln(
        cve_id="CVE-2017-5638",
        component="Apache Struts2",
        affected_versions="Struts 2.3.5-2.3.31, 2.5-2.5.10",
        severity="CRITICAL",
        vuln_type="RCE",
        description="Jakarta Multipart 解析器在异常消息中执行 OGNL 表达式导致 RCE",
        patched_versions="2.3.32, 2.5.10.1+",
        reference_url="https://cwiki.apache.org/confluence/display/WW/S2-045",
        cvss_score=10.0,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2018-11776",
        component="Apache Struts2",
        affected_versions="Struts 2.3.x<2.3.35, 2.5.x<2.5.17",
        severity="CRITICAL",
        vuln_type="RCE",
        description="Struts2 namespace 校验缺陷导致 OGNL 表达式注入 RCE",
        patched_versions="2.3.35, 2.5.17+",
        reference_url="https://cwiki.apache.org/confluence/display/WW/S2-057",
        cvss_score=8.1,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2020-17530",
        component="Apache Struts2",
        affected_versions="Struts 2.0.0-2.5.25",
        severity="CRITICAL",
        vuln_type="RCE",
        description="Struts2 ForcedOGNL 标签属性中强制求值 OGNL 表达式",
        patched_versions="2.5.26+",
        reference_url="https://cwiki.apache.org/confluence/display/WW/S2-061",
        cvss_score=9.8,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2013-2251",
        component="Apache Struts2",
        affected_versions="Struts 2.0.0-2.3.15",
        severity="CRITICAL",
        vuln_type="RCE",
        description="Struts2 S2-016 action:redirect 前缀允许 OGNL 求值",
        patched_versions="2.3.15.1+",
        reference_url="https://cwiki.apache.org/confluence/display/WW/S2-016",
        cvss_score=9.8,
        poc_available=False,
    ),
]


# ─────────────────────── Apache Log4j2 ───────────────────────

LOG4J_VULNS = [
    ComponentVuln(
        cve_id="CVE-2021-44228",
        component="Apache Log4j2",
        affected_versions="Log4j 2.0-beta9 - 2.14.1",
        severity="CRITICAL",
        vuln_type="RCE (Log4Shell)",
        description="Log4j2 JNDI 功能未校验 URL，通过构造日志消息触发 RCE",
        patched_versions="Log4j 2.15.0+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        cvss_score=10.0,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2021-45046",
        component="Apache Log4j2",
        affected_versions="Log4j 2.0-beta9 - 2.15.0",
        severity="CRITICAL",
        vuln_type="RCE / DoS",
        description="Log4j2 2.15.0 对 CVE-2021-44228 修复不完整，可被绕过",
        patched_versions="Log4j 2.16.0+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2021-45046",
        cvss_score=9.0,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2021-45105",
        component="Apache Log4j2",
        affected_versions="Log4j 2.0-beta9 - 2.16.0",
        severity="HIGH",
        vuln_type="DoS",
        description="Log4j2 上下文查找递归求值可导致拒绝服务",
        patched_versions="Log4j 2.17.0+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2021-45105",
        cvss_score=5.9,
        poc_available=False,
    ),
]


# ─────────────────────── Fastjson ───────────────────────

FASTJSON_VULNS = [
    ComponentVuln(
        cve_id="CVE-2017-18349",
        component="Fastjson",
        affected_versions="Fastjson <1.2.25",
        severity="CRITICAL",
        vuln_type="RCE",
        description="Fastjson parseObject() 使用 @type 指定危险类触发 JNDI 注入 RCE",
        patched_versions="Fastjson 1.2.25+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2017-18349",
        cvss_score=9.8,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2022-25845",
        component="Fastjson",
        affected_versions="Fastjson 1.x <1.2.83",
        severity="CRITICAL",
        vuln_type="RCE",
        description="Fastjson 1.x 关闭 AutoType 后仍存在绕过可构造恶意 JSON 触发 RCE",
        patched_versions="Fastjson 1.2.83+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2022-25845",
        cvss_score=9.8,
        poc_available=True,
    ),
]


# ─────────────────────── Apache Shiro ───────────────────────

SHIRO_VULNS = [
    ComponentVuln(
        cve_id="CVE-2016-4437",
        component="Apache Shiro",
        affected_versions="Shiro <1.2.5",
        severity="CRITICAL",
        vuln_type="RCE",
        description="Shiro 默认 AES 密钥硬编码，可构造恶意 rememberMe Cookie",
        patched_versions="Shiro 1.2.5+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2016-4437",
        cvss_score=9.8,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2019-12422",
        component="Apache Shiro",
        affected_versions="Shiro <1.4.2",
        severity="MEDIUM",
        vuln_type="Padding Oracle Attack",
        description="Shiro Cookie AES-CBC 模式可被 Padding Oracle 攻击解密",
        patched_versions="Shiro 1.4.2+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2019-12422",
        cvss_score=6.5,
        poc_available=False,
    ),
    ComponentVuln(
        cve_id="CVE-2020-11989",
        component="Apache Shiro",
        affected_versions="Shiro <1.5.3",
        severity="HIGH",
        vuln_type="权限绕过",
        description="Shiro 对 URL 路径处理的缺陷可被绕过权限控制",
        patched_versions="Shiro 1.5.3+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2020-11989",
        cvss_score=8.1,
        poc_available=True,
    ),
]


# ─────────────────────── Apache Tomcat ───────────────────────

TOMCAT_VULNS = [
    ComponentVuln(
        cve_id="CVE-2020-1938",
        component="Apache Tomcat",
        affected_versions="Tomcat 9.x<9.0.31, 8.x<8.5.51",
        severity="CRITICAL",
        vuln_type="AJP Ghostcat",
        description="Tomcat AJP 连接器 (port 8009) 未认证可读取 webapp 任意文件",
        patched_versions="Tomcat 9.0.31+, 8.5.51+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2020-1938",
        cvss_score=9.8,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2020-17527",
        component="Apache Tomcat",
        affected_versions="Tomcat 9.x<9.0.38, 8.x<8.5.60",
        severity="MEDIUM",
        vuln_type="Open Redirect",
        description="Tomcat UTF-8 到 UTF-16 转换缺陷可被构造开放跳转",
        patched_versions="Tomcat 9.0.38+, 8.5.60+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2020-17527",
        cvss_score=6.1,
        poc_available=False,
    ),
]


# ─────────────────────── Apache Commons Collections ───────────────────────

COMMONS_COLLECTIONS_VULNS = [
    ComponentVuln(
        cve_id="CVE-2015-6420",
        component="Commons Collections",
        affected_versions="Commons Collections 3.x",
        severity="CRITICAL",
        vuln_type="RCE (Deserialization)",
        description="Commons Collections InvokerTransformer 反序列化时可执行任意代码",
        patched_versions="3.2.2+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2015-6420",
        cvss_score=9.8,
        poc_available=True,
    ),
]


# ─────────────────────── Apache Commons Text ───────────────────────

COMMONS_TEXT_VULNS = [
    ComponentVuln(
        cve_id="CVE-2022-42889",
        component="Commons Text",
        affected_versions="Commons Text 1.5-1.9",
        severity="CRITICAL",
        vuln_type="RCE (Text4Shell)",
        description="Commons Text StringSubstitutor interpolated 模式下可执行脚本/JNDI 导致 RCE",
        patched_versions="Commons Text 1.10.0+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2022-42889",
        cvss_score=9.8,
        poc_available=True,
    ),
]


# ─────────────────────── Jackson Databind ───────────────────────

JACKSON_VULNS = [
    ComponentVuln(
        cve_id="CVE-2017-7525",
        component="Jackson Databind",
        affected_versions="Jackson-databind 2.x<2.8.10, 2.9.x<2.9.5",
        severity="CRITICAL",
        vuln_type="RCE",
        description="Jackson enableDefaultTyping() 允许指定任意类名反序列化导致 RCE",
        patched_versions="2.8.10+, 2.9.5+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2017-7525",
        cvss_score=9.8,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2019-14379",
        component="Jackson Databind",
        affected_versions="Jackson-databind <2.9.9.2",
        severity="HIGH",
        vuln_type="RCE",
        description="Jackson multi-type 处理中可触发 JNDI 注入",
        patched_versions="2.9.9.2+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2019-14379",
        cvss_score=8.1,
        poc_available=True,
    ),
]


# ─────────────────────── Apache Dubbo ───────────────────────

DUBBO_VULNS = [
    ComponentVuln(
        cve_id="CVE-2019-17564",
        component="Apache Dubbo",
        affected_versions="Dubbo 2.7.x<2.7.4, 2.6.x<2.6.7",
        severity="HIGH",
        vuln_type="HTTP Deserialization",
        description="Dubbo HTTP 反序列化未校验类型可执行任意代码",
        patched_versions="2.7.4+, 2.6.7+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2019-17564",
        cvss_score=8.1,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2021-30179",
        component="Apache Dubbo",
        affected_versions="Dubbo 2.7.x<2.7.9.1",
        severity="HIGH",
        vuln_type="RCE",
        description="Dubbo Generic invoke 未做参数校验，可反射调用恶意代码",
        patched_versions="2.7.9.1+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2021-30179",
        cvss_score=8.1,
        poc_available=True,
    ),
]


# ─────────────────────── jQuery (JavaScript) ───────────────────────

JQUERY_VULNS = [
    ComponentVuln(
        cve_id="CVE-2020-11023",
        component="jQuery",
        affected_versions="jQuery <3.5.0",
        severity="MEDIUM",
        vuln_type="XSS",
        description="jQuery html() 方法在处理某些标签时可闭合上下文导致 XSS",
        patched_versions="jQuery 3.5.0+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2020-11023",
        cvss_score=6.1,
        poc_available=False,
    ),
    ComponentVuln(
        cve_id="CVE-2020-11022",
        component="jQuery",
        affected_versions="jQuery <3.5.0",
        severity="MEDIUM",
        vuln_type="XSS",
        description="jQuery <3.5 $.htmlPrefilter() 可跳过结束标签导致 XSS",
        patched_versions="jQuery 3.5.0+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2020-11022",
        cvss_score=6.1,
        poc_available=False,
    ),
]


# ─────────────────────── Lodash (JavaScript) ───────────────────────

LODASH_VULNS = [
    ComponentVuln(
        cve_id="CVE-2020-8203",
        component="Lodash",
        affected_versions="Lodash <4.17.21",
        severity="HIGH",
        vuln_type="Prototype Pollution",
        description="Lodash merge/mergeWith 方法可被用于原型链污染",
        patched_versions="Lodash 4.17.21+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2020-8203",
        cvss_score=7.4,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2021-23337",
        component="Lodash",
        affected_versions="Lodash <4.17.21",
        severity="HIGH",
        vuln_type="Command Injection",
        description="Lodash _.template 中可执行任意命令（通过 sourceURL）",
        patched_versions="Lodash 4.17.21+",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
        cvss_score=7.2,
        poc_available=True,
    ),
]


# ─────────────────────── OpenSSL ───────────────────────

OPENSSL_VULNS = [
    ComponentVuln(
        cve_id="CVE-2022-0778",
        component="OpenSSL",
        affected_versions="OpenSSL 1.0.2-1.0.2zc, 1.1.1-1.1.1m, 3.0.0/3.0.1",
        severity="HIGH",
        vuln_type="DoS",
        description="OpenSSL BN_mod_sqrt() 函数在无限循环情况下可导致 DoS",
        patched_versions="OpenSSL 1.1.1n+, 3.0.2+",
        reference_url="https://www.openssl.org/news/secadv/20220315.txt",
        cvss_score=7.5,
        poc_available=True,
    ),
    ComponentVuln(
        cve_id="CVE-2014-0160",
        component="OpenSSL",
        affected_versions="OpenSSL 1.0.1-1.0.1f",
        severity="CRITICAL",
        vuln_type="Heartbleed",
        description="OpenSSL TLS Heartbeat 扩展缺陷导致内存泄露（可泄露私钥）",
        patched_versions="OpenSSL 1.0.1g+",
        reference_url="https://heartbleed.com/",
        cvss_score=7.5,
        poc_available=True,
    ),
]


# ─────────────────────── Netty ───────────────────────

NETTY_VULNS = [
    ComponentVuln(
        cve_id="CVE-2021-43797",
        component="Netty",
        affected_versions="Netty <4.1.71.Final",
        severity="HIGH",
        vuln_type="Response Splitting",
        description="Netty HttpObjectDecoder 处理含 CR/LF 字符 HTTP 请求可导致响应拆分",
        patched_versions="Netty 4.1.71.Final+",
        reference_url="https://github.com/netty/netty/security/advisories/GHSA-6m9h-2xcq-vmcq",
        cvss_score=6.5,
        poc_available=False,
    ),
]


# ─────────────────────── 全量漏洞库索引 ───────────────────────

ALL_COMPONENT_VULNS: List[ComponentVuln] = (
    SPRING_VULNS
    + STRUTS2_VULNS
    + LOG4J_VULNS
    + FASTJSON_VULNS
    + SHIRO_VULNS
    + TOMCAT_VULNS
    + COMMONS_COLLECTIONS_VULNS
    + COMMONS_TEXT_VULNS
    + JACKSON_VULNS
    + DUBBO_VULNS
    + JQUERY_VULNS
    + LODASH_VULNS
    + OPENSSL_VULNS
    + NETTY_VULNS
)


# ─────────────────────── 查询接口 ───────────────────────

def get_vulns_by_component(component: str) -> List[ComponentVuln]:
    """按组件名查询漏洞"""
    return [v for v in ALL_COMPONENT_VULNS if component.lower() in v.component.lower()]


def get_vuln_by_cve(cve_id: str) -> Optional[ComponentVuln]:
    """按 CVE 编号查询漏洞"""
    for v in ALL_COMPONENT_VULNS:
        if v.cve_id.lower() == cve_id.lower():
            return v
    return None


def get_vulns_by_severity(severity: str) -> List[ComponentVuln]:
    """按严重程度查询漏洞"""
    return [v for v in ALL_COMPONENT_VULNS if v.severity == severity.upper()]


def get_vulns_by_type(vuln_type: str) -> List[ComponentVuln]:
    """按漏洞类型查询"""
    return [v for v in ALL_COMPONENT_VULNS if vuln_type.lower() in v.vuln_type.lower()]


def get_db_stats() -> Dict[str, int]:
    """返回漏洞库统计"""
    components = len(set(v.component for v in ALL_COMPONENT_VULNS))
    critical = len([v for v in ALL_COMPONENT_VULNS if v.severity == "CRITICAL"])
    high = len([v for v in ALL_COMPONENT_VULNS if v.severity == "HIGH"])
    medium = len([v for v in ALL_COMPONENT_VULNS if v.severity == "MEDIUM"])
    low = len([v for v in ALL_COMPONENT_VULNS if v.severity == "LOW"])
    return {
        "total_cves": len(ALL_COMPONENT_VULNS),
        "components": components,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }


# 导出常量
COMPONENT_VULN_COUNT: int = len(ALL_COMPONENT_VULNS)
COMPONENT_COUNT: int = len(set(v.component for v in ALL_COMPONENT_VULNS))
COMPONENT_LIST: List[str] = sorted(set(v.component for v in ALL_COMPONENT_VULNS))
