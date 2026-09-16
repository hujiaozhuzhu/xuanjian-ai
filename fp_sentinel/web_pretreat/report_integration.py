"""Web 预处理 → 标准 FindingReport 的转换器。

把 :class:`~fp_sentinel.web_pretreat.js_pretreat.JsPreprocessResult` 等预处理结果
转换为 :class:`~fp_sentinel.mobile_reporting.models.report_models.FindingReport`，
便于统一走报告流水线（HTML / DOCX / Excel / POC 集成）。

CWE 映射：

- eval / Function() 动态执行 → CWE-95 (Eval Injection)
- document.write / innerHTML 拼接 → CWE-79 (XSS)
- URL / 端点信息收集 → CWE-200 (Information Exposure)
- 硬编码密钥 / token 字面量 → CWE-798 (Use of Hard-coded Credentials)
- Packer / 混淆特征 → CWE-94 (Improper Control of Generation of Code)
"""

from __future__ import annotations

import logging
import uuid
from typing import Dict, List

from fp_sentinel.mobile_reporting.models.report_models import (
    Evidence,
    FindingReport,
)

logger = logging.getLogger(__name__)

__all__ = ["js_audit_to_findings"]

# ── CWE 映射常量 ──

_CWE_EVAL: str = "CWE-95"
_CWE_XSS: str = "CWE-79"
_CWE_INFO_EXPOSURE: str = "CWE-200"
_CWE_HARDCODED_CRED: str = "CWE-798"
_CWE_CODE_INJECTION: str = "CWE-94"

# 严重度定义
_SEVERITY_CRITICAL: str = "CRITICAL"
_SEVERITY_HIGH: str = "HIGH"
_SEVERITY_MEDIUM: str = "MEDIUM"
_SEVERITY_LOW: str = "LOW"
_SEVERITY_INFO: str = "INFO"


# ── 内部辅助 ──

def _make_finding_id(prefix: str) -> str:
    """生成带前缀的 finding ID (足够唯一即可)。"""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _severity_for_suspicious(pattern_type: str) -> str:
    """根据可疑片段类型给严重度。"""
    if pattern_type in {"eval_function", "function_constructor", "function_call"}:
        return _SEVERITY_HIGH
    if pattern_type in {"document_write", "inner_html_assign", "script_inject"}:
        return _SEVERITY_HIGH
    if pattern_type in {"atob_decode", "unescape_packed", "fromcharcode"}:
        return _SEVERITY_MEDIUM
    return _SEVERITY_LOW


def _cwe_for_suspicious(pattern_type: str) -> str:
    """根据可疑片段类型返回对应 CWE。"""
    if pattern_type in {"eval_function", "function_constructor", "function_call"}:
        return _CWE_EVAL
    if pattern_type in {"document_write", "inner_html_assign", "script_inject"}:
        return _CWE_XSS
    if pattern_type in {"atob_decode", "unescape_packed", "fromcharcode"}:
        return _CWE_CODE_INJECTION
    return _CWE_CODE_INJECTION


# ── 主函数 ──

def js_audit_to_findings(
    file_path: str,
    prettify_result: str,
    extract_result: List[Dict[str, str]],
    suspicious: List[Dict[str, str]],
    apis: List[Dict[str, str]],
) -> List[FindingReport]:
    """把 JS 预处理结果转换为标准 FindingReport 列表。

    Parameters
    ----------
    file_path:
        原始 JS 文件路径（用于 locating finding）。
    prettify_result:
        美化后的源码字符串（作为完整证据的上下文）。
    extract_result:
        :meth:`JsPrettier.extract_strings` 的输出。
    suspicious:
        :meth:`JsPrettier.find_suspicious` 的输出。
    apis:
        :meth:`JsPrettier.find_api_patterns` 的输出。

    Returns
    -------
    list[FindingReport]
        一个 FindingReport 对应一种风险类别（eval/xss/exposure/hardcoded）；
        没有命中项则返回空列表（调用方决定是否继续）。
    """
    findings: List[FindingReport] = []

    # ── 1. eval / Function 动态执行 ──────────────────
    eval_items = [
        s for s in suspicious
        if s.get("pattern_type") in {"eval_function", "function_constructor", "function_call"}
    ]
    if eval_items:
        evidences: List[Evidence] = []
        for item in eval_items:
            evidences.append(Evidence(
                id=_make_finding_id("eval-ev"),
                location=f"{file_path}:{item.get('line', '?')}",
                content=item.get("snippet", ""),
                description=f"match: {item.get('match_text', '')}",
                source="静态",
            ))
        findings.append(FindingReport(
            id=_make_finding_id("eval"),
            title="[JS] eval / Function() 动态执行",
            severity=_severity_for_suspicious(eval_items[0]["pattern_type"]),
            cwe_id=_CWE_EVAL,
            category="dynamic_execution",
            description=(
                "代码中存在 eval / new Function / Function() 形式的动态执行调用，"
                "可能被用于执行用户输入导致远程代码执行或 XSS。审计员应检查传入"
                "参数是否可被外部控制。"
            ),
            evidence=evidences,
            remediation=(
                "避免使用 eval / Function() 构造器；如需动态逻辑请用白名单映射 / "
                "JSON.parse 替代；必须使用时严格校验输入。"
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/95.html",
                (
                    "https://developer.mozilla.org/en-US/docs/Web/JavaScript/"
                    "Reference/Global_Objects/eval"
                ),
            ],
            tool_version="web_pretreat.js_pretreat",
            confidence=0.7,
        ))

    # ── 2. XSS (document.write / innerHTML) ─────────
    xss_items = [
        s for s in suspicious
        if s.get("pattern_type") in {"document_write", "inner_html_assign", "script_inject"}
    ]
    if xss_items:
        xss_evidences: List[Evidence] = []
        for item in xss_items:
            xss_evidences.append(Evidence(
                id=_make_finding_id("xss-ev"),
                location=f"{file_path}:{item.get('line', '?')}",
                content=item.get("snippet", ""),
                description=f"match: {item.get('match_text', '')}",
                source="静态",
            ))
        findings.append(FindingReport(
            id=_make_finding_id("xss"),
            title="[JS] XSS 风险：document.write / innerHTML 拼接",
            severity=_severity_for_suspicious(xss_items[0]["pattern_type"]),
            cwe_id=_CWE_XSS,
            category="xss",
            description=(
                "代码中存在 document.write / innerHTML = / createElement('script') 等动态 DOM 操作。"
                "若其输入源可被外部控制，攻击者可注入恶意 HTML/JS，导致存储型或反射型 XSS。"
            ),
            evidence=xss_evidences,
            remediation=(
                "使用 textContent / createTextNode 替代 innerHTML；"
                "必须拼接 HTML 时需要做严格转义（DOMPurify / sanitize-html）；"
                "CSP 作为纵深防护。"
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/79.html",
                (
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                ),
            ],
            tool_version="web_pretreat.js_pretreat",
            confidence=0.65,
        ))

    # ── 3. URL / 端点信息收集 ────────────────────────
    # 端点信息收集本身不构成漏洞，但属于 CWE-200 类型（信息暴露给审计
    # 流程的攻击面梳理），给 INFO 级别独立 finding
    if apis:
        url_evidences: List[Evidence] = []
        for item in apis[:20]:  # 截断到前 20 条避免膨胀
            url_evidences.append(Evidence(
                id=_make_finding_id("url-ev"),
                location=f"{file_path}:{item.get('line', '?')}",
                content=item.get("snippet", ""),
                description=f"pattern_type: {item.get('pattern_type', '')}",
                source="静态",
            ))
        findings.append(FindingReport(
            id=_make_finding_id("info-url"),
            title="[JS] URL / 端点信息暴露 (攻击面梳理)",
            severity=_SEVERITY_INFO,
            cwe_id=_CWE_INFO_EXPOSURE,
            category="api_surface",
            description=(
                "在 JS 代码中发现如下 URL / 端点拼接模式："
                "通常需要结合后端验证是否真正生效；此 finding 给审计流程"
                "提示可能存在的 HTTP 接口入口。"
            ),
            evidence=url_evidences,
            remediation="无所谓修复，属于攻击面信息梳理；后续可对照 API 文档确认有效性。",
            references=[
                "https://cwe.mitre.org/data/definitions/200.html",
            ],
            tool_version="web_pretreat.js_pretreat",
            confidence=0.5,
        ))

    # ── 4. 硬编码密钥 / token ────────────────────────
    secret_items = [
        s for s in extract_result
        if s.get("tag") == "secret_like"
    ]
    if secret_items:
        cred_evidences: List[Evidence] = []
        for item in secret_items:
            # 对真实值做部分遮蔽，避免报告外泄
            raw = item.get("value", "")
            masked = raw[:4] + "****" + raw[-4:] if len(raw) > 8 else "****"
            cred_evidences.append(Evidence(
                id=_make_finding_id("cred-ev"),
                location=f"{file_path}:{item.get('line', '?')}",
                content=item.get("snippet", ""),
                description=f"masked_value: {masked}",
                source="静态",
            ))
        findings.append(FindingReport(
            id=_make_finding_id("cred"),
            title="[JS] 疑似硬编码密钥 / token",
            severity=_SEVERITY_MEDIUM,
            cwe_id=_CWE_HARDCODED_CRED,
            category="hardcoded_credential",
            description=(
                "JS 源码中存在包含 ``key/token/secret/apikey`` 字样的字面量字符串，"
                "疑似将敏感凭证硬编码在客户端代码中。前端代码可被任意用户获取，"
                "硬编码凭证一旦泄露可被滥用，请核查其权限范围并考虑迁移至后端。"
            ),
            evidence=cred_evidences,
            remediation=(
                "把密钥 / token 迁移到后端鉴权流程；前端通过短期可撤销的会话凭证"
                "（如 jwt with short ttl）与后端交互；"
                "如确为公开 key 请明确标识行为 'publishable key' 并限制其作用域。"
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/798.html",
            ],
            tool_version="web_pretreat.js_pretreat",
            confidence=0.6,
        ))

    # ── 5. Packer / 混淆 ─────────────────────────────
    # 通过 suspicious 中的 atob / unescape / fromcharcode 提示
    packer_items = [
        s for s in suspicious
        if s.get("pattern_type") in {"atob_decode", "unescape_packed", "fromcharcode"}
    ]
    if packer_items:
        packer_evidences: List[Evidence] = []
        for item in packer_items:
            packer_evidences.append(Evidence(
                id=_make_finding_id("packer-ev"),
                location=f"{file_path}:{item.get('line', '?')}",
                content=item.get("snippet", ""),
                description=f"match: {item.get('match_text', '')}",
                source="静态",
            ))
        findings.append(FindingReport(
            id=_make_finding_id("packer"),
            title="[JS] 使用 atob / unescape / 字符拼接进行代码隐藏",
            severity=_SEVERITY_MEDIUM,
            cwe_id=_CWE_CODE_INJECTION,
            category="obfuscation",
            description=(
                "代码中大量使用 atob() / unescape('%xx') / String.fromCharCode() 进行"
                "字符串拼接，这是典型 JS packer / 混淆特征。本身不代表漏洞，但会严重"
                "影响静态审计效率，并经常是恶意代码逃避检测的手段。"
            ),
            evidence=packer_evidences,
            remediation=(
                "使用专业反混淆工具 (de4js / JStillery / unpack.xenary) 先解密再分析；"
                "尽量联系开发方获取 source map 或未混淆的原始版本。"
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/94.html",
                "https://github.com/jstillery/jstillery",
            ],
            tool_version="web_pretreat.js_pretreat",
            confidence=0.55,
        ))

    logger.info("JS 预处理结果转换为 %d 条 FindingReport", len(findings))
    return findings
