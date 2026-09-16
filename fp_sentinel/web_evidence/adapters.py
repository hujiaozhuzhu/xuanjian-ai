"""Web 漏洞证据 → FindingReport 适配器。

将 Burp / ZAP / Nuclei 等工具输出的原始告警/结果，
统一转换为
:class:`~fp_sentinel.mobile_reporting.models.report_models.FindingReport`，
便于下游报告模块消费。

设计原则：
- 严重度通过 :func:`normalize_severity` 统一映射，无法识别一律降级为 INFO；
- CWE 编号通过 :func:`extract_cwe` 统一提取；
- 单条转换失败 → 记录 warning + 返回 None，绝不抛异常、不中断整批。
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional, Sequence

from fp_sentinel.mobile_reporting.models.report_models import FindingReport

__all__ = [
    "normalize_severity",
    "extract_cwe",
    "burp_alert_to_finding",
    "nuclei_result_to_finding",
    "zap_alert_to_finding",
    "manual_finding",
]

logger = logging.getLogger(__name__)

#: Burp Suite 严重度别名映射（不区分大小写） → 标准值
_SEVERITY_ALIASES: dict[str, str] = {
    "information": "INFO",
    "info": "INFO",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}

#: Burp 原始 severity 字符串 → 标准值（保留原始名词映射方便精确匹配）
_BURP_SEVERITY_MAP: dict[str, str] = {
    "Information": "INFO",
    "Medium": "MEDIUM",
    "High": "HIGH",
}


def normalize_severity(severity: object) -> str:
    """将任意严重度字符串归一化为合法标准值。

    处理流程：
    1. ``str(severity or "").upper().strip()``
    2. 已是合法值（CRITICAL/HIGH/MEDIUM/LOW/INFO）则直接返回
    3. 查别名映射表
    4. 无法识别 → 返回 ``"INFO"``

    Args:
        severity: 任意类型的严重度输入（字符串 / None / 其他）

    Returns:
        大写的标准 severity 字符串；绝不抛异常
    """
    from fp_sentinel.mobile_reporting.models.report_models import (
        VALID_SEVERITIES,
    )

    if severity is None:
        return "INFO"
    try:
        cleaned = str(severity).strip().upper()
    except Exception:
        return "INFO"
    if not cleaned:
        return "INFO"
    if cleaned in VALID_SEVERITIES:
        return cleaned
    # 处理带括号的 "HIGH (HIGH)" 这类 ZAP 风险描述中直接取第一个 token
    first_token = cleaned.split()[0] if cleaned else ""
    if first_token in VALID_SEVERITIES:
        return first_token
    alias = _SEVERITY_ALIASES.get(cleaned.lower())
    if alias:
        return alias
    # 含 HIGH / MEDIUM 之类的子串
    for token in cleaned.replace("(", " ").replace(")", " ").split():
        if token in VALID_SEVERITIES:
            return token
        alias = _SEVERITY_ALIASES.get(token.lower())
        if alias:
            return alias
    return "INFO"


def extract_cwe(text: object) -> str:
    """从文本中第一个匹配的 ``CWE-NNN`` 编号提取并返回。

    多个匹配取第一个；无匹配返回空字符串。

    Args:
        text: 任意文本（非字符串会被 str() 转换）

    Returns:
        CWE 编号字符串（如 ``"CWE-89"``）或空字符串；绝不抛异常
    """
    if text is None:
        return ""
    try:
        content = str(text)
    except Exception:
        return ""
    match = re.search(r"CWE-\d{2,}", content)
    if match:
        return match.group(0)
    return ""


# ────────────────────────── 各工具适配函数 ──────────────────────────


def burp_alert_to_finding(
    alert: dict,
    default_severity: str = "MEDIUM",
) -> Optional[FindingReport]:
    """将 Burp Suite 单条 issue 转换为 :class:`FindingReport`。

    兼容字段：
    - ``name`` → title
    - ``host`` + ``path`` → evidence location / url
    - ``severity`` → normalize_severity
    - ``confidence`` → confidence
    - ``issueDetail`` → description
    - ``remediationBackground`` → remediation
    - ``references`` → references 列表
    - 若不存在 cwe_id，从 description 中正则提取

    Args:
        alert: Burp 导出 issue dict
        default_severity: severity 缺失时的默认值

    Returns:
        转换后的 FindingReport，或失败时返回 None（已记录 warning）
    """
    try:
        title = str(alert.get("name", "") or "").strip()
        host = str(alert.get("host", "") or "").strip()
        path = str(alert.get("path", "") or "").strip()
        url = f"{host}{path}" if host else path

        severity = normalize_severity(
            alert.get("severity") or default_severity
        )
        confidence_raw = alert.get("confidence", 0.5)
        try:
            confidence_val = float(confidence_raw)
            confidence_val = max(0.0, min(1.0, confidence_val))
        except (TypeError, ValueError):
            confidence_val = 0.5

        issue_detail = str(alert.get("issueDetail", "") or "")
        remediation = str(alert.get("remediationBackground", "") or "")
        references_raw = alert.get("references") or []
        if isinstance(references_raw, str):
            references = [references_raw]
        else:
            references = [str(r) for r in references_raw]

        cwe = str(alert.get("cwe_id", "") or "").strip()
        if not cwe:
            cwe = extract_cwe(issue_detail)

        # 构建证据对象
        evidences: List = []
        if url:
            from fp_sentinel.mobile_reporting.models.report_models import (
                Evidence,
            )

            evidences.append(
                Evidence(
                    id="url-1",
                    location=url,
                    content=url,
                    description=f"Burp Suite 发现: {title}",
                    source="静态",
                )
            )

        return FindingReport(
            id=title or f"BURP-{hash(str(alert)) & 0xFFFFFF:06X}",
            title=title or "未命名 Burp 告警",
            severity=severity,
            cwe_id=cwe,
            description=issue_detail,
            evidence=evidences,
            remediation=remediation,
            references=references,
            tool_version="Burp Suite",
            confidence=confidence_val,
        )
    except Exception as exc:
        logger.warning("Burp 告警转换失败，已跳过: %s (alert=%r)", exc, alert)
        return None


def nuclei_result_to_finding(result: dict) -> Optional[FindingReport]:
    """将 Nuclei 单条扫描结果转换为 :class:`FindingReport`。

    兼容字段：
    - ``template-id`` → 作为 id / 分类
    - ``matcher-name`` → title（若缺失用 template-id 兜底）
    - ``matched-at`` → URL / evidence location
    - ``info.name`` → title（当 matcher-name 为空）
    - ``info.severity`` → normalize_severity
    - ``info.description`` → description
    - ``info.tags`` → category
    - ``extracted-results`` → 写入 evidence content

    Args:
        result: Nuclei JSON 输出单行 dict

    Returns:
        转换后的 FindingReport，或失败时返回 None
    """
    try:
        template_id = str(result.get("template-id", "") or "").strip()
        matcher_name = str(result.get("matcher-name", "") or "").strip()
        matched_at = str(result.get("matched-at", "") or "").strip()

        info = result.get("info") or {}
        if not isinstance(info, dict):
            info = {}

        title_candidate = (
            matcher_name
            or str(info.get("name", "") or "").strip()
            or template_id
            or "未命名 Nuclei 告警"
        )
        severity = normalize_severity(info.get("severity"))
        description = str(info.get("description", "") or "")
        tags_raw = info.get("tags") or []
        if isinstance(tags_raw, (list, tuple)):
            category = ",".join(str(t) for t in tags_raw)
        else:
            category = str(tags_raw)

        extracted = result.get("extracted-results") or []
        if not isinstance(extracted, (list, tuple)):
            extracted = [str(extracted)]
        extracted_text = "\n".join(str(x) for x in extracted)

        # 构建证据
        from fp_sentinel.mobile_reporting.models.report_models import Evidence

        evidences: list = []
        if matched_at:
            evidences.append(
                Evidence(
                    id="matched-url",
                    location=matched_at,
                    content=extracted_text or matched_at,
                    description="Nuclei 匹配目标",
                    source="动态",
                )
            )
        elif extracted_text:
            evidences.append(
                Evidence(
                    id="extracted-1",
                    location="<无URL>",
                    content=extracted_text,
                    description="Nuclei 提取结果",
                    source="动态",
                )
            )

        return FindingReport(
            id=template_id or f"NUC-{hash(str(result)) & 0xFFFFFF:06X}",
            title=title_candidate,
            severity=severity,
            cwe_id=extract_cwe(f"{description} {title_candidate}"),
            category=category,
            description=description,
            evidence=evidences,
            remediation="请参考 Nuclei 模板文档及厂商安全公告进行修复。",
            references=[
                "https://github.com/projectdiscovery/nuclei-templates",
            ],
            tool_version="Nuclei",
            confidence=0.7 if matched_at else 0.5,
        )
    except Exception as exc:
        logger.warning("Nuclei 结果转换失败，已跳过: %s (result=%r)", exc, result)
        return None


def zap_alert_to_finding(alert: dict) -> Optional[FindingReport]:
    """将 OWASP ZAP 单条 alert 转换为 :class:`FindingReport`。

    兼容字段：
    - ``name`` → title
    - ``riskdesc`` → severity（取首单词映射）
    - ``cweid`` → cwe_id
    - ``desc`` → description
    - ``uri`` → evidence location
    - ``solution`` → remediation
    - ``instances`` → 批量作为 references

    Args:
        alert: ZAP JSON report 单条 alert dict

    Returns:
        转换后的 FindingReport，或失败时返回 None
    """
    try:
        title = str(alert.get("name", "") or "").strip()
        riskdesc = str(alert.get("riskdesc", "") or "").strip()
        severity = normalize_severity(riskdesc)

        cwe_raw = str(alert.get("cweid", "") or "").strip()
        if cwe_raw and cwe_raw.isdigit():
            cwe = f"CWE-{cwe_raw}"
        else:
            cwe = cwe_raw

        description = str(alert.get("desc", "") or "")
        # 也尝试从 description 中提取 CWE
        if not cwe:
            cwe = extract_cwe(description)

        uri = str(alert.get("uri", "") or "").strip()
        solution = str(alert.get("solution", "") or "")

        # instances → references
        instances = alert.get("instances") or []
        references: list[str] = []
        if isinstance(instances, (list, tuple)):
            for inst in instances:
                if isinstance(inst, dict):
                    inst_uri = str(inst.get("uri", "") or "").strip()
                    if inst_uri:
                        references.append(inst_uri)
                else:
                    references.append(str(inst))
        # 把主 uri 也作为 evidence
        from fp_sentinel.mobile_reporting.models.report_models import Evidence

        evidences: list = []
        if uri:
            evidences.append(
                Evidence(
                    id="zap-uri-1",
                    location=uri,
                    content=uri,
                    description=f"ZAP 发现: {title}",
                    source="动态",
                )
            )

        return FindingReport(
            id=title or f"ZAP-{hash(str(alert)) & 0xFFFFFF:06X}",
            title=title or "未命名 ZAP 告警",
            severity=severity,
            cwe_id=cwe,
            description=description,
            evidence=evidences,
            remediation=solution,
            references=references,
            tool_version="OWASP ZAP",
            confidence=0.6,
        )
    except Exception as exc:
        logger.warning("ZAP 告警转换失败，已跳过: %s (alert=%r)", exc, alert)
        return None


def manual_finding(
    id: str,
    title: str,
    severity: str,
    cwe_id: str = "",
    description: str = "",
    evidence: str = "",
    remediation: str = "",
    repro_steps: Sequence[str] = (),
    references: Sequence[str] = (),
) -> Optional[FindingReport]:
    """手工录入漏洞条目，包装为标准 :class:`FindingReport`。

    所有字段做必要类型转换，不合法输入自动降级。

    Args:
        id: 漏洞唯一标识
        title: 漏洞标题
        severity: 严重度（任意格式，经 normalize_severity 归一化）
        cwe_id: CWE 编号
        description: 漏洞描述
        evidence: 证据内容
        remediation: 修复建议
        repro_steps: 复现步骤列表
        references: 参考链接列表

    Returns:
        转换后的 FindingReport，或失败时返回 None
    """
    try:
        from fp_sentinel.mobile_reporting.models.report_models import Evidence

        evidences: list = []
        if evidence and str(evidence).strip():
            evidences.append(
                Evidence(
                    id=f"manual-ev-{id}",
                    location="<手工录入>",
                    content=str(evidence),
                    description="手工录入证据",
                    source="静态",
                )
            )

        ref_list = list(references) if references else []

        clean_id = str(id or f"MAN-{hash(title) & 0xFFFFFF:06X}").strip()
        clean_cwe = str(cwe_id or "").strip()
        if not clean_cwe:
            clean_cwe = extract_cwe(description)

        return FindingReport(
            id=clean_id,
            title=str(title or clean_id).strip(),
            severity=normalize_severity(severity),
            cwe_id=clean_cwe,
            description=str(description or "").strip(),
            evidence=evidences,
            remediation=str(remediation or "").strip(),
            references=ref_list,
            tool_version="manual",
            confidence=0.5,
        )
    except Exception as exc:
        logger.warning("手工录入转换失败，已跳过: %s (id=%r)", exc, id)
        return None
