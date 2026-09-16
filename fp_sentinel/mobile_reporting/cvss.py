"""CVSS v3.1 评分引擎（玄鉴AI / fp_sentinel）。

提供简易 CVSS v3.1 向量计算器 :class:`CvssV31`、常见漏洞快捷评分字典
:data:`COMMON_FINDINGS`、以及针对 :class:`FindingReport` 的自动评分辅助函数
:func:`auto_score`、:func:`suggest_cvss`、:func:`explain_score`。

设计要点：

- 严格按 CVSS v3.1 规范公式计算 base_score 与 severity 档位；
- 仅依赖标准库，零外部依赖；
- ``auto_score`` 全程不修改 title/description 等审计字段，仅附加 cvss 元数据；
- 所有新字段向后兼容，旧数据零改造即可通过本模块。
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

__all__ = [
    "CvssV31",
    "COMMON_FINDINGS",
    "suggest_cvss",
    "auto_score",
    "explain_score",
]

# ─────────────────────────── 指标枚举 ───────────────────────────

_ATTACK_VECTOR_VALUES = {"ADJACENT": 0.65, "NETWORK": 0.85, "LOCAL": 0.55, "PHYSICAL": 0.2}
_COMPLEXITY_VALUES = {"HIGH": 0.44, "LOW": 0.77}
_PRIVILEGES_VALUES = {
    "NONE": 0.85,
    "LOW": 0.62,
    "HIGH": 0.27,
}
_PRIVILEGES_VALUES_SCOPE_CHG = {
    "NONE": 0.85,
    "LOW": 0.68,
    "HIGH": 0.50,
}
_USER_INTERACTION_VALUES = {"NONE": 0.85, "REQUIRED": 0.62}
_CIA_VALUES = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}

_VECTOR_LABEL_AV = {"ADJACENT": "A", "NETWORK": "N", "LOCAL": "L", "PHYSICAL": "P"}
_VECTOR_LABEL_AC = {"HIGH": "H", "LOW": "L"}
_VECTOR_LABEL_PR = {"NONE": "N", "LOW": "L", "HIGH": "H"}
_VECTOR_LABEL_UI = {"NONE": "N", "REQUIRED": "R"}
_VECTOR_LABEL_S = {"CHANGED": "C", "UNCHANGED": "U"}
_VECTOR_LABEL_CIA = {"NONE": "N", "LOW": "L", "HIGH": "H"}


def _normalize_enum(value: str, valid: set, default: str) -> str:
    """将输入规整为大写枚举值，不在合法集合内时回退默认值。"""
    upper = (value or "").strip().upper()
    return upper if upper in valid else default


def _score_to_severity(score: float) -> str:
    """CVSS v3.1 base 分数映射 severity 档位。"""
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def _severity_to_risk_level(severity: str) -> str:
    """CVSS severity 内部档位 -> 业务风险档位。"""
    mapping = {
        "NONE": "LOW",
        "LOW": "LOW",
        "MEDIUM": "MEDIUM",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL",
    }
    return mapping.get(severity.upper(), "MEDIUM")


def _safe_float(value: Any, default: float = 0.0) -> float:
    """安全浮点转换，失败回退默认值。"""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# ─────────────────────────── CvssV31 计算 ───────────────────────────


class CvssV31:
    """CVSS v3.1 基础评分计算器。

    用法::

        cv = CvssV31(
            AttackVector="NETWORK", Complexity="LOW",
            Privileges="NONE", UserInteraction="NONE",
            Scope="UNCHANGED",
            Confidentiality="HIGH", Integrity="HIGH", Availability="HIGH",
        )
        cv.base_score  # 9.8
        cv.severity    # CRITICAL
        cv.vector_string()  # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """

    def __init__(
        self,
        AttackVector: str = "NETWORK",
        Complexity: str = "LOW",
        Privileges: str = "NONE",
        UserInteraction: str = "NONE",
        Scope: str = "UNCHANGED",
        Confidentiality: str = "NONE",
        Integrity: str = "NONE",
        Availability: str = "NONE",
    ) -> None:
        self.av = _normalize_enum(AttackVector, set(_ATTACK_VECTOR_VALUES), "NETWORK")
        self.ac = _normalize_enum(Complexity, set(_COMPLEXITY_VALUES), "LOW")
        self.pr_key = _normalize_enum(Privileges, set(_PRIVILEGES_VALUES), "NONE")
        self.ui = _normalize_enum(UserInteraction, set(_USER_INTERACTION_VALUES), "NONE")
        self.scope_changed = (
            _normalize_enum(Scope, {"CHANGED", "UNCHANGED"}, "UNCHANGED") == "CHANGED"
        )
        self.c = _normalize_enum(Confidentiality, set(_CIA_VALUES), "NONE")
        self.i_key = _normalize_enum(Integrity, set(_CIA_VALUES), "NONE")
        self.a = _normalize_enum(Availability, set(_CIA_VALUES), "NONE")
        self._computed = False
        self._base_score = 0.0
        self._severity = "NONE"
        self._compute()

    def _compute(self) -> None:
        """按 CVSS v3.1 规范公式计算 base_score 和 severity。"""
        av_val = _ATTACK_VECTOR_VALUES[self.av]
        ac_val = _COMPLEXITY_VALUES[self.ac]
        pr_map = _PRIVILEGES_VALUES_SCOPE_CHG if self.scope_changed else _PRIVILEGES_VALUES
        pr_val = pr_map[self.pr_key]
        ui_val = _USER_INTERACTION_VALUES[self.ui]

        iss = 1.0 - (
            (1.0 - _CIA_VALUES[self.c])
            * (1.0 - _CIA_VALUES[self.i_key])
            * (1.0 - _CIA_VALUES[self.a])
        )

        if iss <= 0.0:
            self._base_score = 0.0
            self._severity = "NONE"
            self._computed = True
            return

        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

        if self.scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        raw = impact + exploitability
        if raw <= 0:
            base = 0.0
        elif self.scope_changed:
            base = min(1.08 * raw, 10.0)
        else:
            base = min(raw, 10.0)
        self._base_score = round(base, 1)
        if self._base_score == 0.0:
            self._severity = "NONE"
        else:
            self._severity = _score_to_severity(self._base_score)
        self._computed = True

    @property
    def base_score(self) -> float:
        """CVSS v3.1 base 分值（0.0-10.0，一位小数）。"""
        return self._base_score

    @property
    def severity(self) -> str:
        """CVSS severity 档位：NONE/LOW/MEDIUM/HIGH/CRITICAL。"""
        return self._severity

    def vector_string(self) -> str:
        """返回标准 CVSS:3.1/AV:N/AC:L/... 格式向量字符串。"""
        parts = [
            "CVSS:3.1",
            f"AV:{_VECTOR_LABEL_AV[self.av]}",
            f"AC:{_VECTOR_LABEL_AC[self.ac]}",
            f"PR:{_VECTOR_LABEL_PR[self.pr_key]}",
            f"UI:{_VECTOR_LABEL_UI[self.ui]}",
            f"S:{_VECTOR_LABEL_S['CHANGED' if self.scope_changed else 'UNCHANGED']}",
            f"C:{_VECTOR_LABEL_CIA[self.c]}",
            f"I:{_VECTOR_LABEL_CIA[self.i_key]}",
            f"A:{_VECTOR_LABEL_CIA[self.a]}",
        ]
        return "/".join(parts)

    @staticmethod
    def parse(vector_str: str) -> "CvssV31":
        """从 CVSS:3.1/... 向量字符串解析并构造计算器实例。

        Args:
            vector_str: 标准 CVSS v3.1 向量字符串。

        Returns:
            CvssV31 实例（指标解析失败时使用默认值）。
        """
        s = (vector_str or "").strip()
        # 反向映射
        av_rev = {v: k for k, v in _VECTOR_LABEL_AV.items()}
        ac_rev = {v: k for k, v in _VECTOR_LABEL_AC.items()}
        pr_rev = {v: k for k, v in _VECTOR_LABEL_PR.items()}
        ui_rev = {v: k for k, v in _VECTOR_LABEL_UI.items()}
        s_rev = {v: k for k, v in _VECTOR_LABEL_S.items()}
        cia_rev = {v: k for k, v in _VECTOR_LABEL_CIA.items()}

        kwargs: Dict[str, str] = {}
        for part in s.split("/"):
            part = part.strip()
            if ":" not in part:
                continue
            key, _, val = part.partition(":")
            key = key.strip().upper()
            val = val.strip().upper()
            if key == "AV":
                kwargs["AttackVector"] = av_rev.get(val, "NETWORK")
            elif key == "AC":
                kwargs["Complexity"] = ac_rev.get(val, "LOW")
            elif key == "PR":
                kwargs["Privileges"] = pr_rev.get(val, "NONE")
            elif key == "UI":
                kwargs["UserInteraction"] = ui_rev.get(val, "NONE")
            elif key == "S":
                kwargs["Scope"] = s_rev.get(val, "UNCHANGED")
            elif key == "C":
                kwargs["Confidentiality"] = cia_rev.get(val, "NONE")
            elif key == "I":
                kwargs["Integrity"] = cia_rev.get(val, "NONE")
            elif key == "A":
                kwargs["Availability"] = cia_rev.get(val, "NONE")
        return CvssV31(**kwargs)

    def __repr__(self) -> str:
        return (
            f"CvssV31(base_score={self.base_score}, "
            f"severity={self.severity}, "
            f"vector={self.vector_string()})"
        )


# ─────────────────────────── 快捷评分字典 ───────────────────────────

COMMON_FINDINGS: Dict[str, str] = {
    "硬编码凭据": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "硬编码密码": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "硬编码密钥": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "硬编码": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "Credentials": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "SQL注入": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "SQLi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "XSS反射": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "反射XSS": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "XSS存储": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:L",
    "存储XSS": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:L",
    "水平越权": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "BOLA": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "垂直越权": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "越权": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "未授权访问": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "未授权": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "敏感信息泄露": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "信息泄露": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "SSRF": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "目录遍历": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "目录词典": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "CSRF": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "弱密码策略": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "弱密码": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "HTTPS缺失": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "传输明文": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "Cookie无Secure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "Cookie无HttpOnly": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "验证码无防爆破": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "验证码": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "LFI": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "RFI": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "文件包含": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "命令注入": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "命令执行": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "硬编码AES密钥": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "AES弱密钥": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "AES密钥": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "备份文件泄露": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "备份文件": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "内部域名泄露": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "内网IP泄露": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "内网IP": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "内部域名": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
}


def _cvss_rank(severity: str) -> int:
    """返回 severity 排序权重（高=小数字，排序靠前）。"""
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    return order.get((severity or "").upper(), 99)


def _risk_rank(risk: str) -> int:
    """返回 risk_level 排序权重。"""
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return order.get((risk or "").upper(), 99)


def suggest_cvss(
    title: str,
    description: str = "",
    category: str = "",
    cwe_id: str = "",
) -> Dict[str, Any]:
    """按标题/描述关键词匹配 COMMON_FINDINGS，命中多条取最高分。

    Args:
        title: 漏洞标题。
        description: 漏洞描述（可选）。
        category: 分类（可选）。
        cwe_id: CWE 编号（可选）。

    Returns:
        dict: {cvss_score, cvss_vector, severity, matched_rule, explanation}。
        无匹配返回 {0.0, "", "UNKNOWN", "", ""}。
    """
    if not COMMON_FINDINGS:
        return {"cvss_score": 0.0, "cvss_vector": "", "severity": "UNKNOWN",
                "matched_rule": "", "explanation": ""}

    candidates: List[Tuple[str, str, float, str]] = []
    search_text = f"{title} {description} {category} {cwe_id}".lower()

    for keyword, vector in COMMON_FINDINGS.items():
        if keyword.lower() in search_text:
            try:
                cv = CvssV31.parse(vector)
                candidates.append((keyword, cv.vector_string(), cv.base_score, cv.severity))
            except Exception:  # noqa: BLE001 - 容错匹配
                logger.debug("关键词 %r 对应的向量解析失败: %s", keyword, vector)
                continue

    if not candidates:
        return {"cvss_score": 0.0, "cvss_vector": "", "severity": "UNKNOWN",
                "matched_rule": "", "explanation": ""}

    # 取最高分，分数相同时按 severity 档位排序
    candidates.sort(key=lambda x: (-x[2], _cvss_rank(x[3])))
    best = candidates[0]
    keywords = ", ".join(c[0] for c in candidates)

    return {
        "cvss_score": best[2],
        "cvss_vector": best[1],
        "severity": best[3],
        "matched_rule": keywords,
        "explanation": (
            f"基于关键词 {keywords} 匹配得到 CVSS v3.1 向量 {best[1]}，"
            f"基础分 {best[1]}，严重程度 {best[3]}。"
        ),
    }


def auto_score(finding: Any) -> Any:
    """给 finding 附带 CVSS 评分字段（cvss_score / cvss_vector / risk_level）。

    仅当 cvss > 0 且（原 severity 为空/UNKNOWN 或 cvss 档位更高）时覆盖
    severity 字段，否则保留原 severity；全程不修改 title/description 等审计字段。

    Args:
        finding: FindingReport 实例或兼容对象。

    Returns:
        原 finding 实例（原地附加 cvss 字段）。
    """
    title = ""
    description = ""
    category = ""
    cwe_id = ""
    try:
        title = str(getattr(finding, "title", "") or "")
        description = str(getattr(finding, "description", "") or "")
        category = str(getattr(finding, "category", "") or "")
        cwe_id = str(getattr(finding, "cwe_id", "") or "")
    except Exception:  # noqa: BLE001
        pass

    result = suggest_cvss(title=title, description=description,
                          category=category, cwe_id=cwe_id)

    # 仅当 cvss > 0 时写入 cvss 字段
    if result["cvss_score"] > 0:
        setattr(finding, "cvss_score", result["cvss_score"])
        setattr(finding, "cvss_vector", result["cvss_vector"])
        severity = result["severity"]
        if severity != "UNKNOWN":
            setattr(finding, "risk_level", _severity_to_risk_level(severity))
            try:
                original = str(getattr(finding, "severity", "") or "").strip().upper()
            except Exception:  # noqa: BLE001
                original = ""
            # 仅当原 severity 为空/UNKNOWN/INFO 或新档位更高时覆盖
            if not original or original in ("UNKNOWN", "INFO"):
                setattr(finding, "severity", severity)
            elif _cvss_rank(severity) < _cvss_rank(original):
                setattr(finding, "severity", severity)
    return finding


def explain_score(
    finding: Any = None,
    score: Optional[float] = None,
    vector: Optional[str] = None,
) -> str:
    """生成 2-4 句中文 CVSS 评分说明（典型攻击场景 + 业务影响 + 缓解建议）。

    Args:
        finding: FindingReport 实例（可选，用于推断上下文）。
        score: 明确的分数值（可选，优先于 finding.cvss_score）。
        vector: 明确的向量字符串（可选）。

    Returns:
        2-4 句中文说明文本。
    """
    if score is not None:
        s = _safe_float(score)
    elif finding is not None:
        try:
            s = _safe_float(getattr(finding, "cvss_score", 0.0))
        except Exception:  # noqa: BLE001
            s = 0.0
    else:
        s = 0.0

    sev = _score_to_severity(s)
    # title context (reserved for future use in explanation text)
    if finding is not None:
        try:
            getattr(finding, "title", "")
        except Exception:  # noqa: BLE001
            pass

    # 提取 AV 等关键指标特征
    av_hint = ""
    if vector:
        av_match = re.search(r"AV:([NALP])", vector)
        if av_match:
            av_label = {"N": "网络", "A": "邻接", "L": "本地", "P": "物理"}
            av_hint = av_label.get(av_match.group(1), "")

    severity_descriptions = {
        "CRITICAL": (
            f"该漏洞 CVSS 基础分 {s} 属于严重（CRITICAL）级别，"
            f"攻击者可在{'远程' if av_hint == '网络' else av_hint}条件下无需交互即可利用，"
            f"影响范围涵盖机密性、完整性与可用性三个维度。"
            f"建议立即启动应急响应，在修复前下线受影响资产并通知相关方。"
        ),
        "HIGH": (
            f"该漏洞 CVSS 基础分 {s} 属于高危（HIGH）级别，"
            f"攻击者可在{'远程' if av_hint == '网络' else av_hint}条件下利用该问题造成重大影响。"
            f"建议将其纳入紧急修复排期，一周内完成修复并复测。"
        ),
        "MEDIUM": (
            f"该漏洞 CVSS 基础分 {s} 属于中危（MEDIUM）级别，"
            f"需要一定的前置条件或用户交互才可被利用。"
            f"建议在下一迭代版本中修复，临时可通过访问控制或输入校验降低利用可能。"
        ),
        "LOW": (
            f"该漏洞 CVSS 基础分 {s} 属于低危（LOW）级别，"
            f"利用受限且影响范围有限，但仍存在信息泄露或被组合利用的风险。"
            f"建议择期修复，在代码清理或重构时一并处理。"
        ),
        "NONE": (
            f"该漏洞 CVSS 基础分 {s}，暂无实质性安全影响或评分信息不足。"
            f"建议结合业务上下文做进一步评估，必要时补充复现与证据。"
        ),
    }
    return severity_descriptions.get(sev, severity_descriptions["NONE"])
