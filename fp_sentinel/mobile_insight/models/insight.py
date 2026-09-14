"""mobile_insight.models —— 提示数据模型(规划文档 2.4.3)。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

__all__ = [
    "Severity",
    "InsightCategory",
    "DifficultyLevel",
    "CodeLocation",
    "TechnicalInsight",
    "InsightReport",
]


class Severity(Enum):
    """严重级别(值越大越严重, 供排序)。"""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: "Severity | str") -> "Severity":
        if isinstance(value, cls):
            return value
        try:
            return cls[str(value).upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc


class InsightCategory(Enum):
    """提示分类(规划文档 2.4.3)。"""

    CRYPTO = "CRYPTO"
    NETWORK = "NETWORK"
    STORAGE = "STORAGE"
    COMPONENT = "COMPONENT"
    ANTI_ANALYSIS = "ANTI"
    PRIVACY = "PRIVACY"

    @classmethod
    def parse(cls, value: "InsightCategory | str") -> "InsightCategory":
        if isinstance(value, cls):
            return value
        try:
            return cls[str(value).upper()]
        except KeyError as exc:
            raise ValueError(f"unknown insight category: {value!r}") from exc


class DifficultyLevel(Enum):
    """建议技法执行难度。"""

    LOW = "低"
    MEDIUM = "中"
    HIGH = "高"


@dataclass
class CodeLocation:
    """代码位置。"""

    file: str = ""
    class_name: str = ""
    method_name: str = ""
    line: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "line": self.line,
        }


@dataclass
class TechnicalInsight:
    """关键技术提示。"""

    id: str
    title: str
    category: InsightCategory
    severity: Severity
    confidence: float

    description: str
    affected_component: str
    code_reference: CodeLocation = field(default_factory=CodeLocation)

    technical_context: str = ""            # 技术上下文(给分析者的指引)
    suggested_technique: str = ""          # 建议技法(对齐③的 7 种技法/POC goal)
    estimated_difficulty: DifficultyLevel = DifficultyLevel.MEDIUM

    next_steps: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)      # CWE 编号
    masvs_refs: List[str] = field(default_factory=list)   # OWASP MASVS 引用
    references: List[str] = field(default_factory=list)   # 参考文档

    auto_fixable: bool = False
    fix_hint: Optional[str] = None

    # 规则出处(便于溯源与去重)
    rule_id: str = ""
    evidence: List[str] = field(default_factory=list)
    # NEW-06: 归属分类(business/library/framework/obfuscated), 由引擎回填
    classification: str = "business"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.name,
            "confidence": self.confidence,
            "description": self.description,
            "affected_component": self.affected_component,
            "code_reference": self.code_reference.to_dict(),
            "technical_context": self.technical_context,
            "suggested_technique": self.suggested_technique,
            "estimated_difficulty": self.estimated_difficulty.value,
            "next_steps": self.next_steps,
            "cwe_ids": self.cwe_ids,
            "masvs_refs": self.masvs_refs,
            "references": self.references,
            "auto_fixable": self.auto_fixable,
            "fix_hint": self.fix_hint,
            "evidence": self.evidence[:10],
            "classification": self.classification,
        }


@dataclass
class InsightReport:
    """一次提示扫描的聚合结果。"""

    target: str
    insights: List[TechnicalInsight]
    rules_total: int = 0
    rules_matched: int = 0
    duration_sec: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "insight_count": len(self.insights),
            "rules_total": self.rules_total,
            "rules_matched": self.rules_matched,
            "duration_sec": round(self.duration_sec, 4),
            "severity_distribution": {
                sev.name: sum(1 for i in self.insights if i.severity == sev)
                for sev in Severity
            },
            # NEW-06: 按类名来源分类的分布统计
            "classification_distribution": {
                cls: sum(1 for i in self.insights if i.classification == cls)
                for cls in ("business", "library", "framework", "obfuscated", "unattributed")
                if any(i.classification == cls for i in self.insights)
            },
            "insights": [i.to_dict() for i in self.insights],
        }

    def grouped_by_classification(self) -> Dict[str, List[TechnicalInsight]]:
        """NEW-06: 按 business/library/framework/obfuscated 分组返回发现。"""
        groups: Dict[str, List[TechnicalInsight]] = {}
        for insight in self.insights:
            groups.setdefault(insight.classification, []).append(insight)
        return groups
