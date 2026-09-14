"""移动安全报告数据模型。

提供玄鉴AI（fp_sentinel）移动安全评估报告的全量数据模型：

- 环境/证据/截图/复现步骤/POC/EXP 等原子模型；
- :class:`FindingReport` 单条漏洞发现；
- :class:`MobileSecurityReport` 报告聚合根（支持 ``to_dict`` / ``from_dict``
  完整 JSON 往返与 :meth:`MobileSecurityReport.validate` 非破坏性校验）。

约束：
- Python 3.10+，全部字段带类型注解；
- 序列化只依赖 dataclasses 与标准库，JSON 可完整往返。
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "VALID_SEVERITIES",
    "VALID_EVIDENCE_SOURCES",
    "VALID_POC_TYPES",
    "VALID_SAFETY_LEVELS",
    "TargetAppInfo",
    "EnvironmentInfo",
    "Evidence",
    "ScreenshotRef",
    "ReproStep",
    "PocInfo",
    "ExpInfo",
    "FindingReport",
    "ReportStatistics",
    "Appendix",
    "ReportMetadata",
    "MobileSecurityReport",
]

#: 合法的漏洞严重级别
VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
#: 合法的证据来源
VALID_EVIDENCE_SOURCES = ("静态", "动态", "frida")
#: 合法的 POC 类型
VALID_POC_TYPES = ("frida", "java", "native")
#: 合法的 POC 安全级别
VALID_SAFETY_LEVELS = ("SAFE", "WARNING", "DANGER")

#: FindingReport 必填（非空）字段
_FINDING_REQUIRED_FIELDS = ("id", "title", "severity", "description")


def _clamp_confidence(value: Any, default: float = 0.5) -> float:
    """把任意输入安全地转换为 0~1 的置信度浮点数（越界值截断到边界）。"""
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, result))


def _safe_int(value: Any, default: int = 0) -> int:
    """宽容 int 转换，失败时回退默认值并记录 warning。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        logger.warning("int 转换失败，已回退默认值 %r: %r", default, value)
        return default


def _dict_items(raw: Any, label: str) -> List[Dict[str, Any]]:
    """把嵌套列表规整为 dict 列表（非 dict 元素记录 warning 后跳过）。"""
    if not raw:
        return []
    if not isinstance(raw, list):
        logger.warning("%s 不是列表，已忽略: %r", label, type(raw).__name__)
        return []
    items: List[Dict[str, Any]] = []
    for idx, element in enumerate(raw, start=1):
        if isinstance(element, dict):
            items.append(element)
        else:
            logger.warning(
                "%s[%d] 不是对象，已跳过: %r", label, idx, type(element).__name__
            )
    return items


@dataclass
class TargetAppInfo:
    """目标应用基本信息。"""

    name: str = ""
    package: str = ""
    version: str = ""
    sha256: str = ""
    file_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict。"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "TargetAppInfo":
        """从 dict 反序列化，字段缺失时使用默认值。"""
        data = data or {}
        return cls(
            name=str(data.get("name", "") or ""),
            package=str(data.get("package", "") or ""),
            version=str(data.get("version", "") or ""),
            sha256=str(data.get("sha256", "") or ""),
            file_size=_safe_int(data.get("file_size", 0) or 0),
        )


@dataclass
class EnvironmentInfo:
    """扫描环境信息（操作系统 / Python / 工具链 / 目标应用 / 扫描命令）。"""

    os: str = ""
    python_version: str = ""
    tool_versions: Dict[str, str] = field(default_factory=dict)
    target_app: Optional[TargetAppInfo] = None
    scan_time: str = ""
    scan_command: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict。"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "EnvironmentInfo":
        """从 dict 反序列化，字段缺失时使用默认值。"""
        data = data or {}
        tools_raw = data.get("tool_versions") or {}
        if not isinstance(tools_raw, dict):
            logger.warning(
                "tool_versions 不是对象，已按空处理: %r", type(tools_raw).__name__
            )
            tools_raw = {}
        tool_versions = {str(k): str(v) for k, v in tools_raw.items()}
        return cls(
            os=str(data.get("os", "") or ""),
            python_version=str(data.get("python_version", "") or ""),
            tool_versions=tool_versions,
            target_app=TargetAppInfo.from_dict(data.get("target_app")),
            scan_time=str(data.get("scan_time", "") or ""),
            scan_command=str(data.get("scan_command", "") or ""),
        )


@dataclass
class Evidence:
    """漏洞证据：代码位置与内容片段。"""

    id: str = ""
    location: str = ""
    content: str = ""
    description: str = ""
    source: str = "静态"

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict。"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "Evidence":
        """从 dict 反序列化，字段缺失时使用默认值。"""
        data = data or {}
        return cls(
            id=str(data.get("id", "") or ""),
            location=str(data.get("location", "") or ""),
            content=str(data.get("content", "") or ""),
            description=str(data.get("description", "") or ""),
            source=str(data.get("source", "静态") or "静态"),
        )


@dataclass
class ScreenshotRef:
    """截图证据引用（含完整性校验状态）。"""

    id: str = ""
    path: str = ""
    caption: str = ""
    sha256: str = ""
    width: int = 0
    height: int = 0
    format: str = ""
    verified: bool = False
    verify_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict。"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ScreenshotRef":
        """从 dict 反序列化，字段缺失时使用默认值。"""
        data = data or {}
        return cls(
            id=str(data.get("id", "") or ""),
            path=str(data.get("path", "") or ""),
            caption=str(data.get("caption", "") or ""),
            sha256=str(data.get("sha256", "") or ""),
            width=_safe_int(data.get("width", 0) or 0),
            height=_safe_int(data.get("height", 0) or 0),
            format=str(data.get("format", "") or ""),
            verified=bool(data.get("verified", False)),
            verify_message=str(data.get("verify_message", "") or ""),
        )


@dataclass
class ReproStep:
    """复现步骤：操作 / 期望结果 / 实际结果 / 可复现命令。"""

    step_no: int = 1
    action: str = ""
    expected_result: str = ""
    actual_result: str = ""
    command: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict。"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ReproStep":
        """从 dict 反序列化，字段缺失时使用默认值。"""
        data = data or {}
        return cls(
            step_no=_safe_int(data.get("step_no", 1) or 1, default=1),
            action=str(data.get("action", "") or ""),
            expected_result=str(data.get("expected_result", "") or ""),
            actual_result=str(data.get("actual_result", "") or ""),
            command=str(data.get("command", "") or ""),
        )


@dataclass
class PocInfo:
    """POC（概念验证）信息，含脚本内容与安全级别。"""

    id: str = ""
    name: str = ""
    type: str = "frida"
    script_path: str = ""
    script_content: str = ""
    safety_level: str = "SAFE"
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict。"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "PocInfo":
        """从 dict 反序列化，字段缺失时使用默认值。"""
        data = data or {}
        return cls(
            id=str(data.get("id", "") or ""),
            name=str(data.get("name", "") or ""),
            type=str(data.get("type", "frida") or "frida"),
            script_path=str(data.get("script_path", "") or ""),
            script_content=str(data.get("script_content", "") or ""),
            safety_level=str(data.get("safety_level", "SAFE") or "SAFE"),
            description=str(data.get("description", "") or ""),
        )


@dataclass
class ExpInfo:
    """EXP（受控利用）信息：前提条件 / 步骤 / 影响 / 缓解措施。"""

    id: str = ""
    name: str = ""
    preconditions: List[str] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)
    impact: str = ""
    mitigation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict。"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ExpInfo":
        """从 dict 反序列化，字段缺失时使用默认值。"""
        data = data or {}
        pre = [str(x) for x in (data.get("preconditions") or [])]
        steps = [str(x) for x in (data.get("steps") or [])]
        return cls(
            id=str(data.get("id", "") or ""),
            name=str(data.get("name", "") or ""),
            preconditions=pre,
            steps=steps,
            impact=str(data.get("impact", "") or ""),
            mitigation=str(data.get("mitigation", "") or ""),
        )


@dataclass
class FindingReport:
    """单条漏洞发现（聚合证据、截图、复现步骤、POC/EXP）。"""

    id: str = ""
    title: str = ""
    severity: str = "MEDIUM"
    cwe_id: str = ""
    owasp_masvs: str = ""
    category: str = ""
    description: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    screenshots: List[ScreenshotRef] = field(default_factory=list)
    repro_steps: List[ReproStep] = field(default_factory=list)
    poc: Optional[PocInfo] = None
    exp: Optional[ExpInfo] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tool_version: str = ""
    confidence: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict。"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "FindingReport":
        """从 dict 反序列化，字段缺失时使用默认值。"""
        data = data or {}
        refs_raw = data.get("references") or []
        return cls(
            id=str(data.get("id", "") or ""),
            title=str(data.get("title", "") or ""),
            severity=str(data.get("severity", "MEDIUM") or "MEDIUM").upper(),
            cwe_id=str(data.get("cwe_id", "") or ""),
            owasp_masvs=str(data.get("owasp_masvs", "") or ""),
            category=str(data.get("category", "") or ""),
            description=str(data.get("description", "") or ""),
            evidence=[
                Evidence.from_dict(e) for e in _dict_items(data.get("evidence"), "evidence")
            ],
            screenshots=[
                ScreenshotRef.from_dict(s)
                for s in _dict_items(data.get("screenshots"), "screenshots")
            ],
            repro_steps=[
                ReproStep.from_dict(s)
                for s in _dict_items(data.get("repro_steps"), "repro_steps")
            ],
            poc=PocInfo.from_dict(data.get("poc")) if data.get("poc") else None,
            exp=ExpInfo.from_dict(data.get("exp")) if data.get("exp") else None,
            remediation=str(data.get("remediation", "") or ""),
            references=[str(x) for x in refs_raw],
            tool_version=str(data.get("tool_version", "") or ""),
            confidence=_clamp_confidence(data.get("confidence", 0.5)),
        )


@dataclass
class ReportStatistics:
    """报告统计汇总：总数 / 严重度分布 / 分类分布 / 覆盖度指标 / 耗时。"""

    total_count: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_category: Dict[str, int] = field(default_factory=dict)
    coverage_metrics: Dict[str, Any] = field(default_factory=dict)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict。"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ReportStatistics":
        """从 dict 反序列化，字段缺失时使用默认值。"""
        data = data or {}
        sev_raw = data.get("by_severity") or {}
        cat_raw = data.get("by_category") or {}
        if not isinstance(sev_raw, dict):
            logger.warning("by_severity 不是对象，已按空处理: %r", type(sev_raw).__name__)
            sev_raw = {}
        if not isinstance(cat_raw, dict):
            logger.warning("by_category 不是对象，已按空处理: %r", type(cat_raw).__name__)
            cat_raw = {}
        sev = {str(k): _safe_int(v) for k, v in sev_raw.items()}
        cat = {str(k): _safe_int(v) for k, v in cat_raw.items()}
        try:
            duration = float(data.get("scan_duration_seconds", 0.0) or 0.0)
        except (TypeError, ValueError):
            duration = 0.0
        return cls(
            total_count=_safe_int(data.get("total_count", 0) or 0),
            by_severity=sev,
            by_category=cat,
            coverage_metrics=dict(data.get("coverage_metrics") or {}),
            scan_duration_seconds=duration,
        )


@dataclass
class Appendix:
    """报告附录：术语表 / 工具链信息 / 原始日志引用。"""

    glossary: Dict[str, str] = field(default_factory=dict)
    toolchain_info: Dict[str, Any] = field(default_factory=dict)
    raw_logs_ref: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict。"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "Appendix":
        """从 dict 反序列化，字段缺失时使用默认值。"""
        data = data or {}
        glossary = {str(k): str(v) for k, v in (data.get("glossary") or {}).items()}
        return cls(
            glossary=glossary,
            toolchain_info=dict(data.get("toolchain_info") or {}),
            raw_logs_ref=str(data.get("raw_logs_ref", "") or ""),
        )


@dataclass
class ReportMetadata:
    """报告元信息：标题 / 作者 / 密级 / 版本 / 日期。"""

    title: str = "移动应用安全评估报告"
    author: str = "玄鉴AI (fp_sentinel)"
    classification: str = "内部资料"
    version: str = "V1.0"
    date: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict。"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ReportMetadata":
        """从 dict 反序列化，字段缺失时使用默认值。"""
        data = data or {}
        return cls(
            title=str(data.get("title") or "移动应用安全评估报告"),
            author=str(data.get("author") or "玄鉴AI (fp_sentinel)"),
            classification=str(data.get("classification") or "内部资料"),
            version=str(data.get("version") or "V1.0"),
            date=str(data.get("date", "") or ""),
        )


@dataclass
class MobileSecurityReport:
    """移动安全评估报告聚合根。

    提供：
    - :meth:`to_dict` / :meth:`from_dict`：完整 JSON 往返序列化；
    - :meth:`validate`：非破坏性校验，返回 warnings 列表而不抛异常。
    """

    metadata: ReportMetadata = field(default_factory=ReportMetadata)
    environment: Optional[EnvironmentInfo] = None
    statistics: Optional[ReportStatistics] = None
    findings: List[FindingReport] = field(default_factory=list)
    appendix: Optional[Appendix] = None
    report_format: str = "json"
    generated_at: str = ""

    # ─────────────────────────── 序列化 ───────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的 dict（嵌套模型全部展开）。"""
        return asdict(self)

    def to_json(self, indent: int = 2, ensure_ascii: bool = False) -> str:
        """序列化为 JSON 字符串。"""
        return json.dumps(
            self.to_dict(), ensure_ascii=ensure_ascii, indent=indent, default=str
        )

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "MobileSecurityReport":
        """从 dict 反序列化，字段缺失时宽容处理。"""
        data = data or {}
        findings = [
            FindingReport.from_dict(f) for f in _dict_items(data.get("findings"), "findings")
        ]
        return cls(
            metadata=ReportMetadata.from_dict(data.get("metadata")),
            environment=(
                EnvironmentInfo.from_dict(data.get("environment"))
                if data.get("environment")
                else None
            ),
            statistics=(
                ReportStatistics.from_dict(data.get("statistics"))
                if data.get("statistics")
                else None
            ),
            findings=findings,
            appendix=(
                Appendix.from_dict(data.get("appendix"))
                if data.get("appendix")
                else None
            ),
            report_format=str(data.get("report_format", "json") or "json"),
            generated_at=str(data.get("generated_at", "") or ""),
        )

    # ─────────────────────────── 校验 ────────────────────────────

    def validate(self) -> List[str]:
        """非破坏性校验，返回 warnings 列表（不抛异常）。

        校验规则：
        - severity 必须属于合法值集合；
        - finding.id 必须唯一且非空；
        - finding 必填字段（id/title/severity/description）非空；
        - confidence 必须位于 [0, 1]；
        - 截图 path 非空时文件必须存在。

        Returns:
            List[str]: 全部 warning 描述；空列表表示通过。
        """
        warnings: List[str] = []
        seen_ids: Dict[str, int] = {}
        for index, finding in enumerate(self.findings, start=1):
            prefix = f"finding[{index}]"
            for req in _FINDING_REQUIRED_FIELDS:
                if not str(getattr(finding, req) or "").strip():
                    warnings.append(f"{prefix} 必填字段为空: {req}")
            if finding.severity.strip().upper() not in VALID_SEVERITIES:
                warnings.append(
                    f"{prefix} 非法 severity: {finding.severity!r}"
                    f"（合法值: {list(VALID_SEVERITIES)}）"
                )
            if finding.id:
                if finding.id in seen_ids:
                    warnings.append(
                        f"{prefix} 发现 id 重复: {finding.id}"
                        f"（首次出现于 finding[{seen_ids[finding.id]}]）"
                    )
                else:
                    seen_ids[finding.id] = index
            if not 0.0 <= finding.confidence <= 1.0:
                warnings.append(
                    f"{prefix} confidence 超出 [0,1]: {finding.confidence}"
                )
            for shot in finding.screenshots:
                if not shot.path:
                    warnings.append(
                        f"{prefix} 截图 {shot.id or '<无id>'} 缺少 path"
                    )
                    continue
                if not Path(shot.path).exists():
                    warnings.append(
                        f"{prefix} 截图文件不存在: {shot.path}"
                        f"（截图 id: {shot.id or '<无id>'}）"
                    )
        warnings.sort()
        if warnings:
            logger.warning("报告校验发现 %d 条 warning", len(warnings))
        return warnings
