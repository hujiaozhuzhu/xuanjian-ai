"""报告数据模型存根（fallback）。

当 ``fp_sentinel.mobile_reporting.models.report_models`` 尚未创建时，
formats 层使用本模块中的 dataclass 存根保证可独立开发与测试。
字段命名与正式模型对齐，正式模型就绪后本模块仅作兜底。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class FindingReport:
    """单个漏洞发现。"""

    finding_id: str = ""
    title: str = ""
    severity: str = "MEDIUM"  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str = ""
    cwe: str = ""
    component: str = ""
    location: str = ""
    confidence: str = "Firm"  # Certain / Firm / Tentative
    likelihood: str = "Medium"  # High / Medium / Low
    has_poc: bool = False
    has_exploit: bool = False
    screenshot_count: int = 0
    description: str = ""
    impact: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    evidence: str = ""
    fix_recommendation: str = ""


@dataclass
class ScreenshotReport:
    """截图证据。"""

    screenshot_id: str = ""
    file_path: str = ""
    caption: str = ""
    related_step: str = ""
    resolution: str = ""
    size_bytes: int = 0
    verification_status: str = "unverified"  # verified / unverified / problem
    sha256: str = ""


@dataclass
class PocReport:
    """POC（无害概念验证）。"""

    finding_id: str = ""
    poc_type: str = "frida"
    code: str = ""
    syntax_valid: bool = False
    safety_valid: bool = False


@dataclass
class ExploitReport:
    """EXP（受控利用，含利用链步骤）。"""

    finding_id: str = ""
    exp_type: str = "manual"
    code: str = ""
    chain_steps: List[str] = field(default_factory=list)
    syntax_valid: bool = False
    safety_valid: bool = False


@dataclass
class EnvironmentInfo:
    """扫描环境信息。"""

    os_name: str = ""
    os_version: str = ""
    python_version: str = ""
    device: str = ""
    tools: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    cli_commands: List[str] = field(default_factory=list)


@dataclass
class ReportStatistics:
    """统计汇总。"""

    total_findings: int = 0
    severity_counts: Dict[str, int] = field(default_factory=dict)
    category_counts: Dict[str, int] = field(default_factory=dict)
    cwe_counts: Dict[str, int] = field(default_factory=dict)
    coverage_rate: float = 0.0
    false_positive_rate: float = 0.0


@dataclass
class MobileSecurityReport:
    """移动端安全评估报告（聚合根）。"""

    report_id: str = ""
    title: str = ""
    package_name: str = ""
    apk_path: str = ""
    sha256: str = ""
    scan_date: str = ""
    analyst: str = ""
    tool_version: str = ""
    risk_score: float = 0.0
    findings: List[FindingReport] = field(default_factory=list)
    screenshots: List[ScreenshotReport] = field(default_factory=list)
    pocs: List[PocReport] = field(default_factory=list)
    exploits: List[ExploitReport] = field(default_factory=list)
    environment: Optional[EnvironmentInfo] = None
    statistics: Optional[ReportStatistics] = None
    references: List[str] = field(default_factory=list)
    disclaimer: str = ""
