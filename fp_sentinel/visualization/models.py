"""
玄鉴 v2.5.1 — 可视化模块数据模型

定义热力图和趋势图所需的枚举、配置和数据结构。
设计原则：
- 与 fp_sentinel/models.py 的 Severity 枚举兼容
- 零外部依赖（仅使用 Python 标准库）
- 支持 Pydantic v2

版本: 2.5.1
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..models import Severity


# ─────────────────────── 枚举 ───────────────────────

class SeverityLevel(Enum):
    """热力图严重程度等级（用于热力图颜色映射）"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ChartTheme(Enum):
    """图表配色主题"""
    DARK = "dark"           # 深色主题（默认，匹配玄鉴暗色仪表板）
    LIGHT = "light"         # 浅色主题
    HIGH_CONTRAST = "high_contrast"  # 高对比度（色盲友好）


class OutputFormat(Enum):
    """输出格式"""
    HTML = "html"
    PNG = "png"
    BOTH = "both"


class TrendMetric(Enum):
    """趋势图指标类型"""
    TOTAL_COUNT = "total_count"         # 总漏洞数
    SEVERITY_DISTRIBUTION = "severity_distribution"  # 严重程度分布
    FIX_RATE = "fix_rate"               # 修复率
    NEW_VS_FIXED = "new_vs_fixed"       # 新增 vs 修复


# ─────────────────────── 热力图模型 ───────────────────────

# 严重度权重映射（用于热力图颜色强度计算）
SEVERITY_WEIGHT: Dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.3,
    "INFO": 0.1,
}

# 漏洞类型简写映射
VULN_TYPE_DISPLAY: Dict[str, str] = {
    "SQL_INJECTION": "SQL注入",
    "XSS": "跨站脚本",
    "COMMAND_INJECTION": "命令注入",
    "PATH_TRAVERSAL": "路径穿越",
    "SSRF": "SSRF",
    "DESERIALIZATION": "反序列化",
    "HARDCODED_SECRET": "硬编码密钥",
    "WEAK_CRYPTO": "弱加密",
    "OPEN_REDIRECT": "开放重定向",
    "CSRF": "CSRF",
    "IDOR": "越权访问",
    "SSTI": "模板注入",
    "XXE": "XXE",
    "NOSQL_INJECTION": "NoSQL注入",
    "PROTOTYPE_POLLUTION": "原型污染",
    "MISSING_AUTH": "认证缺失",
    "DEBUG_MODE": "调试模式",
    "FILE_UPLOAD": "文件上传",
    "INSECURE_CONFIG": "配置不安全",
    "OTHER": "其他",
}


@dataclass
class HeatmapInput:
    """热力图输入数据"""
    # 数据结构: {(module, vuln_type): {severity: count}}
    data: Dict[Tuple[str, str], Dict[str, int]] = field(default_factory=dict)
    # 可选：项目名称
    project_name: str = ""
    # 可选：扫描时间
    scan_time: Optional[str] = None

    @property
    def modules(self) -> List[str]:
        """获取所有模块名称（去重排序）"""
        return sorted({m for m, _ in self.data.keys()})

    @property
    def vuln_types(self) -> List[str]:
        """获取所有漏洞类型（去重排序）"""
        return sorted({v for _, v in self.data.keys()})

    def total_count(self) -> int:
        """总漏洞数"""
        return sum(
            sum(severity_counts.values())
            for severity_counts in self.data.values()
        )

    def get_value(self, module: str, vuln_type: str) -> int:
        """获取指定位置的漏洞总数"""
        return sum(self.data.get((module, vuln_type), {}).values())

    def get_severity_breakdown(self, module: str, vuln_type: str) -> Dict[str, int]:
        """获取指定位置的严重程度分布"""
        return dict(self.data.get((module, vuln_type), {}))

    @property
    def max_value(self) -> int:
        """获取最大值（用于颜色归一化）"""
        if not self.data:
            return 0
        return max(
            sum(severity_counts.values())
            for severity_counts in self.data.values()
        )


@dataclass
class HeatmapCell:
    """热力图单元格"""
    module: str
    vuln_type: str
    count: int
    severity_breakdown: Dict[str, str]  # {severity: count_str}
    risk_score: float                   # 0-10 风险评分
    color: str                          # 十六进制颜色值


@dataclass
class HeatmapResult:
    """热力图结果"""
    cells: List[HeatmapCell]            # 所有单元格
    modules: List[str]                  # 模块列表
    vuln_types: List[str]               # 漏洞类型列表
    total_findings: int                 # 总发现数
    output_path_html: Optional[str] = None
    output_path_png: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ─────────────────────── 趋势图模型 ───────────────────────

@dataclass
class TrendPoint:
    """趋势数据点（一个版本/一次扫描）"""
    version: str                                # 版本号或扫描ID
    scan_time: Optional[str] = None             # 扫描时间
    total_count: int = 0                        # 总漏洞数
    by_severity: Dict[str, int] = field(default_factory=dict)  # 按严重度分布
    fixed_count: int = 0                        # 已修复数
    new_count: int = 0                          # 新增数
    remaining_count: int = 0                    # 遗留数

    @property
    def fix_rate(self) -> float:
        """修复率（已修复 / (已修复+遗留)）"""
        total_past = self.fixed_count + self.remaining_count
        if total_past == 0:
            return 0.0
        return round(self.fixed_count / total_past * 100, 2)

    @property
    def critical_high_count(self) -> int:
        """高危+严重计数"""
        return self.by_severity.get("CRITICAL", 0) + self.by_severity.get("HIGH", 0)


@dataclass
class TrendInput:
    """趋势图输入数据"""
    points: List[TrendPoint] = field(default_factory=list)
    project_name: str = ""

    @property
    def has_data(self) -> bool:
        return len(self.points) > 0

    def get_metric_series(self, metric: TrendMetric) -> List[float]:
        """获取指定指标的时序数据"""
        series = []
        for p in self.points:
            if metric == TrendMetric.TOTAL_COUNT:
                series.append(p.total_count)
            elif metric == TrendMetric.FIX_RATE:
                series.append(p.fix_rate)
            elif metric == TrendMetric.NEW_VS_FIXED:
                series.append(p.new_count)
            elif metric == TrendMetric.SEVERITY_DISTRIBUTION:
                series.append(p.critical_high_count)
            else:
                series.append(0)
        return series


@dataclass
class TrendResult:
    """趋势图结果"""
    points: List[TrendPoint]                # 数据点
    metric_labels: List[str] = field(default_factory=list)
    total_versions: int = 0
    overall_change: float = 0.0             # 总体变化百分比
    output_path_html: Optional[str] = None
    output_path_png: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ─────────────────────── 颜色映射 ───────────────────────

# 深色主题热力图颜色映射（从低到高）
DARK_THEME_COLORS = [
    "#1a1a2e",  # 0
    "#16213e",  # 1-2
    "#0f3460",  # 3-5
    "#e94560",  # 6-10
    "#ff6b6b",  # 11-20
    "#ff2e63",  # 20+
]

# 浅色主题热力图颜色映射
LIGHT_THEME_COLORS = [
    "#f8f9fa",
    "#e9ecef",
    "#ffc107",
    "#fd7e14",
    "#dc3545",
    "#721c24",
]

# 高对比度主题（色盲友好）
HIGH_CONTRAST_COLORS = [
    "#ffffff",
    "#e0e0e0",
    "#b0b0b0",
    "#707070",
    "#404040",
    "#000000",
]


def get_risk_color(risk_score: float, theme: ChartTheme = ChartTheme.DARK) -> str:
    """
    根据风险评分获取颜色。

    Args:
        risk_score: 0-10 风险评分
        theme: 配色主题

    Returns:
        十六进制颜色字符串
    """
    if theme == ChartTheme.LIGHT:
        colors = LIGHT_THEME_COLORS
    elif theme == ChartTheme.HIGH_CONTRAST:
        colors = HIGH_CONTRAST_COLORS
    else:
        colors = DARK_THEME_COLORS

    # 将 0-10 映射到颜色索引 0-5
    idx = min(int(risk_score / 10 * (len(colors) - 1)), len(colors) - 1)
    return colors[idx]


def get_theme_background(theme: ChartTheme) -> str:
    """获取主题背景色"""
    if theme == ChartTheme.LIGHT:
        return "#ffffff"
    elif theme == ChartTheme.HIGH_CONTRAST:
        return "#ffffff"
    return "#0d1117"


def get_theme_text_color(theme: ChartTheme) -> str:
    """获取主题文字颜色"""
    if theme == ChartTheme.LIGHT:
        return "#212529"
    elif theme == ChartTheme.HIGH_CONTRAST:
        return "#000000"
    return "#c9d1d9"
