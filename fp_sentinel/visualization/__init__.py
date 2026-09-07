"""
玄鉴 v2.4.0 — 知识图谱可视化模块 (Knowledge Graph Visualization)

提供漏洞热力图与版本变化趋势图生成功能。
支持 HTML 交互式 与 PNG 静态图 两种输出格式。
零外部绘图依赖（PNG 使用 Python 标准库 zlib+struct 编码）。

子功能：
- VulnerabilityHeatmap: 按模块/漏洞类型/严重程度生成风险热力图
- VersionTrendChart: 展示版本间漏洞数量/严重程度/修复率的变化趋势

版本: 2.4.0
"""

from .heatmap import VulnerabilityHeatmap, HeatmapCell, HeatmapResult
from .version_trend import VersionTrendChart, TrendPoint, TrendResult
from .models import (
    SeverityLevel,
    ChartTheme,
    OutputFormat,
    TrendMetric,
    HeatmapInput,
    TrendInput,
    SEVERITY_WEIGHT,
    VULN_TYPE_DISPLAY,
    get_risk_color,
    get_theme_background,
    get_theme_text_color,
)

__version__ = "2.4.0"

__all__ = [
    # 生成器
    "VulnerabilityHeatmap",
    "VersionTrendChart",
    # 输入模型
    "HeatmapInput",
    "TrendInput",
    # 结果模型
    "HeatmapCell",
    "HeatmapResult",
    "TrendPoint",
    "TrendResult",
    # 枚举/常量
    "SeverityLevel",
    "ChartTheme",
    "OutputFormat",
    "TrendMetric",
    "SEVERITY_WEIGHT",
    "VULN_TYPE_DISPLAY",
    # 工具函数
    "get_risk_color",
    "get_theme_background",
    "get_theme_text_color",
]
