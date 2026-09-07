"""
玄鉴 v2.4.0 — 版本变化趋势图生成器 (Version Trend Chart Generator)

功能：展示不同版本间漏洞数量、严重程度、修复率的变化趋势。
输出：支持 HTML 交互式（Self-contained，内联 JS 折线图）、PNG 静态图（zlib+struct 编码）。

设计原则：
- 纯自包含 HTML（无外部 JS 依赖），离线可查看
- PNG 使用 Python 标准库（zlib + struct）编码，无第三方绘图依赖
- 三种配色主题：dark（默认）/ light / high_contrast
- 支持多种指标：总数、严重度分布、修复率、新增 vs 修复

版本: 2.4.0
"""

from __future__ import annotations

import html
import logging
import math
import os
import struct
import zlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    ChartTheme,
    OutputFormat,
    SeverityLevel,
    TrendInput,
    TrendMetric,
    TrendPoint,
    TrendResult,
    get_risk_color,
    get_theme_background,
    get_theme_text_color,
)

logger = logging.getLogger(__name__)


# ─────────────────────── 核心类 ───────────────────────

class VersionTrendChart:
    """
    版本变化趋势图生成器

    用法::

        from fp_sentinel.visualization.version_trend import VersionTrendChart, TrendInput, TrendPoint

        # 构造输入数据
        points = [
            TrendPoint(version="v1.0", total_count=50,
                        by_severity={"HIGH": 10, "CRITICAL": 2, "MEDIUM": 20},
                        fixed_count=0, new_count=50),
            TrendPoint(version="v1.1", total_count=35,
                        by_severity={"HIGH": 7, "CRITICAL": 1, "MEDIUM": 15},
                        fixed_count=18, new_count=3),
        ]
        inp = TrendInput(points=points, project_name="my-project")

        # 生成趋势图
        chart = VersionTrendChart(theme=ChartTheme.DARK)
        result = chart.generate(inp, output_dir="./reports")

    Args:
        theme: 配色主题
        show_fix_rate: 是否同时显示修复率折线
    """

    def __init__(
        self,
        theme: ChartTheme = ChartTheme.DARK,
        show_fix_rate: bool = True,
    ):
        self.theme = theme
        self.show_fix_rate = show_fix_rate

    # ───────────────── 公共接口 ─────────────────

    def generate(
        self,
        inp: TrendInput,
        output_dir: str = "./reports",
        output_format: OutputFormat = OutputFormat.BOTH,
        filename_prefix: str = "version_trend",
    ) -> TrendResult:
        """
        生成版本变化趋势图。

        Args:
            inp: 趋势图输入数据
            output_dir: 输出目录
            output_format: 输出格式 (HTML / PNG / BOTH)
            filename_prefix: 文件名前缀

        Returns:
            TrendResult: 结果对象，包含数据点和输出路径
        """
        # 计算总体变化
        overall_change = self._calc_overall_change(inp)

        result = TrendResult(
            points=inp.points,
            metric_labels=self._get_metric_labels(inp),
            total_versions=len(inp.points),
            overall_change=overall_change,
            metadata={
                "project_name": inp.project_name,
                "theme": self.theme.value,
                "show_fix_rate": self.show_fix_rate,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
        )

        os.makedirs(output_dir, exist_ok=True)

        if output_format in (OutputFormat.HTML, OutputFormat.BOTH):
            html_path = os.path.join(output_dir, f"{filename_prefix}.html")
            self._write_html(result, inp, html_path)
            result.output_path_html = html_path

        if output_format in (OutputFormat.PNG, OutputFormat.BOTH):
            png_path = os.path.join(output_dir, f"{filename_prefix}.png")
            self._write_png(result, inp, png_path)
            result.output_path_png = png_path

        return result

    # ───────────────── 数据计算 ─────────────────

    def _calc_overall_change(self, inp: TrendInput) -> float:
        """计算总体变化百分比"""
        if len(inp.points) < 2:
            return 0.0
        first = inp.points[0].total_count
        last = inp.points[-1].total_count
        if first == 0:
            return 0.0
        return round((last - first) / first * 100, 2)

    def _get_metric_labels(self, inp: TrendInput) -> List[str]:
        """获取指标标签列表"""
        labels = ["总漏洞数"]
        if self.show_fix_rate and len(inp.points) > 1:
            labels.append("修复率(%)")
        return labels

    # ───────────────── HTML 输出 ─────────────────

    def _write_html(self, result: TrendResult, inp: TrendInput, path: str) -> None:
        """写入自包含 HTML 趋势图"""
        content = self._render_html(result, inp)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"HTML trend chart written to {path}")

    def _render_html(self, result: TrendResult, inp: TrendInput) -> str:
        """渲染 HTML 趋势图内容"""
        bg = get_theme_background(self.theme)
        text_color = get_theme_text_color(self.theme)
        grid_bg = "#161b22" if self.theme == ChartTheme.DARK else "#f0f0f0"
        border_color = "#30363d" if self.theme == ChartTheme.DARK else "#dee2e6"

        points = result.points

        # 统计数据卡片
        total_versions = result.total_versions
        overall_change = result.overall_change
        change_color = "#3fb950" if overall_change <= 0 else "#f85149"
        change_icon = "&#9660;" if overall_change <= 0 else "&#9650;"

        latest = points[-1] if points else TrendPoint(version="N/A")
        earliest = points[0] if points else TrendPoint(version="N/A")

        # 表格行
        table_rows = []
        for p in points:
            sev_detail = "  ".join(
                f'<span style="display:inline-block;padding:2px 6px;margin:2px;'
                f'border-radius:4px;font-size:0.8em;background:'
                f'{_get_severity_bg(sev)};color:{_get_severity_fg(sev)}">'
                f'{html.escape(sev)}: {cnt}'
                f'</span>'
                for sev, cnt in sorted(p.by_severity.items())
            ) or "-"

            table_rows.append(
                f'<tr style="border-bottom:1px solid {border_color}">'
                f'<td style="padding:10px 14px;font-weight:600;color:{text_color}">'
                f'{html.escape(p.version)}</td>'
                f'<td style="padding:10px 14px;text-align:center;font-weight:700;'
                f'color:{text_color}">{p.total_count}</td>'
                f'<td style="padding:10px 14px;text-align:center;color:{text_color}">'
                f'{sev_detail}</td>'
                f'<td style="padding:10px 14px;text-align:center;color:{text_color}">'
                f'{p.fixed_count}</td>'
                f'<td style="padding:10px 14px;text-align:center;color:{text_color}">'
                f'{p.new_count}</td>'
                f'<td style="padding:10px 14px;text-align:center;font-weight:600;'
                f'color:{"#3fb950" if p.fix_rate >= 50 else "#f85149" if p.fix_rate < 20 else "#d29922"}">'
                f'{p.fix_rate}%</td>'
                '</tr>'
            )

        rows_html = "\n".join(table_rows) if table_rows else (
            f'<tr><td colspan="6" style="padding:30px;text-align:center;'
            f'color:{text_color}">无趋势数据</td></tr>'
        )

        # 内联 JS 折线图数据
        version_labels = [p.version for p in points]
        total_series = [p.total_count for p in points]
        fix_rate_series = [p.fix_rate for p in points]
        critical_series = [p.by_severity.get("CRITICAL", 0) for p in points]
        high_series = [p.by_severity.get("HIGH", 0) for p in points]

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        project = html.escape(inp.project_name or "未命名项目")

        # 确定 Y 轴最大值
        max_val = max(total_series) if total_series else 100
        max_val = max(1, max_val)

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>版本变化趋势图 — {project}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background-color: {bg};
    color: {text_color};
    padding: 24px;
    line-height: 1.6;
}}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{
    font-size: 1.5em;
    margin-bottom: 4px;
    color: {text_color};
}}
.subtitle {{
    font-size: 0.9em;
    color: {'#8b949e' if self.theme == ChartTheme.DARK else '#6c757d'};
    margin-bottom: 20px;
}}
.stats {{
    display: flex;
    gap: 16px;
    margin-bottom: 20px;
    flex-wrap: wrap;
}}
.stat-card {{
    background-color: {grid_bg};
    border: 1px solid {border_color};
    border-radius: 8px;
    padding: 14px 20px;
    min-width: 140px;
}}
.stat-card .label {{
    font-size: 0.8em;
    color: {'#8b949e' if self.theme == ChartTheme.DARK else '#6c757d'};
    margin-bottom: 4px;
}}
.stat-card .value {{
    font-size: 1.4em;
    font-weight: 700;
}}
.section {{
    margin-bottom: 24px;
}}
.section h2 {{
    font-size: 1.1em;
    margin-bottom: 10px;
    color: {text_color};
}}
.chart-container {{
    background-color: {grid_bg};
    border: 1px solid {border_color};
    border-radius: 8px;
    overflow: hidden;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    background-color: {grid_bg};
    border: 1px solid {border_color};
    border-radius: 8px;
    overflow: hidden;
}}
th {{
    padding: 10px 14px;
    text-align: left;
    border-bottom: 2px solid {border_color};
    border-right: 1px solid {border_color};
    font-size: 0.85em;
    color: {'#8b949e' if self.theme == ChartTheme.DARK else '#6c757d'};
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
.footer {{
    margin-top: 24px;
    padding-top: 16px;
    border-top: 1px solid {border_color};
    font-size: 0.8em;
    color: {'#8b949e' if self.theme == ChartTheme.DARK else '#6c757d'};
}}
.legend {{
    display: flex;
    gap: 16px;
    margin-top: 8px;
    flex-wrap: wrap;
}}
.legend-item {{
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 0.85em;
}}
.legend-color {{
    width: 14px;
    height: 14px;
    border-radius: 3px;
}}
</style>
</head>
<body>
<div class="container">
    <h1>&#128200; 版本变化趋势图</h1>
    <p class="subtitle">项目: {project} &nbsp;|&nbsp; 生成时间: {now} &nbsp;|&nbsp; 玄鉴 fp-sentinel v2.4.0</p>

    <div class="stats">
        <div class="stat-card">
            <div class="label">版本数</div>
            <div class="value" style="color:{text_color}">{total_versions}</div>
        </div>
        <div class="stat-card">
            <div class="label">总体变化</div>
            <div class="value" style="color:{change_color}">{change_icon} {overall_change}%</div>
        </div>
        <div class="stat-card">
            <div class="label">最新版本</div>
            <div class="value" style="color:{text_color}">{html.escape(latest.version)}</div>
        </div>
        <div class="stat-card">
            <div class="label">最新漏洞总数</div>
            <div class="value" style="color:{'#f85149' if latest.total_count > 0 else '#3fb950'}">{latest.total_count}</div>
        </div>
    </div>

    <div class="section">
        <h2>&#128200; 趋势折线图</h2>
        <div class="chart-container">
            <canvas id="trendChart" width="1140" height="360"></canvas>
        </div>
        <div class="legend">
            <div class="legend-item"><div class="legend-color" style="background:#58a6ff"></div>总漏洞数</div>
            <div class="legend-item"><div class="legend-color" style="background:#f85149"></div>严重(CRITICAL)</div>
            <div class="legend-item"><div class="legend-color" style="background:#d29922"></div>高危(HIGH)</div>
            <div class="legend-item"><div class="legend-color" style="background:#3fb950"></div>修复率(%)</div>
        </div>
    </div>

    <div class="section">
        <h2>&#128203; 详细数据表</h2>
        <table>
            <thead>
                <tr>
                    <th>版本</th>
                    <th style="text-align:center">总漏洞数</th>
                    <th>严重度分布</th>
                    <th style="text-align:center">已修复</th>
                    <th style="text-align:center">新增</th>
                    <th style="text-align:center">修复率</th>
                </tr>
            </thead>
            <tbody>
{rows_html}
            </tbody>
        </table>
    </div>

    <div class="footer">
        <p>由玄鉴 fp-sentinel v2.4.0 知识图谱可视化模块自动生成 &nbsp;|&nbsp; 仅用于防御性安全审计</p>
    </div>
</div>

<script>
(function() {{
    var canvas = document.getElementById('trendChart');
    var ctx = canvas.getContext('2d');
    var W = canvas.width;
    var H = canvas.height;
    var padding = {{ top: 30, right: 60, bottom: 50, left: 60 }};

    // 背景
    ctx.fillStyle = '{grid_bg}';
    ctx.fillRect(0, 0, W, H);

    // 数据
    var labels = {version_labels};
    var totalSeries = {total_series};
    var critSeries = {critical_series};
    var highSeries = {high_series};
    var fixRateSeries = {fix_rate_series};
    var maxY = {max_val};

    function xPos(i) {{
        var plotW = W - padding.left - padding.right;
        return padding.left + (i / Math.max(1, labels.length - 1)) * plotW;
    }}

    function yPos(val, axisMax) {{
        var plotH = H - padding.top - padding.bottom;
        return padding.top + plotH - (val / axisMax) * plotH;
    }}

    // 网格线
    ctx.strokeStyle = '{border_color}';
    ctx.lineWidth = 1;
    for (var g = 0; g <= 5; g++) {{
        var y = yPos(maxY * g / 5, maxY);
        ctx.beginPath();
        ctx.moveTo(padding.left, y);
        ctx.lineTo(W - padding.right, y);
        ctx.stroke();
        // Y 轴标签
        ctx.fillStyle = '{'#8b949e' if self.theme == ChartTheme.DARK else '#6c757d'}';
        ctx.font = '11px sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(Math.round(maxY * g / 5), padding.left - 8, y + 4);
    }}

    // Y2 轴标签（修复率 0-100）
    ctx.fillStyle = '#3fb950';
    ctx.textAlign = 'left';
    for (var g2 = 0; g2 <= 5; g2++) {{
        var yr = yPos(100 * g2 / 5, maxY);
        ctx.fillText((100 * g2 / 5).toFixed(0) + '%', W - padding.right + 5, yr + 4);
    }}

    // X 轴标签
    ctx.fillStyle = '{text_color}';
    ctx.textAlign = 'center';
    for (var xi = 0; xi < labels.length; xi++) {{
        ctx.fillText(labels[xi], xPos(xi), H - padding.bottom + 20);
    }}

    // 绘制折线函数
    function drawLine(series, color, dashed) {{
        if (series.length === 0) return;
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        if (dashed) ctx.setLineDash([5, 3]);
        else ctx.setLineDash([]);
        ctx.beginPath();
        for (var i = 0; i < series.length; i++) {{
            var px = xPos(i);
            var py = yPos(series[i], maxY);
            if (i === 0) ctx.moveTo(px, py);
            else ctx.lineTo(px, py);
        }}
        ctx.stroke();
        ctx.setLineDash([]);

        // 数据点
        for (var j = 0; j < series.length; j++) {{
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(xPos(j), yPos(series[j], maxY), 4, 0, Math.PI * 2);
            ctx.fill();
            // 点值标签
            ctx.fillStyle = '{text_color}';
            ctx.font = 'bold 10px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(series[j], xPos(j), yPos(series[j], maxY) - 10);
        }}
    }}

    // 绘制折线
    drawLine(totalSeries, '#58a6ff', false);
    drawLine(critSeries, '#f85149', false);
    drawLine(highSeries, '#d29922', false);
    drawLine(fixRateSeries, '#3fb950', true);
}})();
</script>
</body>
</html>"""

    # ───────────────── PNG 输出 ─────────────────

    def _write_png(self, result: TrendResult, inp: TrendInput, path: str) -> None:
        """写入 PNG 趋势图"""
        self._render_png(result, inp, path)
        logger.info(f"PNG trend chart written to {path}")

    def _render_png(self, result: TrendResult, inp: TrendInput, path: str) -> None:
        """渲染 PNG 趋势图"""
        # 布局参数
        width, height = 900, 450
        pad_left = 70
        pad_right = 60
        pad_top = 50
        pad_bottom = 60
        plot_w = width - pad_left - pad_right
        plot_h = height - pad_top - pad_bottom

        bg_rgb = _hex_to_rgb_png(get_theme_background(self.theme))
        text_rgb = _hex_to_rgb_png(get_theme_text_color(self.theme))
        grid_rgb = _hex_to_rgb_png(
            "#30363d" if self.theme == ChartTheme.DARK else "#dee2e6"
        )

        # 初始化像素缓冲区（扁平整数列表 [R,G,B,...]）
        pixels = bg_rgb * (width * height)
        total_pixels = width * height

        points = result.points

        if not points:
            _draw_text_png(pixels, width, 20, 20, "NO DATA", text_rgb)
            _save_png_png(pixels, width, height, path)
            return

        # 数据准备
        total_series = [p.total_count for p in points]
        crit_series = [p.by_severity.get("CRITICAL", 0) for p in points]
        high_series = [p.by_severity.get("HIGH", 0) for p in points]
        max_val = max(max(total_series, default=10), 1)

        # 标题
        _draw_text_png(pixels, width, 15, 10, "VERSION TREND CHART", text_rgb)

        # 绘图辅助函数
        def x_pos(i):
            n = len(points)
            if n <= 1:
                return pad_left + plot_w // 2
            return pad_left + int((i / (n - 1)) * plot_w)

        def y_pos(val):
            return pad_top + plot_h - int((val / max_val) * plot_h)

        # 网格线
        for g in range(6):
            y = y_pos(max_val * g / 5)
            _draw_line_png(pixels, width, pad_left, y, pad_left + plot_w, y, grid_rgb)
            # Y 轴标签
            label_val = int(max_val * g / 5)
            _draw_text_png(pixels, width, 5, y - 3, str(label_val), text_rgb)

        # X 轴标签
        for i, p in enumerate(points):
            x = x_pos(i)
            _draw_text_png(pixels, width, x - 15, height - pad_bottom + 15, p.version[:8], text_rgb)

        # 轴
        _draw_line_png(pixels, width, pad_left, pad_top, pad_left, pad_top + plot_h, text_rgb)
        _draw_line_png(pixels, width, pad_left, pad_top + plot_h, pad_left + plot_w, pad_top + plot_h, text_rgb)

        # Y2 轴（右侧，修复率 0-100）
        _draw_line_png(pixels, width, pad_left + plot_w, pad_top, pad_left + plot_w, pad_top + plot_h, text_rgb)

        def draw_line_png_internal(series, color, dashed=False):
            if not series or len(series) < 2:
                return
            for i in range(len(series) - 1):
                x0 = x_pos(i)
                y0 = y_pos(series[i])
                x1 = x_pos(i + 1)
                y1 = y_pos(series[i + 1])
                _draw_line_png(pixels, width, x0, y0, x1, y1, color)

        # 绘制折线
        draw_line_png_internal(total_series, [0x58, 0xa6, 0xff])
        draw_line_png_internal(crit_series, [0xf8, 0x51, 0x49])
        draw_line_png_internal(high_series, [0xd2, 0x99, 0x22])

        # 图例
        legend_x = width - pad_right - 120
        legend_y = pad_top + 10
        _draw_text_png(pixels, width, legend_x, legend_y, "TOTAL", [0x58, 0xa6, 0xff])
        _draw_text_png(pixels, width, legend_x, legend_y + 12, "CRITICAL", [0xf8, 0x51, 0x49])
        _draw_text_png(pixels, width, legend_x, legend_y + 24, "HIGH", [0xd2, 0x99, 0x22])

        _save_png_png(pixels, width, height, path)


# ─────────────────────── PNG 工具函数（模块内部使用） ───────────────────────

def _hex_to_rgb_png(hex_color: str) -> list:
    hex_color = hex_color.lstrip("#")
    if len(hex_color) == 3:
        hex_color = "".join(c * 2 for c in hex_color)
    return [int(hex_color[i:i + 2], 16) for i in (0, 2, 4)]


def _draw_line_png(pixels: list, width: int, x0: int, y0: int, x1: int, y1: int, rgb: list) -> None:
    total_len = len(pixels)
    height = total_len // (width * 3)
    dx = abs(x1 - x0)
    dy = abs(y1 - y0)
    sx = 1 if x0 < x1 else -1
    sy = 1 if y0 < y1 else -1
    err = dx - dy
    while True:
        if 0 <= x0 < width and 0 <= y0 < height:
            idx = (y0 * width + x0) * 3
            if idx + 2 < total_len:
                pixels[idx] = rgb[0]
                pixels[idx + 1] = rgb[1]
                pixels[idx + 2] = rgb[2]
        if x0 == x1 and y0 == y1:
            break
        e2 = 2 * err
        if e2 > -dy:
            err -= dy
            x0 += sx
        if e2 < dx:
            err += dx
            y0 += sy


def _draw_text_png(pixels: list, width: int, x: int, y: int, text: str, rgb: list) -> None:
    cx, cy = x, y
    total_len = len(pixels)
    height = total_len // (width * 3)
    for ch in text.upper():
        glyph = _FONT_5X7_PNG.get(ch, ["00000"] * 7)
        for row_idx, row in enumerate(glyph):
            for col_idx, bit in enumerate(row):
                if bit == "1":
                    px = cx + col_idx
                    py = cy + row_idx
                    if 0 <= px < width and 0 <= py < height:
                        idx = (py * width + px) * 3
                        if idx + 2 < total_len:
                            pixels[idx] = rgb[0]
                            pixels[idx + 1] = rgb[1]
                            pixels[idx + 2] = rgb[2]
        cx += 6


def _save_png_png(pixels: list, width: int, height: int, path: str) -> None:
    signature = b'\x89PNG\r\n\x1a\n'

    def make_chunk(chunk_type, data):
        chunk_len = struct.pack(">I", len(data))
        chunk_crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
        return chunk_len + chunk_type + data + chunk_crc

    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr = make_chunk(b"IHDR", ihdr_data)

    raw_data = bytearray()
    stride = width * 3
    for y in range(height):
        raw_data.append(0)
        start = y * stride
        raw_data.extend(pixels[start:start + stride])

    compressed = zlib.compress(bytes(raw_data), 9)
    idat = make_chunk(b"IDAT", compressed)
    iend = make_chunk(b"IEND", b"")

    with open(path, "wb") as f:
        f.write(signature)
        f.write(ihdr)
        f.write(idat)
        f.write(iend)


# 5x7 点阵字体（PNG 模块用）
_FONT_5X7_PNG = {
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "B": ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
    "C": ["01110", "10001", "10000", "10000", "10000", "10001", "01110"],
    "D": ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "F": ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
    "G": ["01110", "10001", "10000", "10111", "10001", "10001", "01110"],
    "H": ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    "I": ["01110", "00100", "00100", "00100", "00100", "00100", "01110"],
    "J": ["00111", "00010", "00010", "00010", "00010", "10010", "01100"],
    "K": ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
    "L": ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
    "M": ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
    "N": ["10001", "10001", "11001", "10101", "10011", "10001", "10001"],
    "O": ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
    "P": ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    "Q": ["01110", "10001", "10001", "10001", "10101", "10010", "01101"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    "S": ["01110", "10001", "10000", "01110", "00001", "10001", "01110"],
    "T": ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    "U": ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
    "V": ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
    "W": ["10001", "10001", "10001", "10101", "10101", "10101", "01010"],
    "X": ["10001", "10001", "01010", "00100", "01010", "10001", "10001"],
    "Y": ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
    "Z": ["11111", "00001", "00010", "00100", "01000", "10000", "11111"],
    "0": ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
    "1": ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
    "2": ["01110", "10001", "00001", "00010", "00100", "01000", "11111"],
    "3": ["01110", "10001", "00001", "00110", "00001", "10001", "01110"],
    "4": ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
    "5": ["11111", "10000", "11110", "00001", "00001", "10001", "01110"],
    "6": ["01110", "10000", "10000", "11110", "10001", "10001", "01110"],
    "7": ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
    "8": ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    "9": ["01110", "10001", "10001", "01111", "00001", "00001", "01110"],
    "-": ["00000", "00000", "00000", "11111", "00000", "00000", "00000"],
    ".": ["00000", "00000", "00000", "00000", "00000", "01100", "01100"],
    ":": ["00000", "01100", "01100", "00000", "01100", "01100", "00000"],
    " ": ["00000", "00000", "00000", "00000", "00000", "00000", "00000"],
}


def _get_severity_bg(severity: str) -> str:
    """获取严重度标签背景色"""
    colors = {
        "CRITICAL": "#b62324",
        "HIGH": "#d29922",
        "MEDIUM": "#bf8700",
        "LOW": "#2ea043",
        "INFO": "#8b949e",
    }
    return colors.get(severity, "#6e7681")


def _get_severity_fg(severity: str) -> str:
    """获取严重度标签前景色"""
    return "#ffffff"
