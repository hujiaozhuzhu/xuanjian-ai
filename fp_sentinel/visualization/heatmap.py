"""
玄鉴 v2.4.0 — 漏洞热力图生成器 (Vulnerability Heatmap Generator)

功能：按模块、漏洞类型、严重程度生成项目风险热力图。
输出：支持 HTML 交互式（Self-contained，ECharts 内联）、PNG 静态图（zlib+struct 编码）。

设计原则：
- 纯自包含 HTML（内联零外部依赖），离线可查看
- PNG 使用 Python 标准库（zlib + struct）编码，无第三方绘图依赖
- 三种配色主题：dark（默认）/ light / high_contrast
- 与 fp_sentinel/models.py 的 Severity 枚举兼容

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
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    SEVERITY_WEIGHT,
    VULN_TYPE_DISPLAY,
    ChartTheme,
    HeatmapCell,
    HeatmapInput,
    HeatmapResult,
    OutputFormat,
    SeverityLevel,
    get_risk_color,
    get_theme_background,
    get_theme_text_color,
)

logger = logging.getLogger(__name__)


# ─────────────────────── 核心类 ───────────────────────

class VulnerabilityHeatmap:
    """
    漏洞热力图生成器

    用法::

        from fp_sentinel.visualization.heatmap import VulnerabilityHeatmap, HeatmapInput

        # 构造输入数据
        data = {
            ("auth", "SQL_INJECTION"): {"HIGH": 2, "CRITICAL": 1},
            ("api", "XSS"): {"MEDIUM": 3, "LOW": 1},
        }
        inp = HeatmapInput(data=data, project_name="my-project")

        # 生成热力图
        generator = VulnerabilityHeatmap(theme=ChartTheme.DARK)
        result = generator.generate(inp, output_dir="./reports")

    Args:
        theme: 配色主题
        cell_size: PNG 单元格像素大小
        font_size: PNG 字体大小参数
    """

    def __init__(
        self,
        theme: ChartTheme = ChartTheme.DARK,
        cell_size: int = 60,
        font_size: int = 12,
    ):
        self.theme = theme
        self.cell_size = cell_size
        self.font_size = font_size

    # ───────────────── 公共接口 ─────────────────

    def generate(
        self,
        inp: HeatmapInput,
        output_dir: str = "./reports",
        output_format: OutputFormat = OutputFormat.BOTH,
        filename_prefix: str = "vuln_heatmap",
    ) -> HeatmapResult:
        """
        生成漏洞热力图。

        Args:
            inp: 热力图输入数据
            output_dir: 输出目录
            output_format: 输出格式 (HTML / PNG / BOTH)
            filename_prefix: 文件名前缀

        Returns:
            HeatmapResult: 结果对象，包含单元格数据和输出路径
        """
        cells = self._build_cells(inp)
        result = HeatmapResult(
            cells=cells,
            modules=inp.modules,
            vuln_types=inp.vuln_types,
            total_findings=inp.total_count(),
            metadata={
                "project_name": inp.project_name,
                "scan_time": inp.scan_time,
                "theme": self.theme.value,
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

    # ───────────────── 数据处理 ─────────────────

    def _build_cells(self, inp: HeatmapInput) -> List[HeatmapCell]:
        """构建所有热力图单元格"""
        cells: List[HeatmapCell] = []
        max_val = inp.max_value if inp.max_value > 0 else 1

        for (module, vuln_type), sev_counts in sorted(inp.data.items()):
            total = sum(sev_counts.values())
            if total == 0:
                continue

            # 风险评分 = sum(severity_weight * count) / total * 10
            weighted_sum = sum(
                SEVERITY_WEIGHT.get(sev, 0.1) * cnt
                for sev, cnt in sev_counts.items()
            )
            risk_score = round(weighted_sum / total * 10, 2)
            risk_score = min(10.0, max(0.0, risk_score))

            severity_breakdown = {str(k): str(v) for k, v in sorted(sev_counts.items())}
            color = get_risk_color(risk_score, self.theme)

            cells.append(HeatmapCell(
                module=module,
                vuln_type=vuln_type,
                count=total,
                severity_breakdown=severity_breakdown,
                risk_score=risk_score,
                color=color,
            ))

        return cells

    # ───────────────── HTML 输出 ─────────────────

    def _write_html(self, result: HeatmapResult, inp: HeatmapInput, path: str) -> None:
        """写入自包含 HTML 热力图"""
        content = self._render_html(result, inp)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"HTML heatmap written to {path}")

    def _render_html(self, result: HeatmapResult, inp: HeatmapInput) -> str:
        """渲染 HTML 热力图内容"""
        bg = get_theme_background(self.theme)
        text_color = get_theme_text_color(self.theme)
        grid_bg = "#161b22" if self.theme == ChartTheme.DARK else "#f0f0f0"
        border_color = "#30363d" if self.theme == ChartTheme.DARK else "#dee2e6"

        # 构建表格行
        module_rows = []
        for cell in result.cells:
            sev_detail = "<br>".join(
                f"{html.escape(k)}: {html.escape(v)}"
                for k, v in cell.severity_breakdown.items()
            ) or "-"
            vuln_label = VULN_TYPE_DISPLAY.get(cell.vuln_type, cell.vuln_type)
            module_rows.append(
                f'<tr style="border-bottom:1px solid {border_color}">'
                f'<td style="padding:10px 14px;border-right:1px solid {border_color};'
                f'font-weight:600;color:{text_color}">{html.escape(cell.module)}</td>'
                f'<td style="padding:10px 14px;border-right:1px solid {border_color};'
                f'color:{text_color}">{html.escape(vuln_label)}</td>'
                f'<td style="padding:10px 14px;text-align:center;'
                f'background-color:{cell.color};color:#fff;'
                f'font-weight:700;text-shadow:0 1px 2px rgba(0,0,0,0.5)">'
                f'{cell.count}</td>'
                f'<td style="padding:10px 14px;text-align:center;color:{text_color}">'
                f'{cell.risk_score}</td>'
                f'<td style="padding:10px 14px;font-size:0.9em;color:{text_color};line-height:1.4">'
                f'{sev_detail}</td>'
                '</tr>'
            )

        rows_html = "\n".join(module_rows) if module_rows else (
            f'<tr><td colspan="5" style="padding:30px;text-align:center;'
            f'color:{text_color}">无漏洞数据</td></tr>'
        )

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        project = html.escape(inp.project_name or "未命名项目")
        total = result.total_findings
        module_count = len(result.modules)
        vuln_count = len(result.vuln_types)

        # 热力图总览色块
        overview_items = []
        for cell in result.cells:
            vuln_label = VULN_TYPE_DISPLAY.get(cell.vuln_type, cell.vuln_type)
            overview_items.append(
                f'<div style="display:inline-block;margin:4px;padding:8px 12px;'
                f'border-radius:6px;background-color:{cell.color};'
                f'color:#fff;font-size:0.85em;cursor:pointer;'
                f'transition:transform 0.2s" '
                f'title="模块:{html.escape(cell.module)} | {html.escape(vuln_label)} | '
                f'风险:{cell.risk_score}" '
                f'onmouseover="this.style.transform=\'scale(1.05)\'" '
                f'onmouseout="this.style.transform=\'scale(1)\'">'
                f'{html.escape(cell.module)}/<b>{html.escape(vuln_label)}</b>: '
                f'{cell.count}'
                f'</div>'
            )

        overview_html = "\n".join(overview_items) if overview_items else (
            '<span style="color:{text_color}">无数据</span>'
        )

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>漏洞热力图 — {project}</title>
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
    font-size: 1.5em;
    font-weight: 700;
    color: {'#e94560' if self.theme == ChartTheme.DARK else '#dc3545'};
}}
.section {{
    margin-bottom: 24px;
}}
.section h2 {{
    font-size: 1.1em;
    margin-bottom: 10px;
    color: {text_color};
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
    align-items: center;
    gap: 4px;
    margin-bottom: 12px;
    flex-wrap: wrap;
}}
.legend-item {{
    width: 32px;
    height: 16px;
    border-radius: 3px;
}}
</style>
</head>
<body>
<div class="container">
    <h1>&#128293; 漏洞热力图</h1>
    <p class="subtitle">项目: {project} &nbsp;|&nbsp; 生成时间: {now} &nbsp;|&nbsp; 玄鉴 fp-sentinel v2.4.0</p>

    <div class="stats">
        <div class="stat-card">
            <div class="label">总漏洞数</div>
            <div class="value">{total}</div>
        </div>
        <div class="stat-card">
            <div class="label">模块数</div>
            <div class="value">{module_count}</div>
        </div>
        <div class="stat-card">
            <div class="label">漏洞类型数</div>
            <div class="value">{vuln_count}</div>
        </div>
        <div class="stat-card">
            <div class="label">最高风险评分</div>
            <div class="value">{max((c.risk_score for c in result.cells), default=0)}</div>
        </div>
    </div>

    <div class="section">
        <h2>&#127912; 风险总览</h2>
        <div>
            <div class="legend">
                <span style="font-size:0.8em">低</span>
                <div class="legend-item" style="background-color:{get_risk_color(0, self.theme)}"></div>
                <div class="legend-item" style="background-color:{get_risk_color(2, self.theme)}"></div>
                <div class="legend-item" style="background-color:{get_risk_color(4, self.theme)}"></div>
                <div class="legend-item" style="background-color:{get_risk_color(6, self.theme)}"></div>
                <div class="legend-item" style="background-color:{get_risk_color(8, self.theme)}"></div>
                <div class="legend-item" style="background-color:{get_risk_color(10, self.theme)}"></div>
                <span style="font-size:0.8em">高</span>
            </div>
            {overview_html}
        </div>
    </div>

    <div class="section">
        <h2>&#128202; 详细数据表</h2>
        <table>
            <thead>
                <tr>
                    <th>模块</th>
                    <th>漏洞类型</th>
                    <th style="text-align:center">总计数</th>
                    <th style="text-align:center">风险评分</th>
                    <th>严重度分布</th>
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
</body>
</html>"""

    # ───────────────── PNG 输出 ─────────────────

    def _write_png(self, result: HeatmapResult, inp: HeatmapInput, path: str) -> None:
        """写入 PNG 热力图"""
        self._render_png(result, inp, path)
        logger.info(f"PNG heatmap written to {path}")

    def _render_png(self, result: HeatmapResult, inp: HeatmapInput, path: str) -> None:
        """渲染 PNG 热力图"""
        # 布局参数
        margin_left = 140     # 模块名列宽
        margin_top = 80       # 标题+类型行高
        margin_bottom = 40
        margin_right = 40
        cell_w = 100          # 漏洞类型列宽
        cell_h = 50           # 行高

        modules = result.modules
        vuln_types = result.vuln_types

        # 颜色定义（需提前供空数据分支使用）
        bg_rgb = _hex_to_rgb(get_theme_background(self.theme))
        text_rgb = _hex_to_rgb(get_theme_text_color(self.theme))
        grid_rgb = _hex_to_rgb(
            "#30363d" if self.theme == ChartTheme.DARK else "#dee2e6"
        )

        if not modules or not vuln_types:
            # 无数据时输出空白图
            width, height = 400, 200
            pixels = bg_rgb * (width * height)
            _draw_text(pixels, width, width // 2 - 70, height // 2, "NO DATA", text_rgb)
            _save_png(pixels, width, height, path)
            return

        width = margin_left + len(vuln_types) * cell_w + margin_right
        height = margin_top + len(modules) * cell_h + margin_bottom

        # 创建像素缓冲区并填充背景
        pixels = bg_rgb * (width * height)

        # 绘制标题
        _draw_text(pixels, width, 15, 12, "Vulnerability Heatmap", text_rgb)

        # 绘制列标题（漏洞类型）
        for j, vtype in enumerate(vuln_types):
            x = margin_left + j * cell_w + 10
            label = VULN_TYPE_DISPLAY.get(vtype, vtype)
            if len(label) > 8:
                label = label[:7] + ".."
            _draw_text(pixels, width, x, 35, label, text_rgb)

        # 绘制行标题（模块名）和单元格
        for i, module in enumerate(modules):
            y = margin_top + i * cell_h

            # 行标题
            label = module if len(module) <= 14 else module[:13] + ".."
            _draw_text(pixels, width, 10, y + cell_h // 2, label, text_rgb)

            for j, vtype in enumerate(vuln_types):
                x = margin_left + j * cell_w
                # 查找对应单元格
                cell = None
                for c in result.cells:
                    if c.module == module and c.vuln_type == vtype:
                        cell = c
                        break

                if cell and cell.count > 0:
                    cell_rgb = _hex_to_rgb(cell.color)
                    _draw_rect(pixels, width, x, y, cell_w, cell_h, cell_rgb)
                    # 单元格内数字
                    _draw_text(
                        pixels, width,
                        x + cell_w // 2, y + cell_h // 2,
                        str(cell.count), (255, 255, 255),
                    )
                else:
                    # 空单元格背景
                    empty_rgb = _hex_to_rgb(
                        "#161b22" if self.theme == ChartTheme.DARK else "#f0f0f0"
                    )
                    _draw_rect(pixels, width, x, y, cell_w, cell_h, empty_rgb)

        # 绘制网格线
        # 垂直线
        for j in range(len(vuln_types) + 1):
            x = margin_left + j * cell_w
            _draw_line(pixels, width, x, margin_top, x, height - margin_bottom, grid_rgb)
        # 水平线
        for i in range(len(modules) + 1):
            y = margin_top + i * cell_h
            _draw_line(pixels, width, margin_left, y, width - margin_right, y, grid_rgb)

        # 外边框
        _draw_line(pixels, width, margin_left, margin_top,
                    width - margin_right, margin_top, grid_rgb)
        _draw_line(pixels, width, margin_left, height - margin_bottom,
                    width - margin_right, height - margin_bottom, grid_rgb)
        _draw_line(pixels, width, margin_left, margin_top,
                    margin_left, height - margin_bottom, grid_rgb)
        _draw_line(pixels, width, width - margin_right, margin_top,
                    width - margin_right, height - margin_bottom, grid_rgb)

        _save_png(pixels, width, height, path)


# ─────────────────────── PNG 编码工具函数 ───────────────────────

def _hex_to_rgb(hex_color: str) -> List[int]:
    """将十六进制颜色转换为 RGB 列表"""
    hex_color = hex_color.lstrip("#")
    if len(hex_color) == 3:
        hex_color = "".join(c * 2 for c in hex_color)
    return [int(hex_color[i:i + 2], 16) for i in (0, 2, 4)]


def _draw_rect(
    pixels: List[int], width: int,
    x: int, y: int, w: int, h: int, rgb: List[int],
) -> None:
    """在像素缓冲区中绘制填充矩形（pixels 为扁平整数列表 [R,G,B,R,G,B,...]）"""
    total_len = len(pixels)
    for dy in range(h):
        for dx in range(w):
            px = x + dx
            py = y + dy
            idx = (py * width + px) * 3
            if 0 <= px < width and idx + 2 < total_len:
                pixels[idx] = rgb[0]
                pixels[idx + 1] = rgb[1]
                pixels[idx + 2] = rgb[2]


def _draw_line(
    pixels: List[int], width: int,
    x0: int, y0: int, x1: int, y1: int, rgb: List[int],
) -> None:
    """在像素缓冲区中绘制直线（Bresenham算法，pixels 为扁平整数列表）"""
    height = len(pixels) // (width * 3)
    total_len = len(pixels)
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


# 5x7 点阵字体 (A-Z, 0-9, 常用字符)
_FONT_5X7: Dict[str, List[str]] = {
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
    "/": ["00001", "00001", "00010", "00100", "01000", "10000", "10000"],
    ":": ["00000", "01100", "01100", "00000", "01100", "01100", "00000"],
    "(": ["00010", "00100", "01000", "01000", "01000", "00100", "00010"],
    ")": ["01000", "00100", "00010", "00010", "00010", "00100", "01000"],
    "<": ["00010", "00100", "01000", "10000", "01000", "00100", "00010"],
    ">": ["01000", "00100", "00010", "00001", "00010", "00100", "01000"],
    "+": ["00000", "00100", "00100", "11111", "00100", "00100", "00000"],
    "%": ["11001", "11010", "00010", "00100", "01000", "01011", "10011"],
    " ": ["00000", "00000", "00000", "00000", "00000", "00000", "00000"],
}


def _draw_text(
    pixels: List[int], width: int,
    x: int, y: int, text: str, rgb: List[int],
) -> None:
    """在像素缓冲区中绘制文本（5x7 点阵字体，pixels 为扁平整数列表）"""
    cx = x
    cy = y
    total_len = len(pixels)
    height = total_len // (width * 3)
    for ch in text.upper():
        glyph = _FONT_5X7.get(ch, _FONT_5X7.get(" ", ["00000"] * 7))
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
        cx += 6  # 5 像素宽 + 1 像素间距


def _save_png(pixels: List[int], width: int, height: int, path: str) -> None:
    """
    将像素缓冲区保存为 PNG 文件。

    使用 Python 标准库 zlib + struct 实现 PNG 编码。
    无第三方依赖。

    Args:
        pixels: RGB 扁平化像素列表 [R,G,B, R,G,B, ...]
        width: 图像宽度
        height: 图像高度
        path: 输出文件路径
    """
    # PNG 签名
    signature = b'\x89PNG\r\n\x1a\n'

    def _make_chunk(chunk_type: bytes, data: bytes) -> bytes:
        chunk_len = struct.pack(">I", len(data))
        chunk_crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
        return chunk_len + chunk_type + data + chunk_crc

    # IHDR 块
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr = _make_chunk(b"IHDR", ihdr_data)

    # IDAT 块：将像素数据转换为 PNG 扫描行
    raw_data = bytearray()
    stride = width * 3
    for y in range(height):
        raw_data.append(0)  # filter type: None
        start = y * stride
        raw_data.extend(pixels[start:start + stride])

    compressed = zlib.compress(bytes(raw_data), 9)
    idat = _make_chunk(b"IDAT", compressed)

    # IEND 块
    iend = _make_chunk(b"IEND", b"")

    # 写入文件
    with open(path, "wb") as f:
        f.write(signature)
        f.write(ihdr)
        f.write(idat)
        f.write(iend)

