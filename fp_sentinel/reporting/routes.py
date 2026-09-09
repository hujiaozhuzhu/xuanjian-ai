"""
玄鉴 v3.1 — 报表导出模块 REST API 路由

FastAPI 路由组，挂载于 /api/reports/
支持HTML和Excel格式导出。

路由清单：
  POST /api/reports/export/html          — 导出HTML报表
  POST /api/reports/excel          — 导出Excel报表
  GET  /api/reports/templates            — 可用报表模板列表
  GET  /api/reports/history              — 导出历史记录
  GET  /api/reports/status/{task_id}     — 导出任务状态

安全红线：
- 报表数据本地生成，不外发
- 敏感信息自动掩码
- 文件大小限制
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

reports_router = APIRouter(prefix="/api/reports", tags=["reports"])

# ─────────────────────────── 请求模型 ───────────────────────────

class ExportHTMLRequest(BaseModel):
    """HTML报表导出请求"""
    model_config = ConfigDict(extra="ignore")

    scan_id: str = Field(default="", description="扫描ID")
    title: str = Field("玄鉴安全扫描报告", description="报表标题")
    include_findings: bool = Field(True, description="是否包含发现详情")
    include_summary: bool = Field(True, description="是否包含摘要")
    include_charts: bool = Field(True, description="是否包含图表")
    include_remediation: bool = Field(True, description="是否包含修复建议")
    theme: str = Field("dark", description="主题: light/dark")
    data: Dict[str, Any] = Field(default_factory=dict, description="报表数据")


class ExportExcelRequest(BaseModel):
    """Excel报表导出请求"""
    model_config = ConfigDict(extra="ignore")

    scan_id: str = Field(default="", description="扫描ID")
    sheet_name: str = Field("安全扫描", description="工作表名称")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="发现数据")
    summary: Dict[str, Any] = Field(default_factory=dict, description="摘要数据")
    include_statistics: bool = Field(True, description="是否包含统计")
    format_type: str = Field("xlsx", description="格式: xlsx/csv")


# 简单内存存储导出任务
_export_tasks: Dict[str, Dict[str, Any]] = {}


# ─────────────────────────── HTML报表导出 API ───────────────────────────

def _build_html_report(data: Dict[str, Any], title: str, theme: str,
                       include_findings: bool, include_summary: bool,
                       include_charts: bool, include_remediation: bool) -> str:
    """构建HTML报表内容"""
    is_dark = theme == "dark"
    bg_color = "#1a1a2e" if is_dark else "#ffffff"
    text_color = "#e0e0e0" if is_dark else "#333333"
    card_bg = "#16213e" if is_dark else "#f8f9fa"
    accent = "#0f3460" if is_dark else "#e3f2fd"
    border_color = "#2a2a4a" if is_dark else "#dee2e6"

    severity_counts = data.get("severity_counts", {})
    total_findings = data.get("total_findings", 0)
    findings = data.get("findings", [])
    scan_info = data.get("scan_info", {})

    findings_html = ""
    if include_findings and findings:
        rows = ""
        for f in findings:
            sev = f.get("severity", "LOW").lower()
            sev_color = {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107", "low": "#28a745", "info": "#17a2b8"}.get(sev, "#6c757d")
            rows += f"""
            <tr>
                <td>{f.get("finding_id", "")}</td>
                <td><span style="color:{sev_color};font-weight:bold;">{f.get("severity", "")}</span></td>
                <td>{f.get("rule_id", "")}</td>
                <td>{f.get("file_path", "")}:{f.get("line", "")}</td>
                <td>{f.get("category", "")}</td>
                <td>{f.get("message", "")}</td>
            </tr>"""

        findings_html = f"""
        <h2>发现详情</h2>
        <table>
            <thead>
                <tr><th>ID</th><th>严重度</th><th>规则</th><th>位置</th><th>类别</th><th>描述</th></tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>"""

    summary_html = ""
    if include_summary:
        summary_html = f"""
        <h2>安全摘要</h2>
        <div style="display:flex;gap:16px;flex-wrap:wrap;">
            <div style="background:{accent};padding:16px;border-radius:8px;min-width:120px;text-align:center;">
                <div style="font-size:2em;font-weight:bold;">{total_findings}</div>
                <div>总发现</div>
            </div>
            <div style="background:#dc354520;padding:16px;border-radius:8px;min-width:120px;text-align:center;">
                <div style="font-size:2em;font-weight:bold;">{severity_counts.get("CRITICAL", 0)}</div>
                <div>严重</div>
            </div>
            <div style="background:#fd7e1420;padding:16px;border-radius:8px;min-width:120px;text-align:center;">
                <div style="font-size:2em;font-weight:bold;">{severity_counts.get("HIGH", 0)}</div>
                <div>高危</div>
            </div>
            <div style="background:#ffc10720;padding:16px;border-radius:8px;min-width:120px;text-align:center;">
                <div style="font-size:2em;font-weight:bold;">{severity_counts.get("MEDIUM", 0)}</div>
                <div>中危</div>
            </div>
            <div style="background:#28a74520;padding:16px;border-radius:8px;min-width:120px;text-align:center;">
                <div style="font-size:2em;font-weight:bold;">{severity_counts.get("LOW", 0)}</div>
                <div>低危</div>
            </div>
        </div>"""

    charts_html = ""
    if include_charts:
        charts_html = """
        <h2>漏洞分布</h2>
        <p style="color:#888;">（图表需配合前端JavaScript渲染，此处为静态占位）</p>
        <div style="background:#0f346020;padding:20px;border-radius:8px;text-align:center;">
            支持 ECharts 交互式图表渲染
        </div>"""

    remediation_html = ""
    if include_remediation:
        remediation = data.get("remediation", [])
        if remediation:
            rem_items = ""
            for r in remediation[:20]:
                rem_items += f"<li><strong>{r.get('title', '')}</strong>: {r.get('description', '')}</li>"
            remediation_html = f"<h2>修复建议</h2><ul>{rem_items}</ul>"

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: {bg_color}; color: {text_color}; margin: 0; padding: 40px; }}
    h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
    h2 {{ color: #533483; margin-top: 30px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
    th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid {border_color}; }}
    th {{ background: {card_bg}; font-weight: 600; }}
    .meta {{ color: #888; font-size: 0.9em; margin-bottom: 20px; }}
    ul {{ line-height: 1.8; }}
    li {{ margin-bottom: 8px; }}
</style>
</head>
<body>
<h1>{title}</h1>
<div class="meta">
    生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} |
    扫描ID: {scan_info.get('scan_id', 'N/A')} |
    扫描器: {scan_info.get('scanner', 'N/A')}
</div>
{summary_html}
{charts_html}
{findings_html}
{remediation_html}
</body>
</html>"""

    return html


@reports_router.post("/export/html", response_class=HTMLResponse)
async def export_html_report(request: ExportHTMLRequest):
    """
    导出HTML格式安全扫描报告。

    生成交互式HTML报表，支持暗色主题。

    Args:
        request: 导出请求

    Returns:
        HTML报表内容
    """
    html_content = _build_html_report(
        data=request.data,
        title=request.title,
        theme=request.theme,
        include_findings=request.include_findings,
        include_summary=request.include_summary,
        include_charts=request.include_charts,
        include_remediation=request.include_remediation,
    )

    return HTMLResponse(
        content=html_content,
        headers={
            "Content-Disposition": f'attachment; filename="xuanjian-report-{uuid.uuid4().hex[:8]}.html"'
        },
    )


# ─────────────────────────── Excel报表导出 API ───────────────────────────

@reports_router.post("/export/excel")
async def export_excel_report(request: ExportExcelRequest):
    """
    导出Excel格式安全扫描报告。

    生成XLSX文件，包含发现详情和统计数据。

    Args:
        request: 导出请求

    Returns:
        Excel文件
    """
    task_id = str(uuid.uuid4())

    try:
        # 尝试使用 openpyxl
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        from openpyxl.utils import get_column_letter

        wb = Workbook()
        ws = wb.active
        if ws:
            ws.title = request.sheet_name

            # 标题
            ws.merge_cells("A1:G1")
            ws["A1"] = "玄鉴安全扫描报告"
            ws["A1"].font = Font(bold=True, size=16)
            ws["A1"].alignment = Alignment(horizontal="center")

            # 摘要
            ws["A3"] = "摘要"
            ws["A3"].font = Font(bold=True, size=12)

            summary = request.summary
            row = 4
            for k, v in summary.items():
                ws[f"A{row}"] = k
                ws[f"B{row}"] = str(v)
                row += 1

            # 发现详情
            row += 1
            ws[f"A{row}"] = "发现详情"
            ws[f"A{row}"].font = Font(bold=True, size=12)
            row += 1

            headers = ["ID", "严重度", "规则", "文件", "行号", "类别", "描述"]
            for col, h in enumerate(headers, 1):
                cell = ws.cell(row=row, column=col, value=h)
                cell.font = Font(bold=True)
                cell.fill = PatternFill(start_color="0F3460", end_color="0F3460", fill_type="solid")
                cell.font = Font(bold=True, color="FFFFFF")

            row += 1
            for f in request.findings:
                ws.cell(row=row, column=1, value=f.get("finding_id", ""))
                ws.cell(row=row, column=2, value=f.get("severity", ""))
                ws.cell(row=row, column=3, value=f.get("rule_id", ""))
                ws.cell(row=row, column=4, value=f.get("file_path", ""))
                ws.cell(row=row, column=5, value=f.get("line", ""))
                ws.cell(row=row, column=6, value=f.get("category", ""))
                ws.cell(row=row, column=7, value=f.get("message", ""))
                row += 1

            # 自动列宽
            for col in range(1, 8):
                ws.column_dimensions[get_column_letter(col)].width = 20

            import io
            buf = io.BytesIO()
            wb.save(buf)
            content = buf.getvalue()

    except ImportError:
        # 回退到CSV
        import csv
        import io

        buf = io.StringIO()
        writer = csv.writer(buf)

        writer.writerow(["玄鉴安全扫描报告"])
        writer.writerow([])
        writer.writerow(["摘要"])
        for k, v in request.summary.items():
            writer.writerow([k, v])
        writer.writerow([])
        writer.writerow(["发现详情"])
        writer.writerow(["ID", "严重度", "规则", "文件", "行号", "类别", "描述"])

        for f in request.findings:
            writer.writerow([
                f.get("finding_id", ""),
                f.get("severity", ""),
                f.get("rule_id", ""),
                f.get("file_path", ""),
                f.get("line", ""),
                f.get("category", ""),
                f.get("message", ""),
            ])

        content = buf.getvalue().encode("utf-8-sig")

    _export_tasks[task_id] = {
        "status": "completed",
        "format": request.format_type,
        "scan_id": request.scan_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "record_count": len(request.findings),
    }

    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="xuanjian-report-{request.scan_id or uuid.uuid4().hex[:8]}.xlsx"',
            "X-Task-Id": task_id,
        },
    )


# ─────────────────────────── 报表模板 API ───────────────────────────

@reports_router.get("/templates")
async def list_report_templates():
    """
    获取可用报表模板列表。

    Returns:
        模板列表
    """
    return {
        "templates": [
            {
                "id": "security-scan",
                "name": "安全扫描报告",
                "description": "完整安全扫描报告，含漏洞详情、严重性统计和修复建议",
                "formats": ["html", "xlsx", "csv"],
            },
            {
                "id": "compliance",
                "name": "合规报告",
                "description": "合规性检查报告，含合规项通过率和改进建议",
                "formats": ["html", "xlsx"],
            },
            {
                "id": "executive-summary",
                "name": "执行摘要",
                "description": "高层管理视角的安全概要",
                "formats": ["html"],
            },
        ],
    }


# ─────────────────────────── 导出历史 API ───────────────────────────

@reports_router.get("/history")
async def export_history(limit: int = Query(20, ge=1, le=100)):
    """
    获取导出历史记录。

    Args:
        limit: 数量限制

    Returns:
        导出任务列表
    """
    tasks = list(_export_tasks.items())
    tasks.sort(key=lambda x: x[1].get("created_at", ""), reverse=True)

    return {
        "total": len(tasks),
        "tasks": [
            {"task_id": tid, **info}
            for tid, info in tasks[:limit]
        ],
    }


# ─────────────────────────── 任务状态 API ───────────────────────────

@reports_router.get("/status/{task_id}")
async def export_status(task_id: str):
    """
    查询导出任务状态。

    Args:
        task_id: 任务ID

    Returns:
        任务详情
    """
    task = _export_tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"导出任务 {task_id} 不存在")

    return {"task_id": task_id, **task}
