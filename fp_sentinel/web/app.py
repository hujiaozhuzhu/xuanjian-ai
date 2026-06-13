"""
玄鉴 Web 仪表板 - FastAPI 路由模块

提供 /api/v1/ 前缀的 REST API 和 WebSocket 实时推送。
可独立运行，也可被 server.py 导入集成。
"""

import json
import logging
import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Query, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel as PydanticBaseModel

from ..models import (
    ScanResult, FilterResult, FilterResponse, FilterStatistics,
    Verdict, ScanTool, Severity, Project, ProjectStats,
    FalsePositiveMark, ScanHistory, Finding,
    scan_result_to_finding,
)

logger = logging.getLogger(__name__)


# ─────────────────────── 请求模型 ───────────────────────

class ScanRequest(PydanticBaseModel):
    project_path: str
    language: str = "auto"
    scanners: Optional[List[str]] = None


class MarkFPRequest(PydanticBaseModel):
    reason: str
    scope: str = "instance"


class MarkTPRequest(PydanticBaseModel):
    reason: str = ""


class ExportRequest(PydanticBaseModel):
    scan_id: str
    format: str = "json"  # json / markdown


# ─────────────────────── API 路由工厂 ───────────────────────

def create_web_app(server=None) -> FastAPI:
    """
    创建 Web 仪表板 FastAPI 应用。

    Args:
        server: FPServer 实例，若为 None 则延迟导入创建

    Returns:
        FastAPI 实例，挂载了所有 API 和静态文件
    """
    if server is None:
        from ..server import FPServer
        server = FPServer()

    # ─────── API Key 认证 ───────
    API_KEY = os.environ.get("XUANJIAN_API_KEY")
    api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

    async def verify_api_key(request: Request, api_key: Optional[str] = Depends(api_key_header)):
        """API Key 认证依赖。未设置 XUANJIAN_API_KEY 时跳过认证。"""
        if not API_KEY:
            return  # 未配置 API Key，跳过认证（安全模式下应仅绑定 localhost）
        # 健康检查端点免认证
        if request.url.path in ("/api/v1/health", "/api/health"):
            return
        # 静态文件和 SPA 入口免认证
        if request.url.path.startswith("/static") or request.url.path == "/":
            return
        if api_key != API_KEY:
            raise HTTPException(status_code=401, detail="未授权：请提供有效的 API Key")

    app = FastAPI(
        title="玄鉴 Web 仪表板",
        description="XuanJian False Positive Sentinel - Web Dashboard API",
        version="0.1.0",
        dependencies=[Depends(verify_api_key)] if API_KEY else [],
    )

    # ─────── 静态文件 ───────
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # ─────── SPA 入口 ───────
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        index_file = static_dir / "index.html"
        if index_file.exists():
            return HTMLResponse(index_file.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>玄鉴 - index.html not found</h1>")

    # ═══════════════════ API v1 ═══════════════════

    # ── 仪表板统计 ──

    @app.get("/api/v1/stats")
    async def api_v1_stats():
        """获取全局统计信息"""
        stats = server.get_statistics()
        # 额外添加扫描数
        stats["total_scans"] = len([
            s for s in server._scans.values() if s.get("status") == "completed"
        ])
        return stats

    # ── 扫描 ──

    @app.post("/api/v1/scan")
    async def api_v1_scan(req: ScanRequest):
        """启动新扫描"""
        result = await server.scan_project(
            project_path=req.project_path,
            language=req.language,
            scanners=req.scanners,
        )
        return result

    @app.get("/api/v1/scans")
    async def api_v1_list_scans():
        """列出所有扫描记录"""
        scans = []
        for sid, scan in server._scans.items():
            scans.append({
                "id": sid,
                "project_path": scan.get("project_path", ""),
                "language": scan.get("language", "auto"),
                "status": scan.get("status", "unknown"),
                "started_at": scan.get("started_at"),
                "completed_at": scan.get("completed_at"),
                "total_findings": scan.get("total_findings", 0),
                "duration_seconds": scan.get("duration_seconds", 0),
                "stats": scan.get("stats"),
            })
        # 按开始时间倒序
        scans.sort(key=lambda x: x.get("started_at") or "", reverse=True)
        return scans

    @app.get("/api/v1/scans/{scan_id}")
    async def api_v1_scan_detail(scan_id: str):
        """获取扫描详情"""
        scan = server._scans.get(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="扫描不存在")
        return scan

    # ── 发现列表 ──

    @app.get("/api/v1/findings")
    async def api_v1_list_findings(
        scan_id: Optional[str] = None,
        verdict: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
    ):
        """列出发现，支持过滤和搜索"""
        findings = server.list_findings(scan_id=scan_id, verdict=verdict, severity=severity)

        # 按文件路径搜索
        if search:
            search_lower = search.lower()
            findings = [
                f for f in findings
                if search_lower in f.original.file.lower()
                or search_lower in f.original.rule_id.lower()
                or search_lower in f.original.message.lower()
            ]

        return [f.model_dump() for f in findings]

    @app.get("/api/v1/findings/{finding_id}")
    async def api_v1_finding_detail(finding_id: str):
        """获取单个发现详情"""
        fr = server.get_finding(finding_id)
        if fr is None:
            raise HTTPException(status_code=404, detail="发现不存在")
        return fr.model_dump()

    # ── 标记操作 ──

    @app.post("/api/v1/findings/{finding_id}/mark-fp")
    async def api_v1_mark_fp(finding_id: str, req: MarkFPRequest):
        """标记为误报"""
        ok = server.mark_false_positive(finding_id, req.reason, req.scope)
        if not ok:
            raise HTTPException(status_code=404, detail="发现不存在")
        return {"status": "ok", "finding_id": finding_id}

    @app.post("/api/v1/findings/{finding_id}/mark-tp")
    async def api_v1_mark_tp(finding_id: str, req: MarkTPRequest):
        """标记为真实问题"""
        fr = server._findings.get(finding_id)
        if fr is None:
            raise HTTPException(status_code=404, detail="发现不存在")
        fr.verdict = Verdict.TRUE_POSITIVE
        fr.recommendation = f"手动标记为真实问题" + (f": {req.reason}" if req.reason else "")
        return {"status": "ok", "finding_id": finding_id}

    # ── 项目列表 ──

    @app.get("/api/v1/projects")
    async def api_v1_projects():
        """列出已扫描的项目"""
        return server.list_projects()

    # ── 报告导出 ──

    @app.get("/api/v1/export/{scan_id}")
    async def api_v1_export(scan_id: str, format: str = Query("json")):
        """导出扫描报告"""
        scan = server._scans.get(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="扫描不存在")

        report = server.export_report(scan_id, fmt=format)

        if format == "markdown":
            return PlainTextResponse(
                content=report,
                media_type="text/markdown",
                headers={
                    "Content-Disposition": f'attachment; filename="xuanjian-report-{scan_id[:8]}.md"'
                },
            )
        else:
            return JSONResponse(
                content=json.loads(report) if isinstance(report, str) else report,
                headers={
                    "Content-Disposition": f'attachment; filename="xuanjian-report-{scan_id[:8]}.json"'
                },
            )

    # ── WebSocket 实时推送 ──

    @app.websocket("/ws/scan/{scan_id}")
    async def ws_scan(websocket: WebSocket, scan_id: str):
        await websocket.accept()
        server.register_ws(scan_id, websocket)
        try:
            while True:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
        except WebSocketDisconnect:
            pass
        finally:
            server.unregister_ws(scan_id, websocket)

    # ── 健康检查 ──

    @app.get("/api/v1/health")
    async def api_v1_health():
        return {
            "status": "ok",
            "version": "0.1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # 保存 server 引用
    app.state.fp_server = server

    return app


# ─────────────────────── 独立运行入口 ───────────────────────

def main():
    """独立运行 Web 仪表板"""
    import uvicorn
    app = create_web_app()
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")


if __name__ == "__main__":
    main()
