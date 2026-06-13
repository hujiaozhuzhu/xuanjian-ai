"""
FastAPI Web 服务器 + 核心服务层

提供：
- REST API 端点
- WebSocket 扫描进度推送
- 仪表板页面
- 三层误报过滤流水线
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from .models import (
    ScanResult, FilterResult, FilterResponse, FilterStatistics,
    Verdict, ScanTool, Severity, Project, ProjectStats,
    FalsePositiveMark, ScanHistory, Finding,
    scan_result_to_finding,
)
from .filters import RuleFilter, ContextFilter, BaselineFilter
from .scanners.manager import ScannerManager


logger = logging.getLogger(__name__)


# ─────────────────────── 核心服务层 ───────────────────────


class FPServer:
    """玄鉴误报过滤服务器"""

    # 兼容 test_example.py
    @property
    def config(self) -> Dict[str, Any]:
        return self._config_data

    def _calc_stats(self, results: List[FilterResult], processing_time_ms: float = 0.0) -> FilterStatistics:
        """计算统计信息（兼容 test_example.py）"""
        stats = self._calculate_statistics(results)
        stats.processing_time_ms = processing_time_ms
        return stats

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config_data = config or self._default_config()
        self.logger = logging.getLogger("fp_sentinel")

        # 过滤器（兼容 test_example.py 属性名）
        self.rule_filter = RuleFilter(self._config_data.get("rule_filter", {}))
        self.context_filter = ContextFilter(self._config_data.get("context_filter", {}))
        self.ml_filter = BaselineFilter(self._config_data.get("ml_filter", {}))

        # 扫描器管理器
        self.scanner_manager = ScannerManager(self._config_data.get("scanners", {}))

        # 运行时存储
        self._scans: Dict[str, Dict[str, Any]] = {}          # scan_id -> scan info
        self._findings: Dict[str, FilterResult] = {}          # finding_id -> FilterResult
        self._projects: Dict[str, Project] = {}               # project_id -> Project
        self._fp_marks: List[FalsePositiveMark] = []          # 误报标记
        self._scan_history: List[ScanHistory] = []            # 扫描历史
        self._ws_connections: Dict[str, List[Any]] = {}       # scan_id -> ws list

    @staticmethod
    def _default_config() -> Dict[str, Any]:
        return {
            "rule_filter": {"enabled": True},
            "context_filter": {"enabled": True, "false_positive_threshold": 0.5},
            "ml_filter": {"enabled": True, "confidence_threshold": 0.7},
            "scanners": {},
        }

    # ─────── 过滤流水线 ───────

    async def _apply_filters(
        self,
        scan_result: ScanResult,
        filter_level: str = "all",
        confidence_threshold: float = 0.7,
    ) -> FilterResult:
        """应用三层过滤器"""
        import time as _time
        start = _time.monotonic()

        current: Optional[FilterResult] = None

        # L1
        if filter_level in ("L1", "all"):
            current = await self.rule_filter.filter(scan_result)
            if current.is_false_positive and current.confidence >= confidence_threshold:
                return current

        # L2
        if filter_level in ("L2", "all"):
            l2_result = await self.context_filter.filter(scan_result)
            if l2_result.is_false_positive and l2_result.confidence >= confidence_threshold:
                return l2_result
            if current is None:
                current = l2_result
            elif l2_result.confidence > current.confidence:
                current = l2_result

        # L3
        if filter_level in ("L3", "all"):
            l3_result = await self.ml_filter.filter(scan_result)
            if l3_result.is_false_positive and l3_result.confidence >= confidence_threshold:
                return l3_result
            if current is None:
                current = l3_result

        if current is None:
            current = FilterResult(
                original=scan_result,
                verdict=Verdict.NEEDS_REVIEW,
                confidence=0.5,
                filter_reasons=[],
                risk_score=5.0,
                recommendation="未应用任何过滤器",
            )

        return current

    def _calculate_statistics(self, results: List[FilterResult]) -> FilterStatistics:
        """计算统计信息"""
        total = len(results)
        fps = sum(1 for r in results if r.verdict == Verdict.FALSE_POSITIVE)
        likely_fps = sum(1 for r in results if r.verdict == Verdict.LIKELY_FALSE_POSITIVE)
        tps = sum(1 for r in results if r.verdict == Verdict.TRUE_POSITIVE)
        needs_review = sum(1 for r in results if r.verdict == Verdict.NEEDS_REVIEW)

        filtered = fps + likely_fps
        rate = f"{(filtered / total * 100):.1f}%" if total > 0 else "0%"

        level_stats: Dict[str, int] = {"L1": 0, "L2": 0, "L3": 0}
        for r in results:
            for reason in r.filter_reasons:
                if reason.filter_level in level_stats:
                    level_stats[reason.filter_level] += 1

        return FilterStatistics(
            total=total,
            false_positives=fps,
            likely_false_positives=likely_fps,
            true_positives=tps,
            needs_review=needs_review,
            reduction_rate=rate,
            processing_time_ms=0.0,
            filter_level_stats=level_stats,
        )

    # ─────── 扫描操作 ───────

    async def scan_project(
        self,
        project_path: str,
        language: str = "auto",
        scanners: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """执行扫描"""
        scan_id = str(uuid.uuid4())
        start_time = time.monotonic()

        scan_tools = None
        if scanners:
            scan_tools = []
            for s in scanners:
                try:
                    scan_tools.append(ScanTool(s))
                except ValueError:
                    self.logger.warning(f"未知扫描器: {s}")

        # 注册扫描
        self._scans[scan_id] = {
            "id": scan_id,
            "project_path": project_path,
            "language": language,
            "status": "running",
            "started_at": datetime.utcnow().isoformat(),
            "progress": 0,
            "findings": [],
        }

        await self._broadcast_ws(scan_id, {"type": "status", "status": "running"})

        try:
            # 执行扫描
            raw_results = await self.scanner_manager.scan(
                project_path, language=language, scanners=scan_tools
            )
            await self._broadcast_ws(scan_id, {"type": "progress", "progress": 30, "phase": "scan_complete"})

            # 三层过滤
            filtered: List[FilterResult] = []
            for i, sr in enumerate(raw_results):
                fr = await self._apply_filters(sr)
                filtered.append(fr)
                # 存储
                fid = sr.id or f"{scan_id}:{i}"
                fr.id = fid
                self._findings[fid] = fr
                if i % 10 == 0:
                    pct = 30 + int(60 * i / max(len(raw_results), 1))
                    await self._broadcast_ws(scan_id, {"type": "progress", "progress": pct})

            stats = self._calculate_statistics(filtered)
            elapsed = time.monotonic() - start_time

            self._scans[scan_id].update({
                "status": "completed",
                "completed_at": datetime.utcnow().isoformat(),
                "total_findings": len(raw_results),
                "stats": stats.model_dump(),
                "findings": [fr.id for fr in filtered],
                "duration_seconds": round(elapsed, 2),
            })

            # 记录历史
            self._scan_history.append(ScanHistory(
                scan_id=scan_id,
                project_path=project_path,
                language=language,
                scanner=",".join(s.value for s in scan_tools) if scan_tools else "auto",
                total_findings=len(raw_results),
                duration_seconds=round(elapsed, 2),
                status="completed",
            ))

            await self._broadcast_ws(scan_id, {
                "type": "completed",
                "progress": 100,
                "stats": stats.model_dump(),
            })

            return {
                "scan_id": scan_id,
                "total_findings": len(raw_results),
                "statistics": stats.model_dump(),
                "duration_seconds": round(elapsed, 2),
            }

        except Exception as e:
            self._scans[scan_id]["status"] = "failed"
            self._scans[scan_id]["error"] = str(e)
            await self._broadcast_ws(scan_id, {"type": "error", "error": str(e)})
            raise

    # ─────── 查询操作 ───────

    def get_finding(self, finding_id: str) -> Optional[FilterResult]:
        return self._findings.get(finding_id)

    def list_findings(
        self,
        scan_id: Optional[str] = None,
        verdict: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[FilterResult]:
        results = list(self._findings.values())
        if scan_id and scan_id in self._scans:
            ids = set(self._scans[scan_id].get("findings", []))
            results = [r for r in results if r.id in ids]
        if verdict:
            results = [r for r in results if r.verdict.value == verdict]
        if severity:
            results = [r for r in results if r.original.severity.value == severity]
        return results

    def mark_false_positive(
        self, finding_id: str, reason: str, scope: str = "instance"
    ) -> bool:
        fr = self._findings.get(finding_id)
        if fr is None:
            return False
        fr.verdict = Verdict.FALSE_POSITIVE
        fr.recommendation = f"手动标记为误报: {reason}"

        mark = FalsePositiveMark(
            finding_id=finding_id,
            reason=reason,
            marked_by="manual",
            scope=scope,
        )
        self._fp_marks.append(mark)

        # 同时写入基线
        self.ml_filter.add_to_baseline(
            fr.original, verdict="false_positive", confidence=1.0, reason=reason
        )
        return True

    def list_projects(self) -> List[Dict[str, Any]]:
        """列出已扫描的项目"""
        seen: Dict[str, Dict[str, Any]] = {}
        for h in self._scan_history:
            p = h.project_path
            if p not in seen:
                seen[p] = {
                    "name": Path(p).name,
                    "path": p,
                    "language": h.language,
                    "scan_count": 0,
                    "last_scan": None,
                }
            seen[p]["scan_count"] += 1
            seen[p]["last_scan"] = h.timestamp.isoformat() if h.timestamp else None
        return list(seen.values())

    def get_statistics(self, project_path: Optional[str] = None) -> Dict[str, Any]:
        """获取项目统计"""
        findings = list(self._findings.values())
        total = len(findings)
        fps = sum(1 for f in findings if f.verdict == Verdict.FALSE_POSITIVE)
        likely_fps = sum(1 for f in findings if f.verdict == Verdict.LIKELY_FALSE_POSITIVE)
        tps = sum(1 for f in findings if f.verdict == Verdict.TRUE_POSITIVE)
        needs_review = sum(1 for f in findings if f.verdict == Verdict.NEEDS_REVIEW)

        return {
            "total_findings": total,
            "false_positives": fps,
            "likely_false_positives": likely_fps,
            "true_positives": tps,
            "needs_review": needs_review,
            "reduction_rate": f"{((fps + likely_fps) / total * 100):.1f}%" if total else "0%",
            "baseline_size": self.ml_filter.get_baseline_count(),
        }

    def export_report(self, scan_id: str, fmt: str = "json") -> str:
        """导出报告"""
        scan = self._scans.get(scan_id)
        if not scan:
            return json.dumps({"error": "scan not found"})

        findings = self.list_findings(scan_id=scan_id)
        stats = self._calculate_statistics(findings)

        report = {
            "scan_id": scan_id,
            "project_path": scan.get("project_path"),
            "language": scan.get("language"),
            "completed_at": scan.get("completed_at"),
            "statistics": stats.model_dump(),
            "findings": [f.model_dump() for f in findings],
        }

        if fmt == "json":
            return json.dumps(report, ensure_ascii=False, indent=2, default=str)

        # 简单 markdown 格式
        lines = [
            f"# 玄鉴扫描报告",
            f"",
            f"- **扫描ID**: `{scan_id}`",
            f"- **项目路径**: {scan.get('project_path')}",
            f"- **语言**: {scan.get('language')}",
            f"- **完成时间**: {scan.get('completed_at')}",
            f"",
            f"## 统计",
            f"",
            f"| 指标 | 数值 |",
            f"|------|------|",
            f"| 总发现 | {stats.total} |",
            f"| 误报 | {stats.false_positives} |",
            f"| 疑似误报 | {stats.likely_false_positives} |",
            f"| 真实问题 | {stats.true_positives} |",
            f"| 待复核 | {stats.needs_review} |",
            f"| 减少率 | {stats.reduction_rate} |",
            f"",
            f"## 发现详情",
            f"",
        ]

        for f in findings:
            sev = f.original.severity.value
            lines.append(f"### [{sev}] {f.original.rule_id}")
            lines.append(f"- **文件**: `{f.original.file}:{f.original.line}`")
            lines.append(f"- **判定**: {f.verdict.value}")
            lines.append(f"- **置信度**: {f.confidence:.2f}")
            lines.append(f"- **建议**: {f.recommendation}")
            lines.append("")

        return "\n".join(lines)

    # ─────── WebSocket ───────

    async def _broadcast_ws(self, scan_id: str, data: Dict[str, Any]):
        """广播 WebSocket 消息"""
        conns = self._ws_connections.get(scan_id, [])
        dead = []
        for ws in conns:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            conns.remove(ws)

    def register_ws(self, scan_id: str, ws):
        if scan_id not in self._ws_connections:
            self._ws_connections[scan_id] = []
        self._ws_connections[scan_id].append(ws)

    def unregister_ws(self, scan_id: str, ws):
        if scan_id in self._ws_connections:
            try:
                self._ws_connections[scan_id].remove(ws)
            except ValueError:
                pass


# ─────────────────────── FastAPI 应用 ───────────────────────

def create_app(server: Optional[FPServer] = None) -> "FastAPI":
    """创建 FastAPI 应用"""
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    from fastapi.responses import HTMLResponse, JSONResponse
    from pydantic import BaseModel as PydanticBaseModel

    if server is None:
        server = FPServer()

    app = FastAPI(
        title="玄鉴 (XuanJian) 代码审计误报排查",
        description="面向安全研究团队的开源代码审计误报排查 MCP 工具",
        version="0.1.0",
    )

    # 静态文件 & 模板
    web_dir = Path(__file__).parent / "web"
    static_dir = web_dir / "static"
    template_dir = web_dir / "templates"

    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    templates = Jinja2Templates(directory=str(template_dir)) if template_dir.exists() else None

    # ─────── Pydantic 请求模型 ───────

    class ScanRequest(PydanticBaseModel):
        project_path: str
        language: str = "auto"
        scanners: Optional[List[str]] = None

    class MarkFPRequest(PydanticBaseModel):
        reason: str
        scope: str = "instance"

    # ─────── 页面路由 ───────

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        if templates:
            return templates.TemplateResponse("index.html", {
                "request": request,
                "title": "玄鉴 - 代码审计误报排查",
                "version": "0.1.0",
            })
        return HTMLResponse(_inline_dashboard_html())

    # ─────── API 路由 ───────

    @app.get("/api/projects")
    async def api_projects():
        return server.list_projects()

    @app.post("/api/scan")
    async def api_scan(req: ScanRequest):
        result = await server.scan_project(
            project_path=req.project_path,
            language=req.language,
            scanners=req.scanners,
        )
        return result

    @app.get("/api/findings")
    async def api_findings(
        scan_id: Optional[str] = None,
        verdict: Optional[str] = None,
        severity: Optional[str] = None,
    ):
        findings = server.list_findings(scan_id=scan_id, verdict=verdict, severity=severity)
        return [f.model_dump() for f in findings]

    @app.get("/api/findings/{finding_id}")
    async def api_finding_detail(finding_id: str):
        fr = server.get_finding(finding_id)
        if fr is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return fr.model_dump()

    @app.post("/api/findings/{finding_id}/mark-fp")
    async def api_mark_fp(finding_id: str, req: MarkFPRequest):
        ok = server.mark_false_positive(finding_id, req.reason, req.scope)
        if not ok:
            raise HTTPException(status_code=404, detail="Finding not found")
        return {"status": "ok"}

    @app.get("/api/stats")
    async def api_stats(project_path: Optional[str] = None):
        return server.get_statistics(project_path)

    @app.get("/api/scans/{scan_id}")
    async def api_scan_status(scan_id: str):
        scan = server._scans.get(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan

    # ─────── WebSocket ───────

    @app.websocket("/ws/scan/{scan_id}")
    async def ws_scan(websocket: WebSocket, scan_id: str):
        await websocket.accept()
        server.register_ws(scan_id, websocket)
        try:
            while True:
                data = await websocket.receive_text()
                # 心跳
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
        except WebSocketDisconnect:
            pass
        finally:
            server.unregister_ws(scan_id, websocket)

    # 把 server 存到 app 上方便外部访问
    app.state.fp_server = server

    return app


def create_server(config_path: Optional[str] = None) -> FPServer:
    """
    创建 FPServer 实例（兼容 test_example.py 的 create_server()）

    Args:
        config_path: 配置文件路径

    Returns:
        FPServer 实例
    """
    config = None
    if config_path:
        p = Path(config_path)
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                config = json.load(f)
    return FPServer(config=config)


# ─────────────────────── 内联仪表板 HTML ───────────────────────

def _inline_dashboard_html() -> str:
    """当 web/templates 不存在时返回内联 HTML"""
    return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>玄鉴 - 代码审计误报排查</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f1117;color:#e0e0e0;min-height:100vh}
.header{background:linear-gradient(135deg,#1a1f36,#0d1025);padding:20px 32px;border-bottom:1px solid #2a2f45;display:flex;align-items:center;justify-content:space-between}
.header h1{font-size:24px;background:linear-gradient(90deg,#60a5fa,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header .version{color:#666;font-size:13px}
.container{max-width:1200px;margin:0 auto;padding:24px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:#1a1f36;border:1px solid #2a2f45;border-radius:12px;padding:20px;text-align:center}
.stat-card .value{font-size:32px;font-weight:700;color:#60a5fa}
.stat-card .label{color:#888;font-size:13px;margin-top:4px}
.panel{background:#1a1f36;border:1px solid #2a2f45;border-radius:12px;padding:24px;margin-bottom:20px}
.panel h2{font-size:16px;color:#a78bfa;margin-bottom:16px}
.form-row{display:flex;gap:12px;margin-bottom:12px;align-items:center}
.form-row label{min-width:80px;color:#888;font-size:13px}
.form-row input,.form-row select{flex:1;padding:8px 12px;background:#0f1117;border:1px solid #2a2f45;border-radius:6px;color:#e0e0e0;font-size:14px}
button{padding:10px 24px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);border:none;border-radius:8px;color:#fff;font-size:14px;cursor:pointer;transition:opacity .2s}
button:hover{opacity:.85}
button:disabled{opacity:.4;cursor:not-allowed}
#scan-status{margin-top:12px;font-size:13px;color:#888}
.findings-table{width:100%;border-collapse:collapse;margin-top:12px}
.findings-table th,.findings-table td{padding:10px 12px;text-align:left;border-bottom:1px solid #2a2f45;font-size:13px}
.findings-table th{color:#888;font-weight:500}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.badge-critical{background:#dc2626;color:#fff}
.badge-high{background:#f97316;color:#fff}
.badge-medium{background:#eab308;color:#000}
.badge-low{background:#22c55e;color:#fff}
.badge-info{background:#3b82f6;color:#fff}
.badge-fp{background:#6b7280;color:#fff}
.badge-tp{background:#ef4444;color:#fff}
.badge-review{background:#8b5cf6;color:#fff}
.badge-lfp{background:#f59e0b;color:#000}
#findings-list{max-height:500px;overflow-y:auto}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>🔍 玄鉴 XuanJian</h1>
    <span class="version">v0.1.0 - 代码审计误报排查 MCP 工具</span>
  </div>
</div>
<div class="container">
  <div class="stats-grid" id="stats-grid">
    <div class="stat-card"><div class="value" id="s-total">-</div><div class="label">总发现</div></div>
    <div class="stat-card"><div class="value" id="s-fp" style="color:#6b7280">-</div><div class="label">误报</div></div>
    <div class="stat-card"><div class="value" id="s-tp" style="color:#ef4444">-</div><div class="label">真实问题</div></div>
    <div class="stat-card"><div class="value" id="s-review" style="color:#8b5cf6">-</div><div class="label">待复核</div></div>
    <div class="stat-card"><div class="value" id="s-rate" style="color:#22c55e">-</div><div class="label">减少率</div></div>
  </div>

  <div class="panel">
    <h2>🚀 启动扫描</h2>
    <div class="form-row">
      <label>项目路径</label>
      <input type="text" id="project-path" placeholder="/path/to/project" value="">
    </div>
    <div class="form-row">
      <label>语言</label>
      <select id="language">
        <option value="auto">自动检测</option>
        <option value="java">Java</option>
        <option value="python">Python</option>
        <option value="go">Go</option>
      </select>
    </div>
    <button id="btn-scan" onclick="startScan()">开始扫描</button>
    <div id="scan-status"></div>
  </div>

  <div class="panel">
    <h2>📋 发现列表</h2>
    <div id="findings-list">
      <table class="findings-table">
        <thead>
          <tr><th>严重程度</th><th>规则</th><th>文件</th><th>行</th><th>判定</th><th>置信度</th><th>操作</th></tr>
        </thead>
        <tbody id="findings-tbody"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
const API = '';
let currentScanId = null;

async function loadStats() {
  try {
    const r = await fetch(API + '/api/stats');
    const d = await r.json();
    document.getElementById('s-total').textContent = d.total_findings || 0;
    document.getElementById('s-fp').textContent = d.false_positives || 0;
    document.getElementById('s-tp').textContent = d.true_positives || 0;
    document.getElementById('s-review').textContent = d.needs_review || 0;
    document.getElementById('s-rate').textContent = d.reduction_rate || '0%';
  } catch(e) {}
}

async function startScan() {
  const path = document.getElementById('project-path').value.trim();
  if (!path) { alert('请输入项目路径'); return; }
  const lang = document.getElementById('language').value;
  const btn = document.getElementById('btn-scan');
  btn.disabled = true;
  document.getElementById('scan-status').textContent = '扫描中...';

  try {
    const r = await fetch(API + '/api/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({project_path: path, language: lang})
    });
    const d = await r.json();
    currentScanId = d.scan_id;
    document.getElementById('scan-status').textContent =
      `扫描完成！共 ${d.total_findings} 个发现，耗时 ${d.duration_seconds}s`;
    loadStats();
    loadFindings();
  } catch(e) {
    document.getElementById('scan-status').textContent = '扫描失败: ' + e.message;
  } finally {
    btn.disabled = false;
  }
}

async function loadFindings() {
  try {
    const url = currentScanId ? API + '/api/findings?scan_id=' + currentScanId : API + '/api/findings';
    const r = await fetch(url);
    const data = await r.json();
    const tbody = document.getElementById('findings-tbody');
    tbody.innerHTML = '';
    data.forEach(f => {
      const o = f.original;
      const sevBadge = `<span class="badge badge-${o.severity.toLowerCase()}">${o.severity}</span>`;
      const vp = f.verdict === 'false_positive' ? 'fp' : f.verdict === 'likely_false_positive' ? 'lfp' : f.verdict === 'true_positive' ? 'tp' : 'review';
      const vl = {false_positive:'误报',likely_false_positive:'疑似误报',true_positive:'真实问题',needs_review:'待复核'}[f.verdict] || f.verdict;
      const vBadge = `<span class="badge badge-${vp}">${vl}</span>`;
      tbody.innerHTML += `<tr>
        <td>${sevBadge}</td>
        <td>${o.rule_id}</td>
        <td><code>${o.file}:${o.line}</code></td>
        <td>${o.line}</td>
        <td>${vBadge}</td>
        <td>${(f.confidence*100).toFixed(0)}%</td>
        <td><button onclick="markFP('${f.id}')" style="padding:4px 10px;font-size:12px">标记误报</button></td>
      </tr>`;
    });
  } catch(e) {}
}

async function markFP(id) {
  const reason = prompt('请输入误报原因:');
  if (!reason) return;
  await fetch(API + '/api/findings/' + id + '/mark-fp', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({reason, scope: 'instance'})
  });
  loadStats();
  loadFindings();
}

loadStats();
</script>
</body>
</html>"""


# ─────────────────────── 入口 ───────────────────────

# 向后兼容别名
FPSentinelServer = FPServer


async def run_server(host: str = "0.0.0.0", port: int = 8080, **kwargs):
    """启动 Web 服务器"""
    import uvicorn
    app = create_app()
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    srv = uvicorn.Server(config)
    await srv.serve()
