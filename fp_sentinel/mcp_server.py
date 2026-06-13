"""
MCP 服务器（FastMCP 装饰器模式）

8 个 MCP 工具：
1. scan_project        - 扫描项目
2. triage_findings     - 分诊发现（应用三层过滤）
3. explain_finding     - 解释单条发现
4. mark_false_positive - 标记误报
5. list_findings       - 列出发现
6. export_report       - 导出报告
7. get_statistics      - 获取统计
8. list_projects       - 列出项目
"""

import asyncio
import json
import logging
from typing import List, Optional, Dict, Any

from mcp.server.fastmcp import FastMCP

from .models import (
    ScanResult, FilterResult, FilterResponse, FilterStatistics,
    Verdict, ScanTool, Severity, Finding,
    scan_result_to_finding,
)
from .filters import RuleFilter, ContextFilter, BaselineFilter
from .scanners.manager import ScannerManager


logger = logging.getLogger(__name__)


# ─────────────────────── MCP 服务器封装 ───────────────────────


class MCPAuditServer:
    """
    玄鉴 MCP 服务器

    使用 FastMCP 装饰器注册 8 个工具，对外暴露 self.mcp 供 stdio/SSE 运行。
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.logger = logging.getLogger("xuanjian_mcp")

        # 过滤器
        self.rule_filter = RuleFilter(self.config.get("rule_filter", {}))
        self.context_filter = ContextFilter(self.config.get("context_filter", {}))
        self.ml_filter = BaselineFilter(self.config.get("ml_filter", {}))

        # 扫描器管理器
        self.scanner_manager = ScannerManager(self.config.get("scanners", {}))

        # 运行时存储
        self._scans: Dict[str, Dict[str, Any]] = {}
        self._findings: Dict[str, FilterResult] = {}

        # FastMCP 实例
        self.mcp = FastMCP("xuanjian-code-audit")
        self._register_tools()

    @staticmethod
    def _default_config() -> Dict[str, Any]:
        return {
            "rule_filter": {"enabled": True},
            "context_filter": {"enabled": True, "false_positive_threshold": 0.5},
            "ml_filter": {"enabled": True, "confidence_threshold": 0.7},
            "scanners": {},
        }

    # ─────── 工具注册 ───────

    def _register_tools(self):
        """使用 FastMCP @mcp.tool() 装饰器注册 8 个工具"""
        server = self

        # ── 1. scan_project ──
        @self.mcp.tool()
        async def scan_project(
            project_path: str,
            language: str = "auto",
            scanners: Optional[List[str]] = None,
        ) -> str:
            """
            扫描项目，发现安全问题。

            Args:
                project_path: 项目路径
                language: 编程语言 (auto/java/python/go)
                scanners: 指定扫描器列表 (semgrep/bandit/findsecbugs)

            Returns:
                JSON 格式的扫描结果（含 scan_id、统计信息）
            """
            import uuid, time
            from datetime import datetime

            scan_id = str(uuid.uuid4())
            start = time.monotonic()

            scan_tools = None
            if scanners:
                scan_tools = []
                for s in scanners:
                    try:
                        scan_tools.append(ScanTool(s))
                    except ValueError:
                        pass

            server._scans[scan_id] = {
                "id": scan_id,
                "project_path": project_path,
                "language": language,
                "status": "running",
                "started_at": datetime.utcnow().isoformat(),
            }

            try:
                raw = await server.scanner_manager.scan(
                    project_path, language=language, scanners=scan_tools
                )

                filtered: List[FilterResult] = []
                for i, sr in enumerate(raw):
                    fr = await server._apply_filters(sr)
                    fid = sr.id or f"{scan_id}:{i}"
                    fr.id = fid
                    server._findings[fid] = fr
                    filtered.append(fr)

                stats = server._calculate_statistics(filtered)
                elapsed = time.monotonic() - start

                server._scans[scan_id].update({
                    "status": "completed",
                    "completed_at": datetime.utcnow().isoformat(),
                    "findings": [fr.id for fr in filtered],
                    "stats": stats.model_dump(),
                })

                return json.dumps({
                    "scan_id": scan_id,
                    "total_findings": len(raw),
                    "statistics": stats.model_dump(),
                    "duration_seconds": round(elapsed, 2),
                }, ensure_ascii=False, indent=2)

            except Exception as e:
                server._scans[scan_id]["status"] = "failed"
                server.logger.error(f"扫描失败: {e}")
                return json.dumps({"error": str(e), "scan_id": scan_id}, ensure_ascii=False)

        # ── 2. triage_findings ──
        @self.mcp.tool()
        async def triage_findings(
            scan_id: str,
            use_rule_filter: bool = True,
            use_context_filter: bool = True,
            use_baseline: bool = True,
        ) -> str:
            """
            对扫描结果进行分诊，应用三层过滤器识别误报。

            Args:
                scan_id: 扫描 ID
                use_rule_filter: 启用 L1 规则过滤
                use_context_filter: 启用 L2 上下文分析
                use_baseline: 启用 L3 历史基线

            Returns:
                JSON 格式的分诊结果列表
            """
            scan = server._scans.get(scan_id)
            if not scan:
                return json.dumps({"error": f"扫描 {scan_id} 不存在"}, ensure_ascii=False)

            level = "all"
            if not use_baseline:
                level = "L2" if use_context_filter else "L1"
            elif not use_context_filter:
                level = "L3" if use_baseline else "L1"

            findings_ids = scan.get("findings", [])
            results = []
            for fid in findings_ids:
                fr = server._findings.get(fid)
                if fr:
                    # 重新应用过滤
                    new_fr = await server._apply_filters(fr.original, filter_level=level)
                    new_fr.id = fid
                    server._findings[fid] = new_fr
                    results.append(new_fr.model_dump())

            stats = server._calculate_statistics(
                [server._findings[fid] for fid in findings_ids if fid in server._findings]
            )

            return json.dumps({
                "scan_id": scan_id,
                "filter_level": level,
                "results": results,
                "statistics": stats.model_dump(),
            }, ensure_ascii=False, indent=2, default=str)

        # ── 3. explain_finding ──
        @self.mcp.tool()
        async def explain_finding(finding_id: str) -> str:
            """
            解释单条发现，提供详细分析和处理建议。

            Args:
                finding_id: 发现 ID

            Returns:
                JSON 格式的发现详情与解释
            """
            fr = server._findings.get(finding_id)
            if fr is None:
                return json.dumps({"error": f"发现 {finding_id} 不存在"}, ensure_ascii=False)

            o = fr.original
            explanation = {
                "finding_id": finding_id,
                "rule_id": o.rule_id,
                "severity": o.severity.value,
                "file": o.file,
                "line": o.line,
                "code": o.code,
                "message": o.message,
                "cwe": o.cwe,
                "owasp": o.owasp,
                "verdict": fr.verdict.value,
                "confidence": fr.confidence,
                "risk_score": fr.risk_score,
                "recommendation": fr.recommendation,
                "filter_reasons": [r.model_dump() for r in fr.filter_reasons],
                "context_analysis": fr.context_analysis,
                "java_analysis": fr.java_analysis,
                "explanation": _generate_explanation(fr),
            }
            return json.dumps(explanation, ensure_ascii=False, indent=2, default=str)

        # ── 4. mark_false_positive ──
        @self.mcp.tool()
        async def mark_false_positive(
            finding_id: str,
            reason: str,
            scope: str = "instance",
        ) -> str:
            """
            将发现标记为误报，并写入基线。

            Args:
                finding_id: 发现 ID
                reason: 标记原因
                scope: 作用域 (instance/rule/global)

            Returns:
                JSON 格式的操作结果
            """
            fr = server._findings.get(finding_id)
            if fr is None:
                return json.dumps({"error": f"发现 {finding_id} 不存在"}, ensure_ascii=False)

            fr.verdict = Verdict.FALSE_POSITIVE
            fr.recommendation = f"手动标记为误报: {reason}"

            # 写入基线
            fp = server.ml_filter.add_to_baseline(
                fr.original, verdict="false_positive", confidence=1.0, reason=reason
            )

            return json.dumps({
                "status": "ok",
                "finding_id": finding_id,
                "fingerprint": fp,
                "scope": scope,
                "reason": reason,
            }, ensure_ascii=False)

        # ── 5. list_findings ──
        @self.mcp.tool()
        async def list_findings(
            scan_id: str,
            verdict: Optional[str] = None,
            severity: Optional[str] = None,
        ) -> str:
            """
            列出扫描发现。

            Args:
                scan_id: 扫描 ID
                verdict: 过滤判定 (false_positive/true_positive/needs_review/likely_false_positive)
                severity: 过滤严重程度 (CRITICAL/HIGH/MEDIUM/LOW/INFO)

            Returns:
                JSON 格式的发现列表
            """
            scan = server._scans.get(scan_id)
            if not scan:
                return json.dumps({"error": f"扫描 {scan_id} 不存在"}, ensure_ascii=False)

            findings = []
            for fid in scan.get("findings", []):
                fr = server._findings.get(fid)
                if fr is None:
                    continue
                if verdict and fr.verdict.value != verdict:
                    continue
                if severity and fr.original.severity.value != severity:
                    continue
                findings.append(fr.model_dump())

            return json.dumps({
                "scan_id": scan_id,
                "total": len(findings),
                "findings": findings,
            }, ensure_ascii=False, indent=2, default=str)

        # ── 6. export_report ──
        @self.mcp.tool()
        async def export_report(
            scan_id: str,
            format: str = "json",
        ) -> str:
            """
            导出扫描报告。

            Args:
                scan_id: 扫描 ID
                format: 报告格式 (json/markdown)

            Returns:
                报告内容字符串
            """
            scan = server._scans.get(scan_id)
            if not scan:
                return json.dumps({"error": f"扫描 {scan_id} 不存在"}, ensure_ascii=False)

            findings = [
                server._findings[fid]
                for fid in scan.get("findings", [])
                if fid in server._findings
            ]
            stats = server._calculate_statistics(findings)

            report = {
                "scan_id": scan_id,
                "project_path": scan.get("project_path"),
                "language": scan.get("language"),
                "completed_at": scan.get("completed_at"),
                "statistics": stats.model_dump(),
                "findings_count": len(findings),
            }

            if format == "json":
                report["findings"] = [f.model_dump() for f in findings]
                return json.dumps(report, ensure_ascii=False, indent=2, default=str)

            # markdown
            lines = [
                "# 玄鉴扫描报告", "",
                f"- **扫描ID**: `{scan_id}`",
                f"- **项目**: {scan.get('project_path')}",
                f"- **语言**: {scan.get('language')}",
                f"- **时间**: {scan.get('completed_at')}", "",
                "## 统计", "",
                f"| 指标 | 数值 |", f"|------|------|",
                f"| 总发现 | {stats.total} |",
                f"| 误报 | {stats.false_positives} |",
                f"| 疑似误报 | {stats.likely_false_positives} |",
                f"| 真实问题 | {stats.true_positives} |",
                f"| 待复核 | {stats.needs_review} |",
                f"| 减少率 | {stats.reduction_rate} |", "",
                "## 发现详情", "",
            ]
            for f in findings:
                o = f.original
                lines.append(f"### [{o.severity.value}] {o.rule_id}")
                lines.append(f"- 文件: `{o.file}:{o.line}`")
                lines.append(f"- 判定: {f.verdict.value} ({f.confidence:.0%})")
                lines.append(f"- 建议: {f.recommendation}")
                lines.append("")
            return "\n".join(lines)

        # ── 7. get_statistics ──
        @self.mcp.tool()
        async def get_statistics(project_path: Optional[str] = None) -> str:
            """
            获取项目统计信息。

            Args:
                project_path: 项目路径（可选）

            Returns:
                JSON 格式的统计信息
            """
            all_findings = list(server._findings.values())
            if project_path:
                all_findings = [
                    f for f in all_findings
                    if f.original.metadata.get("project_path") == project_path
                    or f.original.file.startswith(project_path)
                ]

            total = len(all_findings)
            fps = sum(1 for f in all_findings if f.verdict == Verdict.FALSE_POSITIVE)
            likely_fps = sum(1 for f in all_findings if f.verdict == Verdict.LIKELY_FALSE_POSITIVE)
            tps = sum(1 for f in all_findings if f.verdict == Verdict.TRUE_POSITIVE)
            needs_review = sum(1 for f in all_findings if f.verdict == Verdict.NEEDS_REVIEW)

            stats = {
                "project_path": project_path or "(all)",
                "total_findings": total,
                "false_positives": fps,
                "likely_false_positives": likely_fps,
                "true_positives": tps,
                "needs_review": needs_review,
                "reduction_rate": f"{((fps + likely_fps) / total * 100):.1f}%" if total else "0%",
                "baseline_size": server.ml_filter.get_baseline_count(),
                "scans_completed": len([
                    s for s in server._scans.values() if s.get("status") == "completed"
                ]),
            }
            return json.dumps(stats, ensure_ascii=False, indent=2)

        # ── 8. list_projects ──
        @self.mcp.tool()
        async def list_projects() -> str:
            """
            列出已扫描的项目。

            Returns:
                JSON 格式的项目列表
            """
            seen: Dict[str, Dict[str, Any]] = {}
            for sid, scan in server._scans.items():
                if scan.get("status") != "completed":
                    continue
                p = scan.get("project_path", "")
                if p not in seen:
                    seen[p] = {
                        "name": p.split("/")[-1] or p,
                        "path": p,
                        "language": scan.get("language", "auto"),
                        "scan_count": 0,
                        "last_scan": None,
                        "total_findings": 0,
                    }
                seen[p]["scan_count"] += 1
                seen[p]["last_scan"] = scan.get("completed_at")
                seen[p]["total_findings"] += scan.get("stats", {}).get("total", 0)

            return json.dumps(list(seen.values()), ensure_ascii=False, indent=2)

    # ─────── 过滤流水线 ───────

    async def _apply_filters(
        self,
        scan_result: ScanResult,
        filter_level: str = "all",
        confidence_threshold: float = 0.7,
    ) -> FilterResult:
        """应用三层过滤器"""
        current: Optional[FilterResult] = None

        if filter_level in ("L1", "all"):
            current = await self.rule_filter.filter(scan_result)
            if current.is_false_positive and current.confidence >= confidence_threshold:
                return current

        if filter_level in ("L2", "all"):
            l2 = await self.context_filter.filter(scan_result)
            if l2.is_false_positive and l2.confidence >= confidence_threshold:
                return l2
            if current is None or l2.confidence > current.confidence:
                current = l2

        if filter_level in ("L3", "all"):
            l3 = await self.ml_filter.filter(scan_result)
            if l3.is_false_positive and l3.confidence >= confidence_threshold:
                return l3
            if current is None:
                current = l3

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

        filtered_count = fps + likely_fps
        rate = f"{(filtered_count / total * 100):.1f}%" if total > 0 else "0%"

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

    async def run(self, transport: str = "stdio", port: int = 8000):
        """运行 MCP 服务器"""
        if transport == "stdio":
            await self.mcp.run_stdio_async()
        elif transport == "sse":
            await self.mcp.run_sse_async(host="0.0.0.0", port=port)
        else:
            raise ValueError(f"不支持的传输方式: {transport}")


# ─────────────────────── 辅助 ───────────────────────


def _generate_explanation(fr: FilterResult) -> str:
    """生成人类可读的解释"""
    o = fr.original
    parts = []

    parts.append(f"该发现在文件 {o.file} 第 {o.line} 行，由 {o.tool.value} 扫描器报告。")
    parts.append(f"规则 {o.rule_id} 触发：{o.message}")

    if o.cwe:
        parts.append(f"关联 CWE: {o.cwe}")
    if o.owasp:
        parts.append(f"OWASP 分类: {o.owasp}")

    parts.append(f"当前判定: {fr.verdict.value}，置信度 {fr.confidence:.0%}，风险评分 {fr.risk_score}/10")

    if fr.filter_reasons:
        reasons_str = "; ".join(
            f"[{r.filter_level}] {r.description}" for r in fr.filter_reasons
        )
        parts.append(f"过滤原因: {reasons_str}")

    parts.append(f"建议: {fr.recommendation}")
    return " ".join(parts)


# ─────────────────────── 工厂函数 ───────────────────────


def create_mcp_server(config: Optional[Dict[str, Any]] = None) -> MCPAuditServer:
    """创建 MCP 服务器实例"""
    return MCPAuditServer(config)


async def mcp_main():
    """MCP 服务器入口"""
    import argparse

    parser = argparse.ArgumentParser(description="玄鉴 MCP 代码审计服务器")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--config", type=str, default=None)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    config = None
    if args.config:
        from pathlib import Path
        p = Path(args.config)
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                config = json.load(f)

    server = create_mcp_server(config)
    await server.run(args.transport, args.port)


if __name__ == "__main__":
    asyncio.run(mcp_main())
