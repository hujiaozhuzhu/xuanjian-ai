#!/usr/bin/env python3
"""Web CLI —— fp-sentinel web-audit discover|full

端到端 pipeline:
    discover:  HAR/Burp/Nuclei/JS/text → 端点 JSON
    full:     证据聚合 → CVSS → Excel/Word/HTML 报告
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, List, Optional

from fp_sentinel.mobile_common import configure_logging

logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fp-sentinel web-audit",
        description="Web 一体化审计: API 发现 → 证据聚合 → 报告生成",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_disc = sub.add_parser("discover", help="API 端点发现(HAR/Burp/Nuclei/JS)")
    p_disc.add_argument("--har")
    p_disc.add_argument("--burp")
    p_disc.add_argument("--nuclei")
    p_disc.add_argument("--js")
    p_disc.add_argument("--text")
    p_disc.add_argument("--output", required=True)

    p_full = sub.add_parser("full", help="全链路 Web 审计")
    p_full.add_argument("--url", required=True)
    p_full.add_argument("--burp")
    p_full.add_argument("--nuclei")
    p_full.add_argument("--zap")
    p_full.add_argument("--js")
    p_full.add_argument("--output", default="./reports/web/")
    p_full.add_argument("--format", default="excel,word,html")
    p_full.add_argument("--cvss", action="store_true")
    p_full.add_argument("--verify", action="store_true")

    return parser


def _discover(args: argparse.Namespace) -> int:
    from fp_sentinel.web_api.api_discovery import ApiDiscovery

    discovery = ApiDiscovery()
    endpoints = []
    if args.har:
        endpoints.extend(discovery.from_har(args.har))
    if args.burp:
        endpoints.extend(discovery.from_burp(args.burp))
    if args.nuclei:
        endpoints.extend(discovery.from_nuclei_json(args.nuclei))
    if args.js:
        endpoints.extend(discovery.from_js(args.js))
    if args.text:
        endpoints.extend(discovery.from_text(args.text))

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "total": len(endpoints),
        "endpoints": [
            {"url": e.url, "method": e.method, "source": e.source, "sensitivity": e.sensitivity}
            for e in endpoints
        ],
    }
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("发现 %d 个端点 -> %s", len(endpoints), out_path)
    return 0


def _full(args: argparse.Namespace) -> int:
    from fp_sentinel.web_evidence.report_builder import WebEvidenceReportBuilder

    builder = WebEvidenceReportBuilder()
    if args.burp:
        builder.add_from_burp_json(Path(args.burp))
    if args.nuclei:
        builder.add_from_nuclei_json(Path(args.nuclei))
    if args.zap:
        builder.add_from_nuclei_json(Path(args.zap))
    report = builder.build(target=args.url)

    # ── JS 预处理后处理: 将 JsPrettier.process() 结果 dump 到输出目录 ──
    if args.js:
        try:
            _run_js_pretreat(args.js, args.output)
        except Exception as exc:
            logger.warning("JS pretreat post-processing failed: %s", exc)

    # ── CVSS 评分 ──
    if args.cvss:
        from fp_sentinel.mobile_reporting.cvss import auto_score

        for finding in report.findings:
            auto_score(finding)

    # ── 自动验证 ──
    if args.verify:
        try:
            _run_verification(report, args.output)
        except Exception as exc:
            logger.warning("Verification failed: %s", exc)

    # ── 报告生成 ──
    from fp_sentinel.mobile_reporting import generate_report

    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    generated = generate_report(report, args.output, formats=formats)
    for fmt, path in generated.items():
        logger.info("%s: %s", fmt.upper(), path)
    return 0


def _run_js_pretreat(js_path: str, output_dir: str) -> None:
    """对 JS 文件运行 JsPrettier 预处理并 dump 结果到 <output>/js_prettify/。"""
    from fp_sentinel.web_pretreat.js_pretreat import JsPrettier

    js_dir = Path(js_path)
    if not js_dir.exists():
        logger.warning("JS path not found: %s", js_path)
        return

    out_base = Path(output_dir) / "js_prettify"
    out_base.mkdir(parents=True, exist_ok=True)

    extensions = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    skip_dirs = {"node_modules", ".git", "dist", "build"}

    prettier = JsPrettier()
    processed = 0

    files = (
        f for f in js_dir.rglob("*")
        if f.suffix.lower() in extensions and f.is_file()
        and not any(skip in f.parts for skip in skip_dirs)
    )

    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            result = prettier.process(content)
            rel = f.relative_to(js_dir)
            out_file = out_base / f"{rel}.json"
            out_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "file": str(rel),
                "packer_type": result.packer_type,
                "used_beautifier": result.used_beautifier,
                "warnings": [{"category": w.category, "message": w.message} for w in result.warnings],
                "strings_count": len(result.strings),
                "apis_count": len(result.apis),
                "suspicious_count": len(result.suspicious),
                "console_outputs_count": len(result.console_outputs),
                "suspicious": result.suspicious[:20],
                "console_outputs": result.console_outputs[:20],
                "apis": result.apis[:10],
            }
            out_file.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            processed += 1
        except Exception as exc:
            logger.warning("Failed to pretreat %s: %s", f, exc)

    logger.info("JS pretreat post-processing: %d files processed -> %s", processed, out_base)


def _run_verification(report: Any, output_dir: str) -> None:
    """对每条 finding 运行 HarmlessVerifier 验证并生成 verification_report.json。"""
    from fp_sentinel.attack.harmless_verifier import HarmlessVerifier

    findings = getattr(report, "findings", [])
    if not findings:
        logger.info("No findings to verify")
        return

    verifier = HarmlessVerifier()
    ver_report = verifier.verify_findings(findings)

    out_path = Path(output_dir) / "verification_report.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "summary": ver_report.summary(),
        "results": [r.to_dict() for r in ver_report.results],
    }
    out_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    logger.info("Verification report -> %s", out_path)


def main(argv: Optional[List[str]] = None) -> int:
    configure_logging()
    args = _build_parser().parse_args(argv)
    if args.command == "discover":
        return _discover(args)
    if args.command == "full":
        return _full(args)
    return 1


try:
    import typer

    web_audit_app = typer.Typer(help="Web 一体化审计 (发现->证据->报告)", no_args_is_help=True)

    @web_audit_app.command("discover")
    def _discover_cmd(
        output: str = typer.Option(..., "--output"),
        har: Optional[str] = typer.Option(None, "--har"),
        burp: Optional[str] = typer.Option(None, "--burp"),
        nuclei: Optional[str] = typer.Option(None, "--nuclei"),
        js: Optional[str] = typer.Option(None, "--js"),
        text: Optional[str] = typer.Option(None, "--text"),
    ) -> None:
        argv = ["discover", "--output", output]
        if har:
            argv += ["--har", har]
        if burp:
            argv += ["--burp", burp]
        if nuclei:
            argv += ["--nuclei", nuclei]
        if js:
            argv += ["--js", js]
        if text:
            argv += ["--text", text]
        raise typer.Exit(main(argv))

    @web_audit_app.command("full")
    def _full_cmd(
        url: str = typer.Option(..., "--url"),
        output: str = typer.Option("./reports/web/", "--output"),
        format: str = typer.Option("excel,word,html", "--format"),
        burp: Optional[str] = typer.Option(None, "--burp"),
        nuclei: Optional[str] = typer.Option(None, "--nuclei"),
        zap: Optional[str] = typer.Option(None, "--zap"),
        js: Optional[str] = typer.Option(None, "--js"),
        cvss: bool = typer.Option(False, "--cvss"),
        verify: bool = typer.Option(False, "--verify"),
    ) -> None:
        argv = ["full", "--url", url, "--output", output, "--format", format]
        if burp:
            argv += ["--burp", burp]
        if nuclei:
            argv += ["--nuclei", nuclei]
        if zap:
            argv += ["--zap", zap]
        if js:
            argv += ["--js", js]
        if cvss:
            argv.append("--cvss")
        if verify:
            argv.append("--verify")
        raise typer.Exit(main(argv))

except ImportError:  # pragma: no cover
    web_audit_app = None  # type: ignore[assignment]


if __name__ == "__main__":
    sys.exit(main())
