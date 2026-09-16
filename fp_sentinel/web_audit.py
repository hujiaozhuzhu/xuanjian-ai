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
from typing import List, Optional

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

    if args.cvss:
        from fp_sentinel.mobile_reporting.cvss import auto_score

        for finding in report.findings:
            auto_score(finding)

    from fp_sentinel.mobile_reporting import generate_report

    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    generated = generate_report(report, args.output, formats=formats)
    for fmt, path in generated.items():
        logger.info("%s: %s", fmt.upper(), path)
    return 0


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
        raise typer.Exit(main(argv))

except ImportError:  # pragma: no cover
    web_audit_app = None  # type: ignore[assignment]


if __name__ == "__main__":
    sys.exit(main())
