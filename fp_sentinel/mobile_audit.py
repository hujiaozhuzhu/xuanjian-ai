#!/usr/bin/env python3
"""Mobile CLI —— fp-sentinel mobile audit"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional

from fp_sentinel.mobile_common import configure_logging
from fp_sentinel.mobile_reporting import generate_report

logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fp-sentinel mobile audit",
        description="移动端一体化审计: insight -> 报告",
    )
    parser.add_argument("target", help="APK / IPA / 反编译源码目录")
    parser.add_argument("--output", default="./reports/mobile/")
    parser.add_argument("--format", default="excel,word,html")
    parser.add_argument("--category")
    parser.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    parser.add_argument("--cvss", action="store_true")
    return parser


def main(argv=None) -> int:
    configure_logging()
    args = _build_parser().parse_args(argv)

    from fp_sentinel.mobile_insight.cli import build_context
    from fp_sentinel.mobile_insight.core.engine import InsightEngine
    from fp_sentinel.mobile_insight.models.insight import InsightCategory
    from fp_sentinel.mobile_insight.core.priority import filter_insights

    try:
        ctx = build_context(args.target)
    except FileNotFoundError:
        logger.error("目标不存在: %s", args.target)
        return 2

    engine = InsightEngine()
    report = engine.run(ctx, target=args.target)

    if args.category:
        categories = [InsightCategory.parse(c.strip()) for c in args.category.split(",")]
        report.insights = [i for i in report.insights if i.category in categories]

    from fp_sentinel.mobile_reporting.core.data_collector import DataCollector

    collector = DataCollector()
    out = collector.from_scan_outputs(insight_json=report.to_dict())

    if args.cvss:
        from fp_sentinel.mobile_reporting.cvss import auto_score

        for f in out.findings:
            auto_score(f)

    formats = [x.strip() for x in args.format.split(",") if x.strip()]
    generated = generate_report(out, args.output, formats=formats)
    for fmt, path in generated.items():
        logger.info("%s: %s", fmt.upper(), path)
    return 0


try:
    import typer

    mobile_audit_app = typer.Typer(help="移动端一体化审计", no_args_is_help=True)

    @mobile_audit_app.callback(invoke_without_command=True)
    def _audit_main(
        ctx: typer.Context,
        target: str = typer.Argument(..., help="APK/IPA"),
        output: str = typer.Option("./reports/mobile/", "--output"),
        format: str = typer.Option("excel,word,html", "--format"),
    ) -> None:
        if ctx.invoked_subcommand is None:
            raise typer.Exit(main([target, "--output", output, "--format", format]))

except ImportError:
    mobile_audit_app = None


if __name__ == "__main__":
    sys.exit(main())
