"""移动端报告系统命令行入口。

用法示例::

    # 用 InsecureBankv2 示例数据生成三种格式报告
    python -m fp_sentinel.mobile_reporting.cli --sample --output reports/out

    # 从扫描 JSON 产物生成 HTML 报告
    python -m fp_sentinel.mobile_reporting.cli \\
        --format html --output reports/out \\
        --insight scan_result.json --apk test_apps/InsecureBankv2.apk
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

from . import generate_report

logger = logging.getLogger(__name__)

SUPPORTED_FORMATS = ("excel", "word", "html")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fp_sentinel.mobile_reporting",
        description="玄鉴 v4.0 移动安全审计报告生成器（Excel/Word/HTML）",
    )
    parser.add_argument(
        "--format",
        default="excel,word,html",
        help="报告格式，逗号分隔（默认 excel,word,html）",
    )
    parser.add_argument("--output", required=True, help="输出目录（S7 白名单内）")
    parser.add_argument("--sample", action="store_true", help="使用 InsecureBankv2 示例数据")
    parser.add_argument("--insight", help="mobile_insight 扫描结果 JSON 路径")
    parser.add_argument("--hook", help="mobile_hook 扫描结果 JSON 路径")
    parser.add_argument("--poc", help="mobile_poc 生成结果 JSON 路径")
    parser.add_argument("--apk", help="目标 APK 路径（用于环境信息采集）")
    parser.add_argument("--verbose", action="store_true", help="输出调试日志")
    return parser


def _build_report(args: argparse.Namespace) -> object:
    """根据命令行参数构建报告数据。"""
    if args.sample:
        from .formats._fallback_models import create_insecurebank_sample_report

        return create_insecurebank_sample_report()

    from .core.data_collector import DataCollector
    from .core.reproducibility import ReproducibilityManager

    insight = _load_json(Path(args.insight)) if args.insight else None
    hook = _load_json(Path(args.hook)) if args.hook else None
    poc = _load_json(Path(args.poc)) if args.poc else None
    apk_path = Path(args.apk) if args.apk else None

    collector = DataCollector()
    report = collector.from_scan_outputs(
        insight_json=insight, hook_json=hook, poc_json=poc
    )
    if apk_path is not None:
        manager = ReproducibilityManager()
        env = manager.capture_environment(
            target_path=str(apk_path), scan_command=" ".join(sys.argv[1:])
        )
        report.environment = env
    return report


def _load_json(path: Path) -> object:
    import json

    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    try:
        report = _build_report(args)
        formats = [f.strip() for f in args.format.split(",") if f.strip()]
        if not formats:
            logger.error(
                "--format 解析结果为空，请传入 excel/word/html 的逗号组合，"
                "例如 --format html"
            )
            return 1
        generated = generate_report(report, args.output, formats=formats)
    except (ValueError, RuntimeError, PermissionError, OSError, TypeError) as exc:
        logger.error("报告生成失败: %s", exc)
        return 1

    for fmt, path in generated.items():
        logger.info("已生成 %s 报告: %s", fmt.upper(), path)
    logger.info("\n".join(f"{fmt.upper()}: {path}" for fmt, path in generated.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
