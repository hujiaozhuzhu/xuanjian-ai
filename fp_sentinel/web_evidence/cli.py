"""Web 证据适配器 CLI 入口。

提供 ``fpSentinel web-evidence`` 子命令，支持从多种来源构建报告或仅验证输入文件。

典型用法::

    # 从多种来源构建 HTML 报告
    python -m fp_sentinel.web_evidence.cli build \\
        --target example.com \\
        --burp burp_issues.json \\
        --nuclei nuclei_results.json \\
        --format html \\
        --output-dir reports/out

    # 仅验证文件格式
    python -m fp_sentinel.web_evidence.cli validate --burp burp_issues.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Optional

from .adapters import (
    burp_alert_to_finding,
    nuclei_result_to_finding,
    zap_alert_to_finding,
)
from .report_builder import WebEvidenceReportBuilder

__all__ = ["main"]

logger = logging.getLogger(__name__)

SUPPORTED_FORMATS = ("excel", "word", "html")
VALIDATION_PREVIEW_LIMIT = 5
LARGE_FILE_THRESHOLD_BYTES = 50 * 1024 * 1024  # 50 MB


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fp_sentinel.web_evidence",
        description="玄鉴AI Web 漏洞证据 → 报告适配器",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── build 子命令 ──
    build_parser = subparsers.add_parser(
        "build",
        help="从多种证据来源构建报告",
    )
    build_parser.add_argument("--target", default="", help="目标应用/站点名称")
    build_parser.add_argument("--burp", help="Burp Suite JSON 导出路径")
    build_parser.add_argument("--nuclei", help="Nuclei JSON 结果路径")
    build_parser.add_argument("--zap", help="OWASP ZAP JSON 报告路径")
    build_parser.add_argument("--csv", help="手工录入 CSV 文件路径")
    build_parser.add_argument(
        "--format",
        default="excel,word,html",
        help="输出格式，逗号分隔（默认 excel,word,html）",
    )
    build_parser.add_argument(
        "--output-dir", required=True, help="输出目录（须在白名单内）"
    )
    build_parser.add_argument("--verbose", action="store_true", help="输出调试日志")

    # ── validate 子命令 ──
    validate_parser = subparsers.add_parser(
        "validate",
        help="验证证据源文件格式并显示前 N 条样本",
    )
    validate_parser.add_argument("--burp", help="Burp Suite JSON 导出路径")
    validate_parser.add_argument("--nuclei", help="Nuclei JSON 结果路径")
    validate_parser.add_argument("--zap", help="OWASP ZAP JSON 报告路径")
    validate_parser.add_argument("--csv", help="CSV 文件路径")
    validate_parser.add_argument("--verbose", action="store_true")
    return parser


def _check_file_size(path: Path) -> None:
    """对超过阈值的文件给出 warning。"""
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size > LARGE_FILE_THRESHOLD_BYTES:
        logger.warning(
            "文件较大 (%d MB)，解析可能需要较长时间: %s",
            size // (1024 * 1024),
            path,
        )


def _validate_burp(path: Path) -> bool:
    """验证 Burp JSON 可解析并预览前 5 条。"""
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, PermissionError, UnicodeDecodeError) as exc:
        logger.error("Burp 文件读取失败: %s (%s)", path, exc)
        return False

    issues: list = []
    if isinstance(data, list):
        issues = data
    elif isinstance(data, dict):
        issues = data.get("issues") or [data]
    else:
        logger.error("Burp JSON 格式不支持: %s", type(data).__name__)
        return False

    preview_count = 0
    success_count = 0
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        finding = burp_alert_to_finding(issue)
        if finding:
            success_count += 1
            if preview_count < VALIDATION_PREVIEW_LIMIT:
                logger.info(
                    "  预览 #%d: [%s] %s | CWE=%s | URL=%s",
                    preview_count + 1,
                    finding.severity,
                    finding.title,
                    finding.cwe_id or "-",
                    finding.evidence[0].location if finding.evidence else "-",
                )
                preview_count += 1
    logger.info("Burp 文件验证完成: %d/%d 条解析成功", success_count, len(issues))
    return success_count > 0 or len(issues) == 0


def _validate_nuclei(path: Path) -> bool:
    """验证 Nuclei JSON 可解析并预览前 5 条。"""
    try:
        with path.open("r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except (FileNotFoundError, PermissionError, UnicodeDecodeError) as exc:
        logger.error("Nuclei 文件读取失败: %s (%s)", path, exc)
        return False

    success_count = 0
    preview_count = 0
    for line_no, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            result = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.warning("Nuclei 行 %d 解析失败: %s", line_no, exc)
            continue
        finding = nuclei_result_to_finding(result)
        if finding:
            success_count += 1
            if preview_count < VALIDATION_PREVIEW_LIMIT:
                logger.info(
                    "  预览 #%d: [%s] %s | CWE=%s | URL=%s",
                    preview_count + 1,
                    finding.severity,
                    finding.title,
                    finding.cwe_id or "-",
                    finding.evidence[0].location if finding.evidence else "-",
                )
                preview_count += 1
    logger.info("Nuclei 文件验证完成: %d 条解析成功", success_count)
    return success_count > 0


def _validate_zap(path: Path) -> bool:
    """验证 ZAP JSON 可解析并预览前 5 条。"""
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, PermissionError, UnicodeDecodeError) as exc:
        logger.error("ZAP 文件读取失败: %s (%s)", path, exc)
        return False

    alerts: list = []
    if isinstance(data, dict):
        sites = data.get("site") or []
        if isinstance(sites, dict):
            sites = [sites]
        for site in sites:
            if isinstance(site, dict):
                site_alerts = site.get("alerts") or []
                if isinstance(site_alerts, list):
                    alerts.extend(site_alerts)
    elif isinstance(data, list):
        alerts = data
    else:
        logger.error("ZAP JSON 格式不支持: %s", type(data).__name__)
        return False

    preview_count = 0
    success_count = 0
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        finding = zap_alert_to_finding(alert)
        if finding:
            success_count += 1
            if preview_count < VALIDATION_PREVIEW_LIMIT:
                logger.info(
                    "  预览 #%d: [%s] %s | CWE=%s | URL=%s",
                    preview_count + 1,
                    finding.severity,
                    finding.title,
                    finding.cwe_id or "-",
                    finding.evidence[0].location if finding.evidence else "-",
                )
                preview_count += 1
    logger.info("ZAP 文件验证完成: %d/%d 条解析成功", success_count, len(alerts))
    return success_count > 0 or len(alerts) == 0


def _validate_csv(path: Path) -> bool:
    """验证 CSV 可解析并预览前 5 条。"""
    import csv

    try:
        with path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
    except (FileNotFoundError, PermissionError, UnicodeDecodeError) as exc:
        logger.error("CSV 文件读取失败: %s (%s)", path, exc)
        return False

    preview_count = 0
    for row_no, row in enumerate(rows, start=2):
        logger.info(
            "  预览行 %d: [%s] %s | CWE=%s",
            row_no,
            row.get("severity", "-"),
            row.get("title", "-")[:60],
            row.get("cwe_id", "-"),
        )
        preview_count += 1
        if preview_count >= VALIDATION_PREVIEW_LIMIT:
            break
    logger.info("CSV 文件验证完成: 共 %d 行", len(rows))
    return True


def _cmd_validate(args: argparse.Namespace) -> int:
    """执行 validate 子命令。"""
    targets = []
    if args.burp:
        targets.append(("Burp", args.burp, _validate_burp))
    if args.nuclei:
        targets.append(("Nuclei", args.nuclei, _validate_nuclei))
    if args.zap:
        targets.append(("ZAP", args.zap, _validate_zap))
    if args.csv:
        targets.append(("CSV", args.csv, _validate_csv))

    if not targets:
        logger.error("请指定至少一个输入文件（--burp / --nuclei / --zap / --csv）")
        return 1

    all_ok = True
    for label, path_str, validator in targets:
        path = Path(path_str)
        logger.info("── 验证 %s: %s", label, path)
        _check_file_size(path)
        if not validator(path):
            all_ok = False
            logger.error("%s 验证失败: %s", label, path)
    return 0 if all_ok else 1


def _cmd_build(args: argparse.Namespace) -> int:
    """执行 build 子命令。"""
    formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    unknown = [f for f in formats if f not in SUPPORTED_FORMATS]
    if unknown:
        logger.error(
            "不支持的报告格式: %s（可选: %s）",
            unknown,
            "/".join(SUPPORTED_FORMATS),
        )
        return 1

    builder = WebEvidenceReportBuilder()
    source_count = 0

    for label, path_str in [
        ("Burp", args.burp),
        ("Nuclei", args.nuclei),
        ("ZAP", args.zap),
        ("CSV", args.csv),
    ]:
        if not path_str:
            continue
        path = Path(path_str)
        _check_file_size(path)
        if not path.exists():
            logger.error("文件不存在: %s", path)
            return 1
        if label == "Burp":
            builder.add_from_burp_json(path)
        elif label == "Nuclei":
            builder.add_from_nuclei_json(path)
        elif label == "ZAP":
            builder.add_from_zap_json(path)
        elif label == "CSV":
            builder.add_from_csv(path)
        source_count += 1

    if source_count == 0:
        logger.error("请指定至少一个输入来源（--burp / --nuclei / --zap / --csv）")
        return 1

    # 打印汇总统计
    total = len(builder._findings)
    logger.info("共收集 %d 条 finding", total)
    if builder._sources:
        for src, cnt in builder._sources.items():
            logger.info("  - %s: %d 条", src, cnt)

    if total == 0:
        logger.warning("未收集到任何有效的 finding，报告将为空。")

    try:
        generated = builder.generate(
            args.output_dir,
            formats=formats,
            target_app_name=args.target,
            scan_command=" ".join(sys.argv[1:]),
        )
    except (
        ValueError, RuntimeError, PermissionError, OSError, TypeError,
    ) as exc:
        logger.error("报告生成失败: %s", exc)
        return 1

    for fmt, out_path in generated.items():
        logger.info("已生成 %s 报告: %s", fmt.upper(), out_path)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """CLI 主入口。"""
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if args.command == "build":
        return _cmd_build(args)
    if args.command == "validate":
        return _cmd_validate(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
