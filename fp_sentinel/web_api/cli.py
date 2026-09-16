"""Web API 安全审计 CLI（子命令 ``fp_sentinel web-api``）。

提供两个子命令：

- ``discover``：端点发现 + 分类，输出 JSON 与 CSV 准入清单。
- ``scan-privilege``：越权探测（要求 ``--i-have-authorization`` 确认旗标）。
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .api_discovery import ApiDiscovery
from .classifier import classify
from .endpoints_models import ApiEndpoint
from .privilege_scan import PrivilegeScanner, PrivilegeFinding
from .report import build_report

logger = logging.getLogger(__name__)

__all__ = ["main", "build_parser"]


def _setup_logging(verbose: bool = False) -> None:
    """配置日志格式与级别。

    Args:
        verbose: 是否开启 DEBUG 级别。
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ────────────────────────── 输出工具 ──────────────────────────


def _write_json(data: Any, output_path: Path) -> None:
    """将数据序列化为 JSON 文件。

    Args:
        data: 可 JSON 化的对象。
        output_path: 输出路径。
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("JSON 输出: %s", output_path)


def _write_csv(
    endpoints: List[ApiEndpoint],
    classifications: List[Dict[str, Any]],
    output_path: Path,
) -> None:
    """将端点准入清单写入 CSV。

    Args:
        endpoints: 端点列表。
        classifications: 分类结果列表。
        output_path: CSV 输出路径。
    """
    headers = [
        "method",
        "url",
        "path",
        "host",
        "status_code",
        "content_type",
        "response_size",
        "source",
        "category",
        "sensitivity",
        "reasons",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        for ep, cls in zip(endpoints, classifications):
            cls = cls or {}
            writer.writerow(
                [
                    ep.method,
                    ep.url,
                    ep.path,
                    ep.host or "",
                    ep.status_code or "",
                    ep.content_type,
                    ep.response_size,
                    ep.source,
                    cls.get("category", ""),
                    cls.get("sensitivity", ""),
                    "; ".join(cls.get("reasons", [])),
                ]
            )
    logger.info("CSV 准入清单: %s", output_path)


# ────────────────────────── 子命令实现 ──────────────────────────


def cmd_discover(args: argparse.Namespace) -> int:
    """执行端点发现与分类。

    Args:
        args: 已解析的命令行参数。

    Returns:
        int: 退出码。
    """
    all_endpoints: List[ApiEndpoint] = []
    if args.har:
        logger.info("从 HAR 解析端点: %s", args.har)
        all_endpoints.extend(ApiDiscovery.from_har(args.har))
    if args.burp:
        logger.info("从 Burp 解析端点: %s", args.burp)
        all_endpoints.extend(ApiDiscovery.from_burp(args.burp))
    if args.nuclei:
        logger.info("从 Nuclei 解析端点: %s", args.nuclei)
        all_endpoints.extend(ApiDiscovery.from_nuclei_json(args.nuclei))
    if args.js:
        logger.info("从 JS 文件提取端点: %d 个文件", len(args.js))
        all_endpoints.extend(ApiDiscovery.from_js(args.js))
    if args.text:
        logger.info("从文本提取端点")
        all_endpoints.extend(ApiDiscovery.from_text(args.text))
    logger.info("=========== 端点发现完成：共 %d 个唯一端点 ===========", len(all_endpoints))
    # 分类
    classifications: List[Dict[str, Any]] = [classify(ep) for ep in all_endpoints]
    high_count = sum(1 for c in classifications if c.get("sensitivity") == "high")
    logger.info("分类完成：高危敏感端点 %d 个", high_count)
    # 输出
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(
        [ep.to_dict() for ep in all_endpoints],
        output_dir / "endpoints.json",
    )
    _write_json(classifications, output_dir / "classifications.json")
    _write_csv(all_endpoints, classifications, output_dir / "endpoints_access_list.csv")
    # 生成聚合报告
    report = build_report(all_endpoints, classifications)
    _write_json(report.to_dict(), output_dir / "report.json")
    print(f"[discover] 完成，已读取 {len(all_endpoints)} 个端点 -> {output_dir.resolve()}")
    return 0


def cmd_scan_privilege(args: argparse.Namespace) -> int:
    """执行越权探测。

    Args:
        args: 已解析的命令行参数。

    Returns:
        int: 退出码。
    """
    if not args.i_have_authorization:
        logger.error(
            "未确认授权：越权探测请确认已获合法测试授权，"
            "并通过 --i-have-authorization 旗标显式确认。"
        )
        print(
            "[scan-privilege] 请添加 --i-have-authorization 确认已获授权后再运行。",
            file=sys.stderr,
        )
        return 2
    # 解析 cookie 参数
    cookies = _parse_cookies([args.cookie_a, args.cookie_b])
    if len(cookies) < 2:
        logger.error("水平越权需要至少两个 cookie")
        return 2
    low_cookie = args.low_cookie or args.cookie_b
    admin_cookie_val = args.admin_cookie or args.cookie_a
    # 端点基线（仅 path，需要 base_url 拼合）
    base_endpoints: List[ApiEndpoint] = []
    if args.endpoints_json:
        data = json.loads(Path(args.endpoints_json).read_text(encoding="utf-8"))
        if isinstance(data, list):
            base_endpoints = [ApiEndpoint(**item) for item in data if isinstance(item, dict)]
    for p in args.paths or []:
        base_endpoints.append(ApiEndpoint(method="GET", url="", path=p, host=""))
    logger.info("=========== 越权探测初始化 ===========")
    logger.info(
        "[scan-privilege] 越权探测仅对比响应，未提交任何写操作，"
        "只发送 GET/HEAD 且 rate_limit=%.1f req/s",
        args.rate_limit,
    )
    scanner = PrivilegeScanner(
        base_url=args.base_url,
        test_cookies=cookies,
        admin_cookie=admin_cookie_val,
        low_cookie=low_cookie,
        rate_limit=args.rate_limit,
    )
    horizontal_results: List[PrivilegeFinding] = []
    vertical_results: List[PrivilegeFinding] = []
    cookie_names = list(cookies.keys())
    if len(cookie_names) >= 2:
        horizontal_results = scanner.test_horizontal(
            base_endpoints,
            cookies[cookie_names[0]],
            cookies[cookie_names[1]],
        )
    if args.admin_cookie and args.low_cookie:
        vertical_results = scanner.test_vertical(
            admin_cookie_val,
            low_cookie,
            base_endpoints,
        )
    all_privilege = horizontal_results + vertical_results
    exposed_count = sum(1 for pf in all_privilege if pf.verdict == "exposed")
    logger.info(
        "[scan-privilege] 完成：水平 %d 项，垂直 %d 项，暴露 %d 项",
        len(horizontal_results),
        len(vertical_results),
        exposed_count,
    )
    # 输出
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(
        [
            {
                "method": pf.method,
                "url": pf.url,
                "type": pf.finding_type,
                "verdict": pf.verdict,
                "status_a": pf.status_a,
                "status_b": pf.status_b,
                "cwe_id": pf.cwe_id,
            }
            for pf in all_privilege
        ],
        output_dir / "privilege_findings.json",
    )
    report = build_report(base_endpoints, [], all_privilege)
    _write_json(report.to_dict(), output_dir / "privilege_report.json")
    print(
        f"[scan-privilege] 完成：水平 {len(horizontal_results)} 项，"
        f"垂直 {len(vertical_results)} 项，暴露 {exposed_count} 项 -> {output_dir.resolve()}"
    )
    return 1 if exposed_count > 0 else 0


# ────────────────────────── Cookie 解析 ──────────────────────────


def _parse_cookies(raw_list: List[str]) -> Dict[str, str]:
    """解析 ``name=value`` 格式的 cookie 字符串列表。

    Args:
        raw_list: cookie 字符串列表（形如 ``sessionid=abc``）。

    Returns:
        Dict[str, str]: cookie 名称到值的映射。
    """
    result: Dict[str, str] = {}
    for raw in raw_list:
        if not raw or "=" not in raw:
            continue
        name, _, value = raw.partition("=")
        result[name.strip()] = value.strip()
    return result


# ────────────────────────── 参数解析 ──────────────────────────


def build_parser(parser: argparse.ArgumentParser) -> None:
    """向主解析器注册 ``web-api`` 子命令。

    Args:
        parser: argparse 主解析器。
    """
    sub = parser.add_subparsers(dest="web_api_command", required=False)
    # discover
    p_disc = sub.add_parser("discover", help="端点发现与分类")
    p_disc.add_argument("--har", help="HAR 文件路径")
    p_disc.add_argument("--burp", help="Burp Suite 导出文件路径（XML/JSON）")
    p_disc.add_argument("--nuclei", help="Nuclei 结果 JSON 路径")
    p_disc.add_argument("--js", nargs="*", default=[], help="JS 文件路径列表")
    p_disc.add_argument("--text", help="自由文本字符串")
    p_disc.add_argument("--output-dir", required=True, help="输出目录")
    # scan-privilege
    p_priv = sub.add_parser("scan-privilege", help="越权探测")
    p_priv.add_argument("--base-url", required=True, help="目标基础 URL")
    p_priv.add_argument(
        "--cookie-a",
        required=True,
        help="账号 A cookie（sessionid=xxx 形式）",
    )
    p_priv.add_argument(
        "--cookie-b",
        required=True,
        help="账号 B cookie（sessionid=xxx 形式）",
    )
    p_priv.add_argument("--admin-cookie", help="管理员 cookie")
    p_priv.add_argument("--low-cookie", help="低权限 cookie")
    p_priv.add_argument(
        "--endpoints-json",
        help="端点 JSON（由 discover 子命令生成）",
    )
    p_priv.add_argument("--paths", nargs="*", default=[], help="高权限路径列表")
    p_priv.add_argument(
        "--rate-limit",
        type=float,
        default=2.0,
        help="每秒最大请求数（默认 2）",
    )
    p_priv.add_argument(
        "--i-have-authorization",
        action="store_true",
        default=False,
        help="确认已获合法测试授权",
    )
    p_priv.add_argument("--output-dir", required=True, help="输出目录")


# ────────────────────────── 入口 ──────────────────────────


def main(argv: Optional[List[str]] = None) -> int:
    """CLI 入口。

    Args:
        argv: 命令行参数列表（不传则使用 sys.argv）。

    Returns:
        int: 退出码。
    """
    logging_parser = argparse.ArgumentParser(prog="fp_sentinel web-api")
    build_parser(logging_parser)
    args = logging_parser.parse_args(argv)
    _setup_logging()
    if args.web_api_command == "discover":
        return cmd_discover(args)
    if args.web_api_command == "scan-privilege":
        return cmd_scan_privilege(args)
    logging_parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
