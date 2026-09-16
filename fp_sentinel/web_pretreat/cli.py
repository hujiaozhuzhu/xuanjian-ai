"""web_pretreat CLI 入口 —— fp_sentinel web-pretreat <subcommand>。

子命令：

- ``env-check``: 一键检测常用扫描器 / LibreOffice / Node.js 的可用性，
  生成 Markdown 报告。
- ``js <file_or_dir>``: 对指定 JS 文件 / 目录下所有 JS 做预处理
  （美化 / 提取 / 可疑 / API / packer）。
- ``scan-env-check``: 给扫描前首跑的一个脚本，
  自动给出"当前能跑 fp_sentinel scan / 报告完整度"的结论。

示例::

    python -m fp_sentinel.web_pretreat.cli env-check
    python -m fp_sentinel.web_pretreat.cli js ./app.min.js
    python -m fp_sentinel.web_pretreat.cli scan-env-check

入口函数 :func:`main` 注册为 ``fp_sentinel.web_pretreat.cli:main``，
可通过 ``python -m fp_sentinel.web_pretreat.cli`` 直接调用。
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Optional

from fp_sentinel.mobile_common import configure_logging

from .js_pretreat import JsPrettier

logger = logging.getLogger(__name__)

__all__ = ["main", "build_parser"]


# ──────────────────────────────────────────────────────
# argparse 构建
# ──────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """构建并返回 ``fp_sentinel web-pretreat`` 的参数解析器。"""
    parser = argparse.ArgumentParser(
        prog="fp-sentinel web-pretreat",
        description="玄鉴AI Web 侧预处理: JS 解混淆 / 环境审计",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ① env-check
    p_env = sub.add_parser(
        "env-check",
        help="检测常用扫描器 / LibreOffice / Node.js 可用性",
    )
    p_env.add_argument(
        "--output", "-O",
        default=None,
        help="Markdown 报告输出路径（未指定则只输出到 stdout）",
    )

    # ② js
    p_js = sub.add_parser(
        "js",
        help="对指定 JS 文件 / 目录下所有 .js 做预处理",
    )
    p_js.add_argument(
        "target",
        help="待处理的 JS 文件路径或目录路径",
    )
    p_js.add_argument(
        "--apis", action="store_true", default=False,
        help="启用 API / URL 端点模式识别",
    )
    p_js.add_argument(
        "--strings", action="store_true", default=False,
        help="启用字面量字符串提取",
    )
    p_js.add_argument(
        "--suspicious", action="store_true", default=False,
        help="启用可疑片段识别",
    )
    p_js.add_argument(
        "--output-dir", "-O",
        default=None,
        help="输出目录；未指定则仅输出到 stdout",
    )

    # ③ scan-env-check
    sub.add_parser(
        "scan-env-check",
        help="扫描前首跑：评估当前能跑 fp_sentinel scan 的完整度",
    )

    return parser


# ──────────────────────────────────────────────────────
# 各子命令实现
# ──────────────────────────────────────────────────────

def _cmd_env_check(args: argparse.Namespace) -> int:
    """``env-check`` 子命令实现。"""
    from fp_sentinel.mobile_common.env_check import (
        LibreOfficeChecker,
        NodeJSExtendedChecker,
        ScannerChecker,
        run_env_audit,
        SCANNER_INSTALL_CMD,
    )

    # 跑完整审计
    report = run_env_audit(output_path=args.output)
    # 输出到 stdout
    print(report)

    # 给出简短结论
    checker = ScannerChecker()
    results = checker.check_all()
    available_count = sum(1 for r in results if r.available)
    total_count = len(results)

    lo = LibreOfficeChecker()
    node = NodeJSExtendedChecker()

    print("---")
    print(
        f"[结论] 扫描器 {available_count}/{total_count} 可用 | "
        f"LibreOffice {'可用' if lo.is_available() else '缺失'} | "
        f"Node.js {'可用' if node.is_available() else '缺失'}"
    )
    if available_count < total_count:
        print(f"建议: {SCANNER_INSTALL_CMD}")
    return 0


def _collect_js_files(target: str) -> List[Path]:
    """根据参数收集待处理的 .js 文件 Path 列表。"""
    p = Path(target)
    if p.is_file():
        return [p]
    if p.is_dir():  # 目录递归收集
        return sorted(p.rglob("*.js"))
    logger.error("无效的 target: %s", target)
    return []


def _cmd_js(args: argparse.Namespace) -> int:
    """``js`` 子命令实现。"""
    files = _collect_js_files(args.target)
    if not files:
        logger.error("未找到任何 JS 文件: %s", args.target)
        return 1

    # 默认全开启（无 flag 指定时）
    enable_all = not (args.apis or args.strings or args.suspicious)
    do_apis = args.apis or enable_all
    do_strings = args.strings or enable_all
    do_suspicious = args.suspicious or enable_all

    prettier = JsPrettier()

    # 确保输出目录
    output_dir: Optional[Path] = None
    if args.output_dir is not None:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

    any_success = False
    for fp in files:
        logger.info("处理: %s", fp)
        try:
            src = fp.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("无法读取 %s: %s", fp, exc)
            continue

        # 跑完整流水线
        result = prettier.process(src)

        # 生成结果 payload
        payload = {
            "file": str(fp),
            "prettified_size": len(result.prettified_src),
            "used_beautifier": result.used_beautifier,
            "packer_type": result.packer_type,
            "warnings": [w.message for w in result.warnings],
            "api_count": len(result.apis) if do_apis else 0,
            "suspicious_count": len(result.suspicious) if do_suspicious else 0,
            "string_count": len(result.strings) if do_strings else 0,
        }

        if do_apis:
            payload["apis_sample"] = result.apis[:10]
        if do_suspicious:
            payload["suspicious"] = result.suspicious
        if do_strings:
            # 只采样前 50 个字符串避免输出过大
            payload["strings_sample"] = result.strings[:50]

        json_str = json.dumps(payload, ensure_ascii=False, indent=2)

        if output_dir is not None:
            out_path = output_dir / f"{fp.stem}.preprocess.json"
            out_path.write_text(json_str, encoding="utf-8")
            logger.info("已写入: %s", out_path)
        else:
            print(f"### {fp}")
            print(json_str)
            print()

        any_success = True

    return 0 if any_success else 1


def _cmd_scan_env_check(args: argparse.Namespace) -> int:
    """``scan-env-check`` 子命令实现。"""
    from fp_sentinel.mobile_common.env_check import (
        LibreOfficeChecker,
        NodeJSExtendedChecker,
        ScannerChecker,
        SCANNER_INSTALL_CMD,
    )

    checker = ScannerChecker()
    results = checker.check_all()
    lo = LibreOfficeChecker()
    node = NodeJSExtendedChecker()

    available = [r for r in results if r.available]
    missing = [r for r in results if not r.available]

    print("=" * 60)
    print("  fp_sentinel scan 能力评估")
    print("=" * 60)

    print(f"\n可用扫描器 ({len(available)}/{len(results)}):")
    for r in available:
        print(f"  [OK] {r.name:<14} {r.version}")

    if missing:
        print(f"\n缺失扫描器 ({len(missing)}):")
        for r in missing:
            print(f"  [--] {r.name:<14} {r.install_hint}")

    print("\n辅助工具:")
    print(
        f"  LibreOffice (soffice): {'可用' if lo.is_available() else '缺失'}",
        f"  Node.js (node): {'可用' if node.is_available() else '缺失'}",
    )

    # 报告完整度
    completeness = len(available) / max(len(results), 1)
    if completeness >= 0.75:
        print(f"\n[结论] scan 完整度 {completeness:.0%} —— 可完整运行")
    elif completeness >= 0.4:
        print(f"\n[结论] scan 完整度 {completeness:.0%} —— 部分可用，建议补装")
    else:
        print(f"\n[结论] scan 完整度 {completeness:.0%} —— 不运行，请先安装依赖")
        print(f"建议: {SCANNER_INSTALL_CMD}")

    return 0


# ──────────────────────────────────────────────────────
# 入口
# ──────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    """CLI 统一入口。

    Parameters
    ----------
    argv:
        自定义命令行参数；未指定时默认取 ``sys.argv[1:]``。
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    configure_logging(verbose=False)

    if args.command == "env-check":
        return _cmd_env_check(args)
    if args.command == "js":
        return _cmd_js(args)
    if args.command == "scan-env-check":
        return _cmd_scan_env_check(args)

    logger.error("未知子命令: %s", args.command)
    return 1


if __name__ == "__main__":
    sys.exit(main())
