"""CVSS 评分命令行子模块（``fp_sentinel cvss``）。

提供 ``calc`` / ``suggest`` / ``audit`` 三个子命令：

- ``calc --vector "CVSS:3.1/AV:N/..."``：解析向量字符串并输出评分详情；
- ``suggest --title "SQL注入"``：根据标题/描述关键词自动匹配 CVSS 评分；
- ``audit <findings.json>``：读取发现 JSON 并为缺失 CVSS 的条目附带评分。

兼容 ``{"findings":[...]}`` / ``[...]`` / newline JSON 三种 JSON 格式。

用法示例::

    python -m fp_sentinel.mobile_reporting.cvss_cli calc \\
        --vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    python -m fp_sentinel.mobile_reporting.cvss_cli suggest \\
        --title "SQL注入" --desc "登录接口存在注入" --category web

    python -m fp_sentinel.mobile_reporting.cvss_cli audit findings.json \\
        --output scored.json --only-empty
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .cvss import (
    CvssV31,
    auto_score,
    explain_score,
    suggest_cvss,
)

logger = logging.getLogger(__name__)

__all__ = ["main", "_build_parser"]


def _build_parser() -> argparse.ArgumentParser:
    """构建 ``fp_sentinel cvss`` 子命令参数解析器。"""
    parser = argparse.ArgumentParser(
        prog="fp_sentinel cvss",
        description="CVSS v3.1 评分工具（计算 / 建议 / 审计）。",
    )
    sub = parser.add_subparsers(dest="command")

    # ── calc ──
    p_calc = sub.add_parser("calc", help="按向量字符串计算 CVSS 评分")
    p_calc.add_argument(
        "--vector", required=True, help="CVSS v3.1 向量字符串，如 CVSS:3.1/AV:N/..."
    )

    # ── suggest ──
    p_sug = sub.add_parser("suggest", help="按标题/描述关键词自动匹配 CVSS 评分")
    p_sug.add_argument("--title", required=True, help="漏洞标题")
    p_sug.add_argument("--desc", default="", help="漏洞描述（可选）")
    p_sug.add_argument("--category", default="", help="分类（可选）")
    p_sug.add_argument("--cwe", default="", help="CWE 编号（可选）")

    # ── audit ──
    p_audit = sub.add_parser("audit", help="读取发现 JSON 并为缺失 CVSS 的条附带评分")
    p_audit.add_argument("input", help="发现 JSON 文件路径")
    p_audit.add_argument("--output", required=True, help="输出文件路径")
    p_audit.add_argument(
        "--only-empty",
        action="store_true",
        help="仅对当前 cvss_score == 0 或缺失 cvss_score 的条目评分",
    )
    p_audit.add_argument(
        "--update-summary",
        action="store_true",
        help="刷新 statistics.by_severity 分布",
    )

    return parser


def _safe_load_input_file(path_str: str) -> Path:
    """校验输入文件存在并返回 Path，不存在时给出清晰错误并 exit(2)。"""
    path = Path(path_str)
    if not path.exists():
        print(f"错误：输入文件不存在: {path_str}", file=sys.stderr)
        sys.exit(2)
    if not path.is_file():
        print(f"错误：输入路径不是文件: {path_str}", file=sys.stderr)
        sys.exit(2)
    return path


def _safe_load_json(path: Path) -> Any:
    """读取并解析 JSON，解析失败时给出清晰错误并 exit(2)。

    支持：

    - 单 JSON 对象/数组；
    - newline JSON（每行一个 JSON 对象）。
    """
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        print(f"错误：输入文件为空: {path}", file=sys.stderr)
        sys.exit(2)

    # 尝试标准 JSON 解析
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 尝试 newline JSON
    items: List[Dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                items.append(item)
        except json.JSONDecodeError as exc:
            print(
                f"错误：JSON 解析失败（第 {line_no} 行）: {exc}\n"
                f"文件: {path}",
                file=sys.stderr,
            )
            sys.exit(2)

    if not items:
        print(f"错误：无法解析任何有效的 JSON 条目: {path}", file=sys.stderr)
        sys.exit(2)
    return items


def _extract_findings(data: Any) -> tuple[List[Dict[str, Any]], bool, dict]:
    """从任意兼容 JSON 结构中提取 findings 列表。

    返回 ``(findings, is_container, container)``，其中 is_container 为 True
    时表示 container 是 {"findings": [...]} 这类包装对象（回写时保留结构）。
    """
    if isinstance(data, dict):
        if "findings" in data:
            findings_raw = data["findings"]
            if isinstance(findings_raw, list):
                return list(findings_raw), True, data
        # 兼容 vulnerabilities 字段名
        if "vulnerabilities" in data:
            findings_raw = data["vulnerabilities"]
            if isinstance(findings_raw, list):
                return list(findings_raw), True, data
        # 没有找到列表字段：整体视为单条
        return [data], False, {}
    if isinstance(data, list):
        return list(data), False, {}
    return [data], False, {}


def _dict_to_finding_obj(d: Dict[str, Any]) -> Any:
    """将 dict 转换为具有属性的简单对象（兼容 auto_score 的属性访问）。"""

    class _Stub:
        def __init__(self, data: Dict[str, Any]) -> None:
            for k, v in data.items():
                setattr(self, k, v)
            # 确保 cvss 字段存在
            if not hasattr(self, "cvss_score"):
                self.cvss_score = 0.0
            if not hasattr(self, "cvss_vector"):
                self.cvss_vector = ""
            if not hasattr(self, "risk_level"):
                self.risk_level = ""
            if not hasattr(self, "affected_scope"):
                self.affected_scope = ""

        def __repr__(self) -> str:
            title = getattr(self, "title", "<无title>")
            fid = getattr(self, "vuln_id", getattr(self, "id", "<无id>"))
            return f"_Stub(id={fid!r}, title={title!r})"

    return _Stub(d)


def _run_calc(args: argparse.Namespace) -> int:
    """执行 ``calc`` 子命令。"""
    cv = CvssV31.parse(args.vector)
    explanation = explain_score(score=cv.base_score, vector=cv.vector_string())
    output = {
        "base_score": cv.base_score,
        "severity": cv.severity,
        "vector": cv.vector_string(),
        "explanation": explanation,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


def _run_suggest(args: argparse.Namespace) -> int:
    """执行 ``suggest`` 子命令。"""
    result = suggest_cvss(
        title=args.title,
        description=args.desc or "",
        category=args.category or "",
        cwe_id=args.cwe or "",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def _run_audit(args: argparse.Namespace) -> int:
    """执行 ``audit`` 子命令。"""
    path = _safe_load_input_file(args.input)
    data = _safe_load_json(path)
    findings, is_container, container = _extract_findings(data)

    scored = 0
    skipped = 0
    for item in findings:
        if not isinstance(item, dict):
            continue
        obj = _dict_to_finding_obj(item)
        # 读取当前 cvss_score（兼容属性名和字典访问）
        current_cvss = 0.0
        raw = item.get("cvss_score", 0.0)
        try:
            current_cvss = float(raw) if raw is not None else 0.0
        except (TypeError, ValueError):
            current_cvss = 0.0

        if args.only_empty and current_cvss > 0:
            skipped += 1
            continue

        auto_score(obj)
        new_cvss = getattr(obj, "cvss_score", 0.0)
        if new_cvss > 0:
            item["cvss_score"] = new_cvss
            item["cvss_vector"] = getattr(obj, "cvss_vector", "")
            item["risk_level"] = getattr(obj, "risk_level", "")
            scored += 1
        else:
            skipped += 1

    # 可选：刷新 statistics.by_severity
    if args.update_summary and is_container:
        severity_counts: Dict[str, int] = {}
        for item in findings:
            sev = str(item.get("severity", "INFO") or "INFO").strip().upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        statistics = container.get("statistics", {})
        if not isinstance(statistics, dict):
            statistics = {}
        statistics["by_severity"] = severity_counts
        container["statistics"] = statistics

    # 输出
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # 决定输出结构
    if is_container:
        output_data = container
    elif isinstance(data, list):
        output_data = findings
    else:
        output_data = findings[0] if findings else {}
    out_path.write_text(
        json.dumps(output_data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(
        f"审计完成：共 {len(findings)} 条，新评分 {scored} 条，跳过 {skipped} 条。",
        file=sys.stderr,
    )
    print(f"输出: {out_path}", file=sys.stderr)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """``fp_sentinel cvss`` 子命令入口。

    Args:
        argv: 命令行参数列表（不含程序名）；为 ``None`` 时使用 ``sys.argv``。

    Returns:
        退出码（0 成功，2 输入错误）。
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 2

    if args.command == "calc":
        return _run_calc(args)
    if args.command == "suggest":
        return _run_suggest(args)
    if args.command == "audit":
        return _run_audit(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
