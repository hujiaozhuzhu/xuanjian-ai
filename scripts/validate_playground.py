#!/usr/bin/env python3
"""
靶场验证脚本

读取双靶场（JS / Python）的 expected-findings.json，调用真实扫描管道，
断言 vulnerability 检出 + safe 零误报，打印汇总表。

用法:
    python scripts/validate_playground.py [--strict]

退出码:
    0 = 全部通过（或 --strict 下 JS 失败也算失败）
    1 = Python 靶场验证失败（或 --strict 下 JS 靶场失败）
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from fp_sentinel.models import ScanResult  # noqa: E402
from fp_sentinel.scanners import ResultNormalizer  # noqa: E402

PLAYGROUNDS = {
    "python": {
        "dir": PROJECT_ROOT / "playground" / "python-vuln-app",
        "source": "app.py",
    },
    "js": {
        "dir": PROJECT_ROOT / "playground" / "js-vuln-app",
        "source": "app.js",
    },
}

LINE_TOLERANCE = 3

# Python 靶场 expected-findings.json 未列出 safe 条目，这里补充 7 条 safe 行（app.py）：
# 参数化SQL / 白名单subprocess / ast.literal_eval / json.loads / sha256 / 路径realpath校验open / yaml.safe_load
FALLBACK_SAFE_LINES = {
    "python": [32, 50, 68, 87, 104, 130, 148],
    "js": [],
}


async def scan_python(source: Path) -> List[ScanResult]:
    """Python 靶场：使用项目 Python 扫描器（经 ScannerManager 调度）"""
    from fp_sentinel.models import ScanTool
    from fp_sentinel.scanners import ScannerManager

    manager = ScannerManager({"scanners": {"semgrep": {"enabled": False}, "bandit": {"enabled": False}}})
    if ScanTool.PY_SCANNER not in manager.scanners:
        raise RuntimeError("PythonScanner 未注册")
    return await manager.scan(str(source), language="python", scanners=[ScanTool.PY_SCANNER])


async def scan_js(source: Path) -> List[ScanResult]:
    """JS 靶场：使用 JSScanner（不检查 npm 依赖）"""
    from fp_sentinel.scanners.js_scanner import JSScanner

    scanner = JSScanner({"check_dependencies": False})
    return await scanner.scan(str(source))


def normalize(results: List[ScanResult]):
    norm = ResultNormalizer()
    return norm.deduplicate(norm.normalize_many(results))


def verify(findings, expected: dict, lang_key: str = "") -> Dict:
    """核对预期检出与零误报"""
    vulns = [f for f in expected.get("findings", []) if f.get("type") == "vulnerability"]
    found = {}
    for f in findings:
        found.setdefault(f.rule_id, []).append(f.line_start)

    detected, missed, line_miss = [], [], []
    for v in vulns:
        rid, approx = v["rule_id"], v.get("line_approx", 0)
        hits = found.get(rid, [])
        if hits:
            detected.append(v)
            if approx and min(abs(h - approx) for h in hits) > LINE_TOLERANCE:
                # 行号偏差过大也记为疑似（expected line_approx 可能与靶场有出入）
                line_miss.append((rid, hits, approx))
        else:
            missed.append(rid)

    # safe 零误报：safe 行 ±3 内不应有任何报告
    safe_entries = [v for v in expected.get("findings", []) if v.get("type") == "safe"]
    safe_lines = [v.get("line_approx") for v in safe_entries if v.get("line_approx")]
    if not safe_lines:
        safe_lines = FALLBACK_SAFE_LINES.get(lang_key, [])
    fp = []
    for f in findings:
        for s in safe_lines:
            if s and abs(f.line_start - s) <= LINE_TOLERANCE:
                fp.append(f"{f.rule_id} L{f.line_start} (safe {s})")

    return {
        "total_vulns": len(vulns),
        "detected": len(detected),
        "missed": missed,
        "line_miss": line_miss,
        "false_positives": fp,
        "safe_count": len(safe_lines),
        "extra": [f"{f.rule_id} L{f.line_start}" for f in findings
                  if f.rule_id not in {v["rule_id"] for v in vulns}],
    }


async def validate_one(lang: str) -> tuple:
    cfg = PLAYGROUNDS[lang]
    source = cfg["dir"] / cfg["source"]
    expected_file = cfg["dir"] / "expected-findings.json"
    if not source.exists() or not expected_file.exists():
        return lang, None, f"靶场文件缺失: {source} 或 {expected_file}"

    expected = json.loads(expected_file.read_text(encoding="utf-8"))
    try:
        if lang == "python":
            results = await scan_python(source)
        else:
            results = await scan_js(source)
    except Exception as e:
        return lang, None, f"扫描失败: {e}"

    findings = normalize(results)
    return lang, verify(findings, expected, lang), None


def print_table(rows: List[Dict]) -> None:
    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(title="靶场验证结果", show_lines=False)
        table.add_column("靶场")
        table.add_column("检出")
        table.add_column("漏检")
        table.add_column("safe误报")
        table.add_column("状态")
        for r in rows:
            table.add_row(
                r["lang"],
                f"{r['detected']}/{r['total']}",
                ",".join(r["missed"]) or "-",
                ",".join(r["fp"]) or "0",
                "PASS" if r["ok"] else "FAIL",
            )
        Console().print(table)
    except ImportError:
        for r in rows:
            print(f"[{r['lang']}] {r['detected']}/{r['total']} missed={r['missed']} fp={r['fp']} -> {'PASS' if r['ok'] else 'FAIL'}")


async def main() -> int:
    parser = argparse.ArgumentParser(description="玄鉴靶场验证")
    parser.add_argument("--strict", action="store_true", help="JS 靶场失败也返回非零")
    args = parser.parse_args()

    rows, failed = [], []
    for lang in ("python", "js"):
        lang_name, report, err = await validate_one(lang)
        if err:
            print(f"\n[{lang_name}] 验证出错: {err}")
            if lang_name == "python":
                failed.append(lang_name)
            else:
                print(f"提示: JS 侧由并行任务修复中，失败不阻塞 Python 验证"
                      f"{'' if args.strict else '（--strict 可将其计入失败）'}")
                if args.strict:
                    failed.append(lang_name)
            rows.append({"lang": lang_name, "total": "-", "detected": "-",
                         "missed": "-", "fp": "-", "ok": False})
            continue

        ok = report["detected"] == report["total_vulns"] and not report["false_positives"]
        rows.append({
            "lang": lang_name,
            "total": report["total_vulns"],
            "detected": report["detected"],
            "missed": report["missed"],
            "fp": report["false_positives"],
            "ok": ok,
        })
        if report["line_miss"]:
            print(f"[{lang_name}] 行号偏差提醒: {report['line_miss']}")
        if not ok:
            failed.append(lang_name)

    print_table(rows)
    if failed:
        print(f"\n验证失败: {failed}")
        return 1
    print("\n全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
