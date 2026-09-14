# -*- coding: utf-8 -*-
"""mobile_hook CLI —— `fp-sentinel mobile hook ...` 子命令组。

命令::

    fp-sentinel mobile hook recommend ./app.apk --goal encrypt-trace
    fp-sentinel mobile hook technique base64 --apk ./app.apk --output ./trace.json
    fp-sentinel mobile hook scan ./app.apk --techniques all --goal request-plaintext
    fp-sentinel mobile hook verify ./hook_point.json --device <serial>

说明：verify 为 mock 化验证，不实际连接设备（规划约束）。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional

import typer

from fp_sentinel.mobile_common import configure_logging

hook_app = typer.Typer(
    help="自动化 Hook 定位（7 种技法 + 关键性评分推荐）",
    no_args_is_help=True,
)

logger = logging.getLogger(__name__)


def _echo_table(text: str) -> None:
    typer.echo(text)


@hook_app.command()
def recommend(
    apk: str = typer.Argument(..., help="目标 APK 路径"),
    goal: str = typer.Option("encrypt-trace", "--goal", "-g",
                             help="分析目标: encrypt-trace/request-plaintext/signature-bypass/root-detection/generic"),
    top_n: int = typer.Option(10, "--top", "-n", help="推荐 Top-N 点位"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="结果 JSON 输出文件"),
):
    """自动化推荐 Hook 点位（七技法 + 关键性评分排序）。"""
    configure_logging()
    from .core.base import HookLocator
    from .models import HookRecommendation

    locator = HookLocator(apk_path=apk, goal=goal)
    with typer.progressbar(length=1, label="静态分析+推荐") as bar:
        rec: HookRecommendation = locator.recommend(apk_path=apk, goal=goal, top_n=top_n)
        bar.update(1)

    typer.echo(f"\nAPK: {rec.apk_path}   包名: {rec.package_name}   目标: {rec.goal}")
    if rec.degraded:
        typer.echo("提示: 发生了降级（Frida/依赖不可用），结果来自纯静态分析。")
    typer.echo(f"技法命中统计: {rec.technique_stats()}\n")
    _echo_table(rec.format_table(top_n))
    if rec.top is not None:
        typer.echo(f"\nTop1 调用链: {' -> '.join(rec.top.call_chain) if rec.top.call_chain else '(无调用链)'}")
        typer.echo(f"Top1 评分明细: {rec.top.score_breakdown}")

    _write_json_output(output, rec.to_dict())


@hook_app.command()
def technique(
    name: str = typer.Argument(..., help=f"技法名（keyword/collection/toast/log/json/string/base64）"),
    apk: str = typer.Option(..., "--apk", help="目标 APK 路径"),
    goal: str = typer.Option("generic", "--goal", "-g", help="分析目标"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="结果 JSON 输出文件"),
    script: Optional[str] = typer.Option(None, "--script", help="同时导出 Frida 脚本到该路径"),
):
    """执行单一技法（独立可运行，含脚本模板导出）。"""
    configure_logging()
    from .core.base import HookLocator

    locator = HookLocator(apk_path=apk, goal=goal)
    result = locator.execute_technique(name, apk_path=apk)

    if not result.success:
        typer.secho(f"技法 {name} 执行失败: {result.error}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    typer.echo(f"技法 {name} 完成: 命中 {result.count} 个点位, 耗时 {result.duration_ms:.0f}ms\n")
    _echo_table(_points_to_table(result.ranked()))
    _write_json_output(output, result.to_dict())

    if script:
        hook_points = result.ranked()
        from .techniques.base import build_technique
        src = build_technique(name, goal=goal).generate_frida_script(hook_points)
        Path(script).write_text(src, encoding="utf-8")
        typer.echo(f"\nFrida 脚本已导出: {script}")


@hook_app.command()
def scan(
    apk: str = typer.Argument(..., help="目标 APK 路径"),
    techniques: str = typer.Option("all", "--techniques", "-t",
                                   help="逗号分隔的技法列表或 all"),
    goal: str = typer.Option("request-plaintext", "--goal", "-g", help="分析目标"),
    top_n: int = typer.Option(20, "--top", "-n", help="输出 Top-N 点位"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="结果 JSON 输出文件"),
):
    """组合技法扫描（多技法并行产出并统一评分）。"""
    configure_logging()
    from .core.base import HookLocator
    from .techniques import TECHNIQUE_NAMES

    if techniques.strip().lower() == "all":
        names = list(TECHNIQUE_NAMES)
    else:
        names = [t.strip() for t in techniques.split(",") if t.strip()]
        unknown = [t for t in names if t not in TECHNIQUE_NAMES]
        if unknown:
            typer.secho(f"未知技法: {unknown}，可选: {TECHNIQUE_NAMES}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)

    locator = HookLocator(apk_path=apk, goal=goal)
    rec = locator.recommend(apk_path=apk, goal=goal, top_n=top_n, techniques=names)

    typer.echo(f"\n组合扫描完成: 技法 {names}，共命中 {len(rec.hook_points)} 个点位（Top {top_n}）\n")
    _echo_table(rec.format_table(top_n))
    _write_json_output(output, rec.to_dict())


@hook_app.command()
def verify(
    hook_point_file: str = typer.Argument(..., help="HookPoint JSON 文件（recommend/technique 输出）"),
    device: Optional[str] = typer.Option(None, "--device", "-d", help="设备序列号（mock，不实际连接）"),
):
    """验证 Hook 点位（mock 化：脚本合法性 + 静态一致性，不连接设备）。"""
    configure_logging()
    from .core.base import HookLocator
    from .models import HookPoint

    raw = json.loads(Path(hook_point_file).read_text(encoding="utf-8"))
    # 兼容三种输入: 单个 HookPoint / {hook_points: [...]} / recommendation dict
    if isinstance(raw, dict) and "hook_points" in raw:
        items = raw["hook_points"]
    elif isinstance(raw, list):
        items = raw
    else:
        items = [raw]
    if not items:
        typer.secho("输入文件中没有 HookPoint", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    points = [HookPoint.from_dict(i) for i in items]
    locator = HookLocator()
    all_ok = True
    for hp in points:
        verdict = locator.verify_hook(hp, device=device)
        status = "PASS" if verdict["verified"] else "FAIL"
        typer.echo(
            f"[{status}] {verdict['target']}  technique={hp.technique}  "
            f"script_valid={verdict['script_valid']}  static_match={verdict['static_match']}  "
            f"(mock device={verdict['device']})"
        )
        all_ok = all_ok and verdict["verified"]
    raise typer.Exit(code=0 if all_ok else 1)


# ────────────────────────── 辅助 ──────────────────────────

def _points_to_table(points) -> str:
    headers = ("Rank", "Class", "Method", "Confidence", "Technique")
    width = (6, 52, 26, 12, 12)
    lines = ["  ".join(h.ljust(w) for h, w in zip(headers, width)).rstrip()]
    lines.append("  ".join("-" * w for w in width))
    for i, hp in enumerate(points, 1):
        cells = (str(i), hp.class_name[: width[1]], hp.method_name[: width[2]],
                 f"{hp.confidence:.2f}", hp.technique)
        lines.append("  ".join(c.ljust(w) for c, w in zip(cells, width)).rstrip())
    return "\n".join(lines)


def _write_json_output(output: Optional[str], data: dict) -> None:
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        typer.echo(f"\n结果已写入: {path}")


# ── mobile 命令组（挂载 hook 组，后续 mobile decompile 等能力也挂这里） ──

mobile_app = typer.Typer(help="移动安全能力（mobile hook / decompile / ...）", no_args_is_help=True)
mobile_app.add_typer(hook_app, name="hook")


def main() -> None:
    """支持 `python -m fp_sentinel.mobile_hook.cli hook ...` 独立运行。"""
    mobile_app()


if __name__ == "__main__":
    main()
