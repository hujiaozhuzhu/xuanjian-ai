"""mobile_poc CLI —— fp-sentinel mobile poc <subcommand>。

子命令:
    generate     按 goal / hook-point 生成 POC
    batch        批量生成(多个 hook-point)
    validate     校验已生成的脚本文件
    run          (mock)执行脚本 —— 默认 dry-run, 不连接真实设备
    templates    列出全部模板
    goals        列出全部意图

示例::

    python -m fp_sentinel.mobile_poc.cli generate --goal ssl-bypass --apk com.target.app
    python -m fp_sentinel.mobile_poc.cli generate --goal basic-hook \
        --hook-point hook_point.json --output ./scripts/
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from fp_sentinel.mobile_common import configure_logging

from .core.generator import (
    DEFAULT_GOALS,
    POCGenerator,
    HookPointSchemaError,
    UnknownGoalError,
)
from .core.validator import POCValidator
from .runtime.frida_client import MockFridaClient, create_client
from .runtime.script_executor import ScriptExecutor

__all__ = ["main", "build_parser"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fp-sentinel mobile poc",
        description="玄鉴 v4.0 能力⑤: Frida POC 自动生成(仅用于授权测试)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- generate ----
    p_gen = sub.add_parser("generate", help="按 goal 生成 POC 脚本")
    p_gen.add_argument("--goal", required=True, help="生成意图, 见 goals 子命令")
    p_gen.add_argument("--hook-point", help="hook 点位 JSON 文件路径")
    p_gen.add_argument("--class-name", help="目标类全名(覆盖 hook-point)")
    p_gen.add_argument("--method-name", help="目标方法名")
    p_gen.add_argument("--package", "--apk", dest="package", help="目标包名")
    p_gen.add_argument("--param-types", nargs="*", default=None, help="参数类型列表")
    p_gen.add_argument("--platform", default="android", choices=["android", "ios"])
    p_gen.add_argument("--rank", type=int, default=0,
                       help="hook-point 为推荐输出/列表时取第 N 个点位(0 起始)")
    p_gen.add_argument("--output", help="脚本输出目录, 或以 .js/.py 结尾的文件路径")
    p_gen.add_argument("--no-save", action="store_true", help="仅打印, 不落盘")

    # ---- batch ----
    p_batch = sub.add_parser("batch", help="按 hook-points JSON 批量生成")
    p_batch.add_argument("--hook-points", required=True, help="hook 点位列表 JSON")
    p_batch.add_argument("--goal", required=True)
    p_batch.add_argument("--output", required=True)

    # ---- validate ----
    p_val = sub.add_parser("validate", help="校验 POC 脚本")
    p_val.add_argument("script", help="脚本文件路径")
    p_val.add_argument("--language", default=None, choices=["js", "py"])

    # ---- run ----
    p_run = sub.add_parser("run", help="执行 POC(默认 mock dry-run)")
    p_run.add_argument("script", help="脚本文件路径")
    p_run.add_argument("--package", required=True, help="目标包名(红线 M6: 需授权)")
    p_run.add_argument("--device", default="mock-device-0000")
    p_run.add_argument("--authorized-packages", default=None,
                       help="逗号分隔的授权包名列表(红线 M6); 缺省时仅授权 --package 指定的包")
    p_run.add_argument("--real", action="store_true",
                       help="启用真实设备(需显式授权, 默认关闭)")

    # ---- templates / goals ----
    sub.add_parser("templates", help="列出全部模板")
    sub.add_parser("goals", help="列出全部生成意图")

    return parser


def _emit(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _load_hook_point(args: argparse.Namespace) -> Optional[dict]:
    if args.hook_point:
        return json.loads(Path(args.hook_point).read_text(encoding="utf-8"))
    ctx: dict = {"platform": args.platform}
    if args.class_name:
        ctx["class_name"] = args.class_name
    if args.method_name:
        ctx["method_name"] = args.method_name
    if args.package:
        ctx["package_name"] = args.package
    if args.param_types:
        ctx["param_types"] = args.param_types
    return ctx or None


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging()
    gen = POCGenerator()

    if args.command == "templates":
        _emit({"templates": gen.list_templates(), "count": len(gen.list_templates())})
        return 0

    if args.command == "goals":
        _emit({
            goal: [
                {"template": s["template"], "language": s["language"], "platform": s["platform"]}
                for s in specs
            ]
            for goal, specs in sorted(DEFAULT_GOALS.items())
        })
        return 0

    if args.command == "generate":
        hook_point = _load_hook_point(args)
        out_path = Path(args.output) if args.output else None
        # RD-004: --output 支持文件路径(.js/.py)与目录两种形态
        out_file = out_path.suffix.lower() in (".js", ".py") if out_path else False
        out_dir = None if (args.no_save or out_file) else (args.output or "./poc_scripts")
        try:
            result = gen.generate_for_goal(
                args.goal, hook_point=hook_point, output_dir=out_dir, rank=args.rank)
        except (UnknownGoalError, HookPointSchemaError) as exc:
            _emit({"success": False, "error": str(exc)})
            return 2
        if out_file and result.success:
            out_path.parent.mkdir(parents=True, exist_ok=True)  # type: ignore[union-attr]
            out_path.write_text(result.script, encoding="utf-8")  # type: ignore[union-attr]
            result.script_path = str(out_path.resolve())  # type: ignore[union-attr]
        payload = result.to_dict()
        payload["script"] = result.script
        _emit(payload)
        return 0 if result.success else 1

    if args.command == "batch":
        results = gen.batch_generate(args.hook_points, args.goal, output_dir=args.output)
        _emit({
            "total": len(results),
            "success": sum(1 for r in results if r.success),
            "items": [r.to_dict() for r in results],
        })
        return 0 if all(r.success for r in results) else 1

    if args.command == "validate":
        path = Path(args.script)
        text = path.read_text(encoding="utf-8")
        lang = args.language or ("py" if path.suffix == ".py" else "js")
        report = POCValidator().validate(text, lang)
        _emit({"script": str(path), **report.to_dict()})
        return 0 if report.valid else 1

    if args.command == "run":
        source = Path(args.script).read_text(encoding="utf-8")
        authorized = (
            [p.strip() for p in args.authorized_packages.split(",") if p.strip()]
            if args.authorized_packages else [args.package]
        )
        client = create_client(mock=not args.real, device_serial=args.device,
                               authorized_packages=authorized)
        executor = ScriptExecutor(client, authorized_packages=authorized,
                                  dry_run=not args.real)
        exec_result = executor.execute(source, args.package)
        _emit(exec_result.to_dict())
        return 0 if exec_result.success else 1

    parser.error(f"unknown command: {args.command}")  # pragma: no cover
    return 2


if __name__ == "__main__":
    sys.exit(main())


# ---------------------------------------------------------------------------
# typer 集成入口: 供 fp-sentinel/cli/__init__.py 聚合为
#   fp-sentinel mobile poc <subcommand>
# ---------------------------------------------------------------------------
try:  # typer 为主 CLI 既有依赖, 缺失时仅影响聚合注册
    import typer

    poc_app = typer.Typer(help="Frida POC 自动生成 (v4.0 能力⑤)", no_args_is_help=True)

    @poc_app.command("generate")
    def poc_generate(
        goal: str = typer.Option(..., "--goal", help="生成意图, 如 ssl-bypass/root-bypass"),
        hook_point: Optional[str] = typer.Option(None, "--hook-point", help="hook 点位 JSON"),
        class_name: Optional[str] = typer.Option(None, "--class-name"),
        method_name: Optional[str] = typer.Option(None, "--method-name"),
        package: Optional[str] = typer.Option(None, "--package", "--apk"),
        param_types: Optional[List[str]] = typer.Option(None, "--param-types"),
        output: Optional[str] = typer.Option(None, "--output"),
        rank: int = typer.Option(0, "--rank"),
        no_save: bool = typer.Option(False, "--no-save"),
    ) -> None:
        argv = ["generate", "--goal", goal, "--rank", str(rank)]
        if hook_point:
            argv += ["--hook-point", hook_point]
        if class_name:
            argv += ["--class-name", class_name]
        if method_name:
            argv += ["--method-name", method_name]
        if package:
            argv += ["--package", package]
        for pt in param_types or []:
            argv += ["--param-types", pt]
        if output:
            argv += ["--output", output]
        if no_save:
            argv += ["--no-save"]
        raise typer.Exit(main(argv))

    @poc_app.command("batch")
    def poc_batch(hook_points: str = typer.Option(..., "--hook-points"),
                  goal: str = typer.Option(..., "--goal"),
                  output: str = typer.Option(..., "--output")) -> None:
        raise typer.Exit(main(["batch", "--hook-points", hook_points,
                               "--goal", goal, "--output", output]))

    @poc_app.command("validate")
    def poc_validate(script: str = typer.Argument(...),
                     language: Optional[str] = typer.Option(None, "--language")) -> None:
        argv = ["validate", script]
        if language:
            argv += ["--language", language]
        raise typer.Exit(main(argv))

    @poc_app.command("run")
    def poc_run(script: str = typer.Argument(...),
                package: str = typer.Option(..., "--package"),
                authorized_packages: Optional[str] = typer.Option(None, "--authorized-packages")) -> None:
        argv = ["run", script, "--package", package]
        if authorized_packages:
            argv += ["--authorized-packages", authorized_packages]
        raise typer.Exit(main(argv))

    @poc_app.command("templates")
    def poc_templates() -> None:
        raise typer.Exit(main(["templates"]))

    @poc_app.command("goals")
    def poc_goals() -> None:
        raise typer.Exit(main(["goals"]))
except ImportError:  # pragma: no cover
    poc_app = None  # type: ignore[assignment]
