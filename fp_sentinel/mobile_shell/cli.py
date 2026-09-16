"""
mobile_shell CLI 入口 —— fp-sentinel mobile shell detect|dump-android|dump-ios|batch

对齐《v4.0.0-mobile-reverse-engineering-plan.md》2.1.4 CLI 设计::

    fp-sentinel mobile shell detect ./app.apk
    fp-sentinel mobile shell dump-android --apk ./app.apk --output ./dumped/
    fp-sentinel mobile shell dump-ios --app com.target.app --output ./dumped/
    fp-sentinel mobile shell batch ./apps/ --platform all --output ./results/

安全红线：S1（仅 localhost）、S7（输出仅写入 --output 指定目录）。
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

import typer

from fp_sentinel.mobile_common import configure_logging
from fp_sentinel.mobile_shell.core.android_dumper import AndroidDumper
from fp_sentinel.mobile_shell.core.ios_dumper import IOSDumper
from fp_sentinel.mobile_shell.models.dump_result import (
    DumpConfig,
    DumpMode,
    DumpResult,
    DumpTarget,
    Platform,
)
from fp_sentinel.mobile_shell.models.protection_info import ProtectionInfo

shell_app = typer.Typer(help="砸壳引擎 (能力①：加固检测 / Android·iOS 脱壳)")


def _echo_result(result: DumpResult) -> None:
    """以 JSON 形式输出脱壳结果。"""
    typer.echo(
        json.dumps(
            {
                "success": result.success,
                "mode": result.mode.value,
                "platform": result.platform.value,
                "protection": result.protection_type,
                "original": result.original_path,
                "dumped": result.dumped_path,
                "dex_count": result.dex_count,
                "duration_sec": result.duration_sec,
                "sha256_before": result.sha256_before,
                "sha256_after": result.sha256_after,
                "warnings": result.warnings,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


@shell_app.command()
def detect(
    target: str = typer.Argument(..., help="APK/IPA 文件路径"),
    json_output: bool = typer.Option(False, "--json", help="JSON 输出"),
) -> None:
    """自动识别加固类型（360/腾讯/梆梆/爱加密/娜迦/百度/阿里/无壳）。"""
    configure_logging()
    path = Path(target)
    if path.suffix.lower() == ".ipa":
        info: ProtectionInfo = IOSDumper().detect_protection(str(path))
    else:
        info = AndroidDumper().detect_protection(str(path))
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "protection": info.protection,
                    "confidence": info.confidence,
                    "version": info.version,
                    "packer_class": info.packer_class,
                    "native_libs": info.native_libs,
                    "signature_files": info.signature_files,
                    "is_packed": info.is_packed,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        typer.echo(info.summary())


@shell_app.command("dump-android")
def dump_android(
    apk: str = typer.Option(..., "--apk", help="APK 路径"),
    output: str = typer.Option("./reports/mobile_shell/", "--output", help="输出目录"),
    mode: str = typer.Option("auto", "--mode", help="auto(动态优先)/static"),
    device: Optional[str] = typer.Option(None, "--device", help="USB 设备 ID"),
) -> None:
    """Android 脱壳：优先 frida-dexdump，降级 androguard 静态检测。"""
    configure_logging()
    dump_mode = DumpMode.FRIDA if mode.lower() in {"auto", "frida"} else DumpMode.STATIC
    target = DumpTarget(path=apk, device_id=device)
    config = DumpConfig(output_dir=output, mode=dump_mode)
    result = AndroidDumper().dump(target, config)
    _echo_result(result)
    raise typer.Exit(code=0 if result.success else 1)


@shell_app.command("dump-ios")
def dump_ios(
    app: Optional[str] = typer.Option(None, "--app", help="IPA 路径"),
    package: Optional[str] = typer.Option(None, "--package", help="目标包名(需越狱设备)"),
    output: str = typer.Option("./reports/mobile_shell/", "--output", help="输出目录"),
    mode: str = typer.Option("auto", "--mode", help="auto(动态优先)/static(仅提取)/detect(仅检测)"),
    device: Optional[str] = typer.Option(None, "--device", help="设备 UDID"),
) -> None:
    """iOS 脱壳：frida-ios-dump（需越狱设备），降级检测模式。

    ``--mode`` 三档：
    - ``auto``: 优先 frida-ios-dump 动态脱壳，失败自动降级检测
    - ``static``: 仅提取未加密二进制或复制 IPA，不尝试动态脱壳
    - ``detect``: 仅 cryptid 加密检测，不产出解密二进制
    """
    configure_logging()
    if not app and not package:
        typer.echo("错误: --app 与 --package 至少提供一个", err=True)
        raise typer.Exit(code=2)
    mode_lower = mode.lower()
    if mode_lower in ("auto", "frida"):
        dump_mode = DumpMode.FRIDA
    elif mode_lower == "static":
        dump_mode = DumpMode.STATIC
    elif mode_lower == "detect":
        dump_mode = DumpMode.DETECT
    else:
        typer.echo(f"错误: 未知 mode={mode}（可选 auto/static/detect）", err=True)
        raise typer.Exit(code=2)
    target = DumpTarget(
        path=app or package or "",
        package=package,
        device_id=device,
        platform_hint=Platform.IOS,
    )
    config = DumpConfig(output_dir=output, mode=dump_mode)
    result = IOSDumper().dump(target, config)
    _echo_result(result)
    raise typer.Exit(code=0 if result.success else 1)


@shell_app.command("batch")
def batch(
    directory: str = typer.Argument(..., help="包含 APK/IPA 的目录"),
    output: str = typer.Option("./reports/mobile_shell/", "--output", help="输出目录"),
    platform: str = typer.Option("all", "--platform", help="all/android/ios"),
    mode: str = typer.Option("static", "--mode", help="auto/static"),
) -> None:
    """批量检测 + 脱壳目录内所有安装包。"""
    configure_logging()
    root = Path(directory)
    if not root.is_dir():
        typer.echo(f"错误: 目录不存在 {directory}", err=True)
        raise typer.Exit(code=2)
    files = sorted(list(root.glob("*.apk")) + list(root.glob("*.ipa")))
    if platform == "android":
        files = [f for f in files if f.suffix == ".apk"]
    elif platform == "ios":
        files = [f for f in files if f.suffix == ".ipa"]
    if not files:
        typer.echo("目录内未发现 APK/IPA 文件")
        raise typer.Exit(code=0)

    dump_mode = DumpMode.FRIDA if mode.lower() in {"auto", "frida"} else DumpMode.STATIC
    results = []
    for f in files:
        started = time.time()
        try:
            target = DumpTarget(path=str(f))
            config = DumpConfig(output_dir=output, mode=dump_mode)
            if f.suffix == ".ipa":
                result = IOSDumper().dump(target, config)
            else:
                result = AndroidDumper().dump(target, config)
        except Exception as exc:  # noqa: BLE001 - 批量模式单文件失败不中断
            result = DumpResult(success=False, original_path=str(f))
            result.warn(f"处理失败: {exc}")
        results.append(result)
        typer.echo(
            f"[{'OK' if result.success else 'FAIL'}] {f.name} "
            f"protection={result.protection_type} "
            f"({result.duration_sec or round(time.time() - started, 3)}s)"
        )
        if result.warnings:
            typer.echo(f"    warn: {result.warnings[0]}")

    ok = sum(1 for r in results if r.success)
    typer.echo(f"批量完成: {ok}/{len(results)} 成功")
    raise typer.Exit(code=0 if ok == len(results) else 1)


#: 挂载点：mobile → shell
mobile_app = typer.Typer(help="移动端安全分析 (v4.0)")
mobile_app.add_typer(shell_app, name="shell")

if __name__ == "__main__":  # pragma: no cover
    mobile_app()
