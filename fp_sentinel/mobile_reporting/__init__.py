"""玄鉴 v4.0 移动端报告系统。

提供移动安全评估报告的多格式生成能力（Excel / Word / HTML），
报告数据模型由 :mod:`fp_sentinel.mobile_reporting.models` 提供，
截图完整性与正确性校验由 :mod:`fp_sentinel.mobile_reporting.core.screenshot_manager`
提供。模型尚未就绪时，formats 层使用内置存根保证可独立运行。

CLI 用法::

    python -m fp_sentinel.mobile_reporting.cli \\
        --format excel,word,html \\
        --output reports/out \\
        --sample
"""

from pathlib import Path

from .formats.base_generator import BaseReportGenerator, PathNotAllowedError

try:
    from .cvss import (  # type: ignore[no-redef]
        COMMON_FINDINGS,
        CvssV31,
        auto_score,
        explain_score,
        suggest_cvss,
    )
except ImportError:  # pragma: no cover
    COMMON_FINDINGS = {}  # type: ignore[assignment]
    CvssV31 = None  # type: ignore[assignment]
    auto_score = None  # type: ignore[assignment]
    explain_score = None  # type: ignore[assignment]
    suggest_cvss = None  # type: ignore[assignment]

__all__ = [
    "BaseReportGenerator",
    "PathNotAllowedError",
    "ExcelReportGenerator",
    "WordReportGenerator",
    "HtmlReportGenerator",
    "OPENPYXL_AVAILABLE",
    "generate_report",
    "CvssV31",
    "suggest_cvss",
    "auto_score",
    "explain_score",
    "COMMON_FINDINGS",
]

try:
    from .formats.excel_generator import (  # type: ignore[no-redef]
        OPENPYXL_AVAILABLE,
        ExcelReportGenerator,
    )
except ImportError:  # pragma: no cover
    OPENPYXL_AVAILABLE = False
    ExcelReportGenerator = None  # type: ignore[assignment,misc]

try:
    from .formats.word_generator import (  # type: ignore[no-redef]
        WordGenerator as WordReportGenerator,
    )
except ImportError:  # pragma: no cover
    WordReportGenerator = None  # type: ignore[assignment,misc]

try:
    from .formats.html_generator import (  # type: ignore[no-redef]
        HtmlGenerator as HtmlReportGenerator,
    )
except ImportError:  # pragma: no cover
    HtmlReportGenerator = None  # type: ignore[assignment,misc]


def _ensure_output_dir_allowed(
    output_dir: "Path", allowed_roots: "list[str] | tuple[str, ...]"
) -> None:
    """在创建输出目录前执行 S7 白名单预校验（与生成器校验逻辑一致）。

    Args:
        output_dir: 待创建的输出目录（相对路径按当前工作目录解析）。
        allowed_roots: 白名单根目录集合。

    Raises:
        PathNotAllowedError: 解析后的输出目录不在任何白名单根目录之内。
    """
    raw = Path(output_dir).expanduser()
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    resolved = raw.resolve(strict=False)
    roots = {
        Path(str(root)).expanduser().resolve(strict=False)
        for root in allowed_roots
    }
    for root in roots:
        try:
            resolved.relative_to(root)
            return
        except ValueError:
            continue
    raise PathNotAllowedError(
        f"S7 红线: 输出目录 {resolved} 不在白名单根目录 "
        f"{sorted(str(r) for r in roots)} 之内。"
    )


def generate_report(
    report: object,
    output_dir: str,
    formats: list[str] | tuple[str, ...] = ("excel", "word", "html"),
    allowed_roots: list[str] | tuple[str, ...] | None = None,
) -> dict[str, str]:
    """按指定格式集合生成报告，返回 ``{格式: 输出文件路径}``。

    Args:
        report: MobileSecurityReport 实例（共享模型或回退模型均可）。
        output_dir: 输出目录（须位于 S7 白名单内）。
        formats: ``excel`` / ``word`` / ``html`` 的任意组合。
        allowed_roots: 输出路径白名单根目录；为空时使用 output_dir 本身。

    Raises:
        ValueError: 格式名不受支持。
        RuntimeError: 对应格式生成器不可用（依赖缺失或导入失败）。
        PathNotAllowedError: 输出路径违反 S7 白名单。
    """
    roots = (
        [str(Path(output_dir).resolve())]
        if allowed_roots is None
        else list(allowed_roots)
    )
    out_dir = Path(output_dir)
    _ensure_output_dir_allowed(out_dir, roots)
    out_dir.mkdir(parents=True, exist_ok=True)

    registry = {
        "excel": (ExcelReportGenerator, ".xlsx"),
        "word": (WordReportGenerator, ".docx"),
        "html": (HtmlReportGenerator, ".html"),
    }
    generated: dict[str, str] = {}
    for fmt in formats:
        fmt = fmt.strip().lower()
        if fmt not in registry:
            raise ValueError(f"不支持的报告格式: {fmt}（可选 excel/word/html）")
        generator_cls, suffix = registry[fmt]
        if generator_cls is None:
            raise RuntimeError(f"格式 {fmt} 的生成器不可用，请检查第三方依赖是否安装")
        target = out_dir / f"mobile_security_report{suffix}"
        instance = generator_cls(allowed_roots=roots)
        path = instance.generate(report, target)
        generated[fmt] = str(path)
    return generated
