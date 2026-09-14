"""报告输出格式层。

- :class:`BaseReportGenerator`：生成器基类（含 S7 红线路径白名单校验）。
- :class:`ExcelReportGenerator`：Excel 报告生成器（openpyxl）。
- :class:`WordReportGenerator`：Word 报告生成器（python-docx）。
- :class:`HtmlReportGenerator`：HTML 单文件自包含报告生成器。

各生成器在对应第三方依赖缺失时导入即失败并给出安装指引；
``*_AVAILABLE`` 标记用于上层 UI 预判可选格式。
"""

from .base_generator import BaseReportGenerator, PathNotAllowedError

__all__ = [
    "BaseReportGenerator",
    "PathNotAllowedError",
    "ExcelReportGenerator",
    "WordReportGenerator",
    "HtmlReportGenerator",
    "OPENPYXL_AVAILABLE",
]

from .excel_generator import (  # noqa: E402  保持统一导出顺序
    OPENPYXL_AVAILABLE,
    ExcelReportGenerator,
)

try:
    from .word_generator import WordGenerator as WordReportGenerator  # type: ignore[no-redef]
except ImportError:  # pragma: no cover - python-docx 缺失
    WordReportGenerator = None  # type: ignore[assignment,misc]

try:
    from .html_generator import HtmlGenerator as HtmlReportGenerator  # type: ignore[no-redef]
except ImportError:  # pragma: no cover - 模板异常
    HtmlReportGenerator = None  # type: ignore[assignment,misc]
