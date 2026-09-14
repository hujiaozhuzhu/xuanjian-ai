"""Excel 安全审计报告生成器（玄鉴AI / fp_sentinel）。

面向移动安全评估报告输出专业排版的 ``.xlsx`` 审计报告，
共 10 个工作表（顺序固定）：

封面 / 漏洞概览 / 漏洞清单 / 漏洞详情 / 证据明细 /
截图清单 / POC脚本 / EXP说明 / 复现步骤 / 附录。

安全与兼容约定：

- 继承 :class:`BaseReportGenerator`，输出路径强制经过 S7 白名单校验，
  违规抛出 :class:`~fp_sentinel.mobile_reporting.formats.`
  ``base_generator.PathNotAllowedError``；
- 数据模型兼容 ``models.report_models``（并行开发中）与
  ``_fallback_models`` 两种来源，字段一律通过 :func:`get_attr`
  鸭子类型读取；
- 生成完成后重新打开文件自检（sheet 数量、顺序与非空内容），
  失败抛出 :class:`ReportGenerationError`；
- openpyxl 缺失时抛出带安装命令的 :class:`ImportError`。
"""

from __future__ import annotations

import logging
import math
import struct
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from openpyxl.utils import get_column_letter

from .base_generator import BaseReportGenerator
from ._fallback_models import get_attr

try:
    from ..models.report_models import MobileSecurityReport
except ImportError:  # pragma: no cover - 模型包由其他 Agent 并行开发
    from ._fallback_models import MobileSecurityReport

try:
    from openpyxl import Workbook, load_workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.worksheet.worksheet import Worksheet

    OPENPYXL_AVAILABLE = True
    _OPENPYXL_IMPORT_ERROR: Optional[ImportError] = None
except ImportError as exc:  # pragma: no cover - 环境缺依赖时触发
    OPENPYXL_AVAILABLE = False
    _OPENPYXL_IMPORT_ERROR = exc

__all__ = [
    "ExcelGenerator",
    "ExcelReportGenerator",
    "ReportGenerationError",
    "OPENPYXL_AVAILABLE",
    "SHEET_ORDER",
    "SEVERITY_STYLES",
]

logger = logging.getLogger(__name__)

#: 工作表顺序（固定）
SHEET_ORDER: List[str] = [
    "封面",
    "漏洞概览",
    "漏洞清单",
    "漏洞详情",
    "证据明细",
    "截图清单",
    "POC脚本",
    "EXP说明",
    "复现步骤",
    "附录",
]

#: 严重度 -> (填充色, 字体色)
SEVERITY_STYLES: Dict[str, Tuple[str, str]] = {
    "CRITICAL": ("7B1D1D", "FFFFFF"),
    "HIGH": ("C0392B", "FFFFFF"),
    "MEDIUM": ("E67E22", "FFFFFF"),
    "LOW": ("F4D03F", "6B5900"),
    "INFO": ("2E86C1", "FFFFFF"),
}

SEVERITY_ORDER: Tuple[str, ...] = (
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
)

#: 附录术语表
GLOSSARY: List[Tuple[str, str]] = [
    ("CRITICAL/HIGH/MEDIUM/LOW/INFO", "漏洞严重等级，从致命到提示"),
    ("CWE", "Common Weakness Enumeration，通用缺陷枚举编号"),
    ("OWASP MASVS", "OWASP 移动应用安全验证标准"),
    ("POC", "Proof of Concept，无害概念验证脚本"),
    ("EXP", "Exploit，受控利用说明与利用链"),
    ("SHA256", "文件完整性哈希，用于证据防篡改校验"),
    ("覆盖率", "提供 POC/证据/复现步骤的漏洞占比"),
]

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_MONO_FONT = "Consolas"

_THIN = Side(style="thin", color="BFBFBF")
_BORDER = Border(left=_THIN, right=_THIN, top=_THIN, bottom=_THIN)
_HEADER_FILL = PatternFill("solid", fgColor="1F4E79")
_HEADER_FONT = Font(bold=True, color="FFFFFF", size=11)
_ALT_FILL = PatternFill("solid", fgColor="F2F6FA")
_LABEL_FILL = PatternFill("solid", fgColor="DDEBF7")
_CODE_FILL = PatternFill("solid", fgColor="F2F2F2")


class ReportGenerationError(RuntimeError):
    """报告生成或生成后自检失败。"""


def _display_width(text: str) -> int:
    """估算文本显示宽度（中日韩全角字符按 2 计）。"""

    def _line_width(line: str) -> int:
        return sum(
            2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
            for ch in line
        )

    return max((_line_width(seg) for seg in str(text).split("\n")), default=0)


def _png_size(path: Path) -> Optional[Tuple[int, int]]:
    """从 PNG 文件头解析宽高（IHDR），失败返回 ``None``。"""
    try:
        header = path.read_bytes()[:26]
    except OSError:
        return None
    if len(header) < 26 or not header.startswith(_PNG_SIGNATURE):
        return None
    if header[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", header[16:24])
    return width, height


def _truncate_lines(text: str, limit: int = 100) -> str:
    """超长文本按行截断并注明原始行数。"""
    text = str(text)
    lines = text.split("\n")
    if len(lines) <= limit:
        return text
    kept = "\n".join(lines[:limit])
    note = (
        f"\n... (内容已截断：原始共 {len(lines)} 行，"
        f"仅显示前 {limit} 行)"
    )
    return kept + note


class ExcelGenerator(BaseReportGenerator):
    """Excel（.xlsx）安全审计报告生成器。

    Args:
        allowed_roots: 输出路径白名单根目录集合（S7 红线）。
        allowed_suffixes: 允许的输出后缀，默认仅 ``.xlsx``。

    Raises:
        ImportError: openpyxl 未安装时抛出，附安装命令。
    """

    DEFAULT_ALLOWED_SUFFIXES = frozenset({".xlsx"})

    def __init__(
        self,
        allowed_roots: Optional[Sequence[Any]] = None,
        allowed_suffixes: Optional[Sequence[str]] = None,
    ) -> None:
        super().__init__(
            allowed_roots=allowed_roots,
            allowed_suffixes=allowed_suffixes or self.DEFAULT_ALLOWED_SUFFIXES,
        )
        if not OPENPYXL_AVAILABLE:
            raise ImportError(
                "生成 Excel 报告需要 openpyxl>=3.1，"
                "请执行: pip install openpyxl==3.1.5"
            ) from _OPENPYXL_IMPORT_ERROR

    # ────────────────────────── 对外接口 ──────────────────────────

    def get_format_name(self) -> str:
        """返回格式名称。"""
        return "Excel (.xlsx)"

    def generate(
        self, report: MobileSecurityReport, output_path: Path
    ) -> Path:
        """生成 Excel 审计报告。

        Args:
            report: 移动安全评估报告数据（兼容共享模型与回退模型）。
            output_path: 输出 ``.xlsx`` 路径（须经 S7 白名单校验）。

        Returns:
            实际生成的文件路径。

        Raises:
            PathNotAllowedError: 输出路径逃逸白名单或后缀不被允许。
            ReportGenerationError: 生成后自检失败。
        """
        target = self.validate_output_path(output_path)
        findings = self._collect_findings(report)
        wb = Workbook()
        wb.remove(wb.active)
        for name in SHEET_ORDER:
            wb.create_sheet(title=name)
        anchors = self._fill_detail(wb["漏洞详情"], report, findings)
        self._fill_cover(wb["封面"], report)
        self._fill_overview(wb["漏洞概览"], report, findings)
        self._fill_list(wb["漏洞清单"], findings, anchors)
        self._fill_evidence(wb["证据明细"], findings)
        self._fill_screenshots(wb["截图清单"], report, findings)
        self._fill_poc(wb["POC脚本"], findings)
        self._fill_exp(wb["EXP说明"], findings)
        self._fill_repro(wb["复现步骤"], findings)
        self._fill_appendix(wb["附录"], report, findings)
        wb.properties.title = str(
            get_attr(report, "title", "") or "移动安全审计报告"
        )
        wb.properties.creator = str(
            get_attr(report, "analyst", "") or "玄鉴AI"
        )
        for name in SHEET_ORDER:
            self._finalize_sheet(wb[name], skip_autosize=(name == "封面"))
        wb.save(target)
        self._verify_output(target)
        logger.info(
            "Excel 报告生成完成: %s (findings=%d)", target, len(findings)
        )
        return target

    # ────────────────────────── 数据规整 ──────────────────────────

    def _collect_findings(self, report: Any) -> List[Any]:
        """读取漏洞列表，兼容 ``findings`` 与 ``vulnerabilities`` 字段。"""
        findings = (
            get_attr(report, "findings", None)
            or get_attr(report, "vulnerabilities", [])
            or []
        )
        return list(findings)

    @staticmethod
    def _finding_id(finding: Any) -> str:
        """读取漏洞编号，兼容 ``finding_id`` / ``vuln_id``。"""
        fid = (
            get_attr(finding, "finding_id", None)
            or get_attr(finding, "vuln_id", "")
            or "FINDING-?"
        )
        return str(fid)

    @staticmethod
    def _norm_severity(finding: Any) -> str:
        """规整严重度为标准枚举，未知值降级为 INFO。"""
        sev = str(get_attr(finding, "severity", "INFO") or "INFO").upper()
        return sev if sev in SEVERITY_STYLES else "INFO"

    def _norm_evidence(self, finding: Any) -> List[Dict[str, str]]:
        """规整证据列表为 ``location/content/description/source`` 字典。

        兼容三种来源：字符串（存根模型）、Evidence 对象、字符串列表。
        """
        raw = get_attr(finding, "evidence", []) or []
        items: List[Dict[str, str]] = []
        if isinstance(raw, str):
            if raw.strip():
                items.append(
                    {
                        "location": str(
                            get_attr(finding, "location", "") or "-"
                        ),
                        "content": raw,
                        "description": "",
                        "source": "",
                    }
                )
            return items
        for ev in raw:
            if isinstance(ev, str):
                items.append(
                    {
                        "location": "-",
                        "content": ev,
                        "description": "",
                        "source": "",
                    }
                )
                continue
            items.append(
                {
                    "location": str(get_attr(ev, "location", "") or "-"),
                    "content": str(
                        get_attr(ev, "content", "")
                        or get_attr(ev, "code", "")
                        or ""
                    ),
                    "description": str(get_attr(ev, "description", "") or ""),
                    "source": str(get_attr(ev, "source", "") or ""),
                }
            )
        return items

    @staticmethod
    def _shot_count(finding: Any) -> int:
        """读取截图数量，兼容计数字段与截图列表。"""
        shots = get_attr(finding, "screenshots", []) or []
        explicit = get_attr(finding, "screenshot_count", 0)
        return int(explicit or 0) or len(shots)

    def _has_poc(self, finding: Any) -> bool:
        """判断是否携带 POC（字符串 / 列表 / 布尔字段均可）。"""
        poc = get_attr(finding, "poc", None)
        pocs = get_attr(finding, "pocs", []) or []
        return bool(poc) or bool(pocs) or bool(
            get_attr(finding, "has_poc", False)
        )

    def _has_exp(self, finding: Any) -> bool:
        """判断是否携带 EXP。"""
        exp = get_attr(finding, "exp", None)
        exps = get_attr(finding, "exploits", []) or []
        return bool(exp) or bool(exps) or bool(
            get_attr(finding, "has_exploit", False)
        )

    def _fix_text(self, finding: Any) -> str:
        """规整修复建议为编号列表文本。"""
        fixes = get_attr(finding, "fix_suggestions", []) or []
        if not fixes:
            rec = get_attr(finding, "fix_recommendation", "")
            fixes = [rec] if rec else []
        if not fixes:
            return "-"
        if isinstance(fixes, str):
            return fixes
        return "\n".join(
            f"{i}. {item}" for i, item in enumerate(fixes, 1)
        )

    def _first_fix(self, finding: Any) -> str:
        """取第一条修复建议作为默认缓解措施。"""
        fixes = get_attr(finding, "fix_suggestions", []) or []
        if fixes:
            return str(fixes[0])
        rec = get_attr(finding, "fix_recommendation", "")
        return str(rec) if rec else "-"

    # ────────────────────────── 通用绘制 ──────────────────────────

    @staticmethod
    def _apply_severity_style(
        cell: Any, severity: Optional[str] = None
    ) -> None:
        """为单元格应用严重度配色（深红/红/橙/黄/蓝 + 对比字色）。"""
        sev = (severity or str(cell.value or "INFO")).upper()
        if sev not in SEVERITY_STYLES:
            sev = "INFO"
        bg, fg = SEVERITY_STYLES[sev]
        cell.fill = PatternFill("solid", fgColor=bg)
        cell.font = Font(
            color=fg, bold=sev in ("CRITICAL", "HIGH"), size=11
        )
        cell.alignment = Alignment(horizontal="center", vertical="center")

    def _write_table(
        self,
        ws: Any,
        headers: Sequence[str],
        rows: List[List[Any]],
        start_row: int = 1,
        severity_col: Optional[int] = None,
        mono_cols: Sequence[int] = (),
    ) -> int:
        """写入表头与数据行（边框、隔行填充、长文本换行）。

        Args:
            ws: 目标工作表。
            headers: 表头文本。
            rows: 数据行（每行长度应与表头一致）。
            start_row: 起始行号（表头所在行）。
            severity_col: 需要应用严重度配色的列（0 基）。
            mono_cols: 使用等宽字体 + 浅灰底的列（0 基）。

        Returns:
            数据区之后的下一个可用行号。
        """
        mono = set(mono_cols)
        for col, name in enumerate(headers, start=1):
            cell = ws.cell(row=start_row, column=col, value=name)
            cell.font = _HEADER_FONT
            cell.fill = _HEADER_FILL
            cell.border = _BORDER
            cell.alignment = Alignment(
                horizontal="center", vertical="center"
            )
        row_idx = start_row + 1
        for i, values in enumerate(rows):
            for col, value in enumerate(values, start=1):
                cell = ws.cell(row=row_idx, column=col, value=value)
                cell.border = _BORDER
                if i % 2 == 1:
                    cell.fill = _ALT_FILL
                text = "" if value is None else str(value)
                if col - 1 in mono:
                    cell.font = Font(name=_MONO_FONT, size=10)
                    cell.fill = _CODE_FILL
                    cell.alignment = Alignment(
                        horizontal="left", vertical="top", wrap_text=True
                    )
                else:
                    wrap = "\n" in text or _display_width(text) > 36
                    cell.alignment = Alignment(
                        vertical="top", wrap_text=wrap
                    )
            if severity_col is not None:
                self._apply_severity_style(
                    ws.cell(row=row_idx, column=severity_col + 1)
                )
            row_idx += 1
        return row_idx

    def _label_value_row(
        self, ws: Any, row: int, label: str, value: Any, span: int = 10
    ) -> None:
        """写入一行"标签 + 合并值单元格"（用于封面/详情/附录）。"""
        lab = ws.cell(row=row, column=1, value=label)
        lab.font = Font(bold=True, size=11)
        lab.fill = _LABEL_FILL
        lab.alignment = Alignment(vertical="top")
        ws.merge_cells(
            start_row=row, start_column=2, end_row=row, end_column=span
        )
        val = ws.cell(row=row, column=2, value=value)
        val.alignment = Alignment(vertical="top", wrap_text=True)
        for col in range(1, span + 1):
            ws.cell(row=row, column=col).border = _BORDER

    def _section_header(self, ws: Any, row: int, title: str, span: int) -> int:
        """写入附录小节标题行，返回下一行号。"""
        ws.merge_cells(
            start_row=row, start_column=1, end_row=row, end_column=span
        )
        cell = ws.cell(row=row, column=1, value=title)
        cell.font = _HEADER_FONT
        cell.fill = _HEADER_FILL
        cell.alignment = Alignment(vertical="center")
        for col in range(1, span + 1):
            ws.cell(row=row, column=col).border = _BORDER
        return row + 1

    # ────────────────────────── 各工作表 ──────────────────────────

    def _fill_cover(self, ws: Any, report: Any) -> None:
        """填充封面：大标题、密级、目标 APP、时间与署名信息。"""
        title = str(
            get_attr(report, "title", "") or "移动应用安全审计报告"
        )
        subtitle = str(
            get_attr(report, "subtitle", "")
            or "代码安全审计与渗透测试评估"
        )
        ws.merge_cells("A1:F1")
        head = ws["A1"]
        head.value = title
        head.font = Font(size=20, bold=True, color="FFFFFF")
        head.fill = PatternFill("solid", fgColor="1F4E79")
        head.alignment = Alignment(horizontal="center", vertical="center")
        ws.row_dimensions[1].height = 46
        ws.merge_cells("A2:F2")
        sub = ws["A2"]
        sub.value = subtitle
        sub.font = Font(size=11, italic=True, color="44546A")
        sub.fill = PatternFill("solid", fgColor="DDEBF7")
        sub.alignment = Alignment(horizontal="center", vertical="center")
        ws.row_dimensions[2].height = 24

        target = get_attr(report, "target", None)

        def tfield(name: str) -> str:
            if target is not None:
                value = get_attr(target, name, "")
                if value:
                    return str(value)
            return str(get_attr(report, name, "") or "")

        app_name = tfield("app_name") or tfield("package_name") or "-"
        version = tfield("version_name") or tfield("version_code") or "-"
        pairs: List[Tuple[str, str]] = [
            ("密级", str(
                get_attr(report, "classification", "") or "内部资料"
            )),
            ("应用名称", app_name),
            ("包名", tfield("package_name") or "-"),
            ("版本", version),
            ("SHA256", tfield("sha256") or "-"),
            ("扫描时间", str(get_attr(report, "scan_date", "") or "-")),
            ("工具版本", str(
                get_attr(report, "tool_version", "")
                or get_attr(report, "report_version", "")
                or "-"
            )),
            ("生成时间", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            ("作者", str(
                get_attr(report, "analyst", "")
                or get_attr(report, "company", "")
                or "玄鉴AI"
            )),
            ("评估机构", str(get_attr(report, "company", "") or "-")),
        ]
        row = 4
        for label, value in pairs:
            self._label_value_row(ws, row, label, value, span=6)
            row += 1
        for col, width in {1: 16, 2: 60, 3: 12, 4: 12, 5: 12, 6: 12}.items():
            ws.column_dimensions[get_column_letter(col)].width = width

    def _fill_overview(
        self, ws: Any, report: Any, findings: List[Any]
    ) -> None:
        """填充漏洞概览：severity 分布（条件配色）与分类分布。"""
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for finding in findings:
            counts[self._norm_severity(finding)] += 1
        if not findings:
            stats = get_attr(report, "statistics", None)
            sev_counts = get_attr(stats, "severity_counts", {}) if stats \
                else {}
            if isinstance(sev_counts, dict):
                for key, value in sev_counts.items():
                    upper = str(key).upper()
                    if upper in counts:
                        counts[upper] = int(value)
        total = sum(counts.values())
        rows = [
            [sev, counts[sev],
             f"{counts[sev] / total * 100:.1f}%" if total else "-"]
            for sev in SEVERITY_ORDER
        ]
        next_row = self._write_table(
            ws, ["等级", "数量", "占比"], rows
        )
        for offset, sev in enumerate(SEVERITY_ORDER):
            self._apply_severity_style(
                ws.cell(row=2 + offset, column=1), severity=sev
            )
            self._apply_severity_style(
                ws.cell(row=2 + offset, column=2), severity=sev
            )

        cat_counts: Dict[str, int] = {}
        for finding in findings:
            cat = str(get_attr(finding, "category", "") or "未分类")
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        row = next_row + 1
        row = self._section_header(ws, row, "分类分布", span=3)
        cat_rows = [
            [cat, n, f"{n / total * 100:.1f}%" if total else "-"]
            for cat, n in sorted(
                cat_counts.items(), key=lambda kv: -kv[1]
            )
        ]
        row = self._write_table(
            ws, ["分类", "数量", "占比"], cat_rows, start_row=row
        )

        overall = str(get_attr(report, "overall_assessment", "") or "")
        if overall:
            row += 1
            row = self._section_header(ws, row, "总体评估", span=3)
            ws.merge_cells(
                start_row=row, start_column=1,
                end_row=row, end_column=3,
            )
            cell = ws.cell(row=row, column=1, value=overall)
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            for col in range(1, 4):
                ws.cell(row=row, column=col).border = _BORDER

    def _fill_list(
        self,
        ws: Any,
        findings: List[Any],
        anchors: Dict[str, int],
    ) -> None:
        """填充漏洞清单，编号单元格超链接到漏洞详情对应区块。"""
        headers = [
            "编号", "标题", "等级", "CWE", "OWASP MASVS",
            "分类", "证据数", "截图数", "有POC", "有EXP",
        ]
        rows = []
        for finding in findings:
            rows.append([
                self._finding_id(finding),
                str(get_attr(finding, "title", "") or "-"),
                self._norm_severity(finding),
                str(get_attr(finding, "cwe", "") or "-"),
                str(get_attr(finding, "masvs", "") or "-"),
                str(get_attr(finding, "category", "") or "未分类"),
                len(self._norm_evidence(finding)),
                self._shot_count(finding),
                "是" if self._has_poc(finding) else "否",
                "是" if self._has_exp(finding) else "否",
            ])
        self._write_table(ws, headers, rows, severity_col=2)
        for i, finding in enumerate(findings):
            fid = self._finding_id(finding)
            cell = ws.cell(row=2 + i, column=1)
            cell.hyperlink = f"#'漏洞详情'!A{anchors.get(fid, 1)}"
            cell.font = Font(color="0563C1", underline="single", bold=True)

    def _fill_detail(
        self, ws: Any, report: Any, findings: List[Any]
    ) -> Dict[str, int]:
        """填充漏洞详情区块，返回 ``{漏洞编号: 区块标题行号}`` 锚点表。"""
        tool_version = str(
            get_attr(report, "tool_version", "")
            or get_attr(report, "report_version", "")
            or "-"
        )
        anchors: Dict[str, int] = {}
        row = 1
        for finding in findings:
            fid = self._finding_id(finding)
            title = str(get_attr(finding, "title", "") or "-")
            anchors[fid] = row
            ws.merge_cells(
                start_row=row, start_column=1,
                end_row=row, end_column=10,
            )
            head = ws.cell(row=row, column=1, value=f"{fid}  {title}")
            bg, _ = SEVERITY_STYLES[self._norm_severity(finding)]
            head.fill = PatternFill("solid", fgColor=bg)
            head.font = Font(bold=True, color="FFFFFF", size=12)
            head.alignment = Alignment(vertical="center")
            ws.row_dimensions[row].height = 24
            row += 1
            blocks: List[Tuple[str, str]] = [
                ("描述", str(get_attr(finding, "description", "") or "-")),
                ("影响", str(get_attr(finding, "impact", "") or "-")),
                ("修复建议", self._fix_text(finding)),
                ("置信度", str(
                    get_attr(finding, "confidence", "") or "未标注"
                )),
                ("工具版本", tool_version),
                ("参考链接", "\n".join(
                    str(ref)
                    for ref in (get_attr(finding, "references", []) or [])
                ) or "-"),
            ]
            for label, value in blocks:
                self._label_value_row(ws, row, label, value, span=10)
                row += 1
            row += 1  # 区块间空行
        return anchors

    def _fill_evidence(self, ws: Any, findings: List[Any]) -> None:
        """填充证据明细：代码片段使用等宽字体 + 浅灰底。"""
        rows = []
        for finding in findings:
            fid = self._finding_id(finding)
            components = get_attr(finding, "components", []) or []
            default_source = str(
                components[0]
                if components
                else get_attr(finding, "component", "") or "-"
            )
            evidence = self._norm_evidence(finding)
            if not evidence:
                rows.append(
                    [fid, "-", "-", "-", "-", "（本条漏洞无证据记录）"]
                )
                continue
            for i, ev in enumerate(evidence, 1):
                rows.append([
                    fid,
                    f"EV-{fid}-{i:02d}",
                    ev["location"],
                    ev["content"] or "-",
                    ev["source"] or default_source,
                    ev["description"] or "-",
                ])
        self._write_table(
            ws,
            ["finding_id", "证据ID", "位置(文件:行号)",
             "代码片段", "来源", "说明"],
            rows,
            mono_cols=(3,),
        )

    @staticmethod
    def _shot_status(shot: Any, sha256: str) -> str:
        """规整截图校验状态为带符号的可读文本。"""
        status = str(
            get_attr(shot, "verification_status", "") or ""
        ).strip().lower()
        if status in ("verified", "pass", "ok", "通过", "success"):
            return "✓已验证"
        if status in ("problem", "fail", "failed", "mismatch", "未通过"):
            return "✗未通过（哈希校验失败）"
        if sha256:
            return "✓已验证（SHA256 已记录）"
        return "✗未验证（缺少校验信息）"

    def _norm_shot(self, shot: Any, finding_id: str) -> List[Any]:
        """规整截图记录为截图清单行（兼容两种截图模型）。"""
        path = str(
            get_attr(shot, "file_path", None)
            or get_attr(shot, "path", "")
            or "-"
        )
        caption = str(
            get_attr(shot, "caption", None)
            or get_attr(shot, "description", "")
            or ""
        )
        sha = str(get_attr(shot, "sha256", "") or "")
        width = get_attr(shot, "width", None)
        height = get_attr(shot, "height", None)
        wh = f"{width}x{height}" if width and height else str(
            get_attr(shot, "resolution", "") or ""
        )
        if not wh and path != "-":
            size = _png_size(Path(path))
            wh = f"{size[0]}x{size[1]}" if size else "-"
        fmt = str(get_attr(shot, "format", "") or "").upper()
        if not fmt and path != "-":
            fmt = Path(path).suffix.lstrip(".").upper()
        sid = str(
            get_attr(shot, "screenshot_id", None)
            or get_attr(shot, "shot_id", "")
            or f"SHOT-{Path(path).stem or finding_id}"
        )
        return [
            sid,
            path,
            caption or "-",
            sha[:16] if sha else "-",
            wh or "-",
            fmt or "-",
            self._shot_status(shot, sha),
            finding_id,
        ]

    def _fill_screenshots(
        self, ws: Any, report: Any, findings: List[Any]
    ) -> None:
        """填充截图清单（含 PNG 尺寸解析与校验状态）。"""
        rows = []
        for finding in findings:
            fid = self._finding_id(finding)
            for shot in (get_attr(finding, "screenshots", []) or []):
                rows.append(self._norm_shot(shot, fid))
        for shot in (get_attr(report, "screenshots", []) or []):
            rows.append(self._norm_shot(shot, "全局"))
        if not rows:
            rows.append(["-", "-", "-", "-", "-", "-",
                         "✗未验证（无截图记录）", "-"])
        self._write_table(
            ws,
            ["截图ID", "路径", "标题(说明)", "SHA256前16位",
             "宽x高", "格式", "校验状态", "所属finding"],
            rows,
        )

    def _norm_poc_row(
        self, fid: str, item: Any, idx: int
    ) -> List[Any]:
        """规整单条 POC 为 POC脚本 行（兼容字符串与 POC 对象）。"""
        if isinstance(item, str):
            return [
                fid,
                f"POC-{fid}-{idx:02d}",
                "命令/脚本",
                "无害验证",
                "-",
                _truncate_lines(item),
            ]
        name = str(
            get_attr(item, "name", "") or f"POC-{fid}-{idx:02d}"
        )
        ptype = str(get_attr(item, "poc_type", "") or "script")
        safety = get_attr(item, "safety_valid", None)
        level = "✓安全(无害)" if safety else "✗未审核"
        path = str(
            get_attr(item, "path", "")
            or get_attr(item, "script_path", "")
            or "-"
        )
        code = str(
            get_attr(item, "code", "") or get_attr(item, "content", "") or ""
        )
        return [fid, name, ptype, level, path, _truncate_lines(code)]

    def _fill_poc(self, ws: Any, findings: List[Any]) -> None:
        """填充 POC 脚本表：脚本内容等宽展示，超 100 行截断注明。"""
        rows = []
        for finding in findings:
            fid = self._finding_id(finding)
            poc = get_attr(finding, "poc", None)
            items: List[Any] = []
            if isinstance(poc, (list, tuple)):
                items.extend(poc)
            elif poc:
                items.append(poc)
            items.extend(get_attr(finding, "pocs", []) or [])
            for i, item in enumerate(items, 1):
                rows.append(self._norm_poc_row(fid, item, i))
        if not rows:
            rows.append(["-", "-", "-", "-", "-", "（无 POC 记录）"])
        self._write_table(
            ws,
            ["finding_id", "POC名称", "类型", "安全等级",
             "脚本路径", "脚本内容"],
            rows,
            mono_cols=(5,),
        )

    def _norm_exp_row(
        self, fid: str, finding: Any, item: Any
    ) -> List[Any]:
        """规整单条 EXP 为 EXP说明 行（兼容字符串与 EXP 对象）。"""
        if isinstance(item, str):
            return [
                fid,
                "手工利用",
                "具备漏洞可达路径",
                item,
                str(get_attr(finding, "impact", "") or "-"),
                self._first_fix(finding),
            ]
        name = str(
            get_attr(item, "name", "")
            or get_attr(item, "exp_type", "")
            or "受控利用"
        )
        pre = str(get_attr(item, "preconditions", "") or "具备漏洞可达路径")
        steps = get_attr(item, "chain_steps", []) or []
        steps_text = str(
            get_attr(item, "steps", "")
            or ("\n".join(str(s) for s in steps) if steps else "")
            or get_attr(item, "code", "")
            or "-"
        )
        impact = str(
            get_attr(item, "impact", "")
            or get_attr(finding, "impact", "")
            or "-"
        )
        mitigation = str(
            get_attr(item, "mitigation", "") or self._first_fix(finding)
        )
        return [fid, name, pre, steps_text, impact, mitigation]

    def _fill_exp(self, ws: Any, findings: List[Any]) -> None:
        """填充 EXP 说明表。"""
        rows = []
        for finding in findings:
            fid = self._finding_id(finding)
            exp = get_attr(finding, "exp", None)
            items: List[Any] = []
            if isinstance(exp, (list, tuple)):
                items.extend(exp)
            elif exp:
                items.append(exp)
            items.extend(get_attr(finding, "exploits", []) or [])
            for item in items:
                rows.append(self._norm_exp_row(fid, finding, item))
        if not rows:
            rows.append(["-", "-", "-", "-", "-", "（无 EXP 记录）"])
        self._write_table(
            ws,
            ["finding_id", "名称", "前提条件", "利用步骤",
             "影响", "缓解措施"],
            rows,
        )

    def _fill_repro(self, ws: Any, findings: List[Any]) -> None:
        """填充复现步骤表：复现命令使用等宽字体。"""
        rows = []
        for finding in findings:
            fid = self._finding_id(finding)
            steps = get_attr(finding, "reproduction_steps", []) or []
            for i, step in enumerate(steps, 1):
                if isinstance(step, str):
                    rows.append([fid, i, step, "-", "-", "-"])
                    continue
                rows.append([
                    fid,
                    i,
                    str(get_attr(step, "action", "") or "-"),
                    str(get_attr(step, "expected", "") or "-"),
                    str(get_attr(step, "actual", "") or "-"),
                    str(get_attr(step, "command", "") or "-"),
                ])
        if not rows:
            rows.append(["-", "-", "（无复现步骤记录）", "-", "-", "-"])
        self._write_table(
            ws,
            ["finding_id", "步骤号", "操作", "预期结果",
             "实际结果", "复现命令"],
            rows,
            mono_cols=(5,),
        )

    def _env_pairs(self, report: Any) -> List[Tuple[str, str]]:
        """规整环境信息为键值对（兼容 dict 与 EnvironmentInfo）。"""
        env = get_attr(report, "environment", None)
        pairs: List[Tuple[str, str]] = []
        if isinstance(env, dict):
            pairs.extend((str(k), str(v)) for k, v in env.items())
        elif env is not None:
            for key in ("os_name", "os_version",
                        "python_version", "device"):
                value = get_attr(env, key, "")
                if value:
                    pairs.append((key, str(value)))
            for key in ("tools", "dependencies", "cli_commands"):
                seq = get_attr(env, key, []) or []
                if seq:
                    pairs.append((key, "; ".join(str(x) for x in seq)))
        cli = get_attr(report, "cli_commands", []) or []
        if cli:
            pairs.append(("扫描命令", "; ".join(str(x) for x in cli)))
        return pairs or [("环境信息", "-")]

    def _coverage_pairs(
        self, report: Any, findings: List[Any]
    ) -> List[Tuple[str, str]]:
        """计算覆盖率指标（含工具统计字段兜底）。"""
        total = len(findings)

        def ratio(predicate: Any) -> str:
            if not total:
                return "-"
            hit = sum(1 for f in findings if predicate(f))
            return f"{hit / total * 100:.1f}% ({hit}/{total})"

        pairs: List[Tuple[str, str]] = [
            ("漏洞总数", str(total)),
            ("有POC占比", ratio(self._has_poc)),
            ("有EXP占比", ratio(self._has_exp)),
            ("有证据占比", ratio(lambda f: bool(self._norm_evidence(f)))),
            ("有复现步骤占比", ratio(
                lambda f: bool(get_attr(f, "reproduction_steps", []))
            )),
            ("有截图占比", ratio(lambda f: self._shot_count(f) > 0)),
        ]
        stats = get_attr(report, "statistics", None)
        if stats is not None:
            cov = get_attr(stats, "coverage_rate", None)
            if cov is not None:
                text = (
                    f"{float(cov) * 100:.1f}%"
                    if 0 <= float(cov) <= 1 else str(cov)
                )
                pairs.append(("工具覆盖率", text))
        return pairs

    def _fill_appendix(
        self, ws: Any, report: Any, findings: List[Any]
    ) -> None:
        """填充附录：环境信息、术语表与覆盖率指标。"""
        row = self._section_header(ws, 1, "一、环境信息", span=4)
        for label, value in self._env_pairs(report):
            self._label_value_row(ws, row, label, value, span=4)
            row += 1
        row += 1
        row = self._section_header(ws, row, "二、术语表", span=4)
        row = self._write_table(
            ws, ["术语", "说明"],
            [[term, desc] for term, desc in GLOSSARY],
            start_row=row,
        )
        row += 1
        row = self._section_header(ws, row, "三、覆盖率指标", span=4)
        for label, value in self._coverage_pairs(report, findings):
            self._label_value_row(ws, row, label, value, span=4)
            row += 1

    # ─────────────────────── 排版与自检 ───────────────────────

    def _autosize(self, ws: Any) -> None:
        """按内容自适应估算列宽（上限 60 字符，下限 8）。"""
        for col_idx, cells in enumerate(ws.columns, start=1):
            letter = get_column_letter(col_idx)
            width = 8.0
            for cell in cells:
                if cell.value is None:
                    continue
                w = float(_display_width(str(cell.value)))
                if cell.alignment is not None and cell.alignment.wrap_text:
                    w = min(w, 40.0)
                width = max(width, w)
            ws.column_dimensions[letter].width = min(width, 60.0)

    def _adjust_row_heights(self, ws: Any) -> None:
        """依据换行文本与列宽估算行高，保证长文本完整可见。"""
        merged_width: Dict[Tuple[int, int], float] = {}
        for rng in ws.merged_cells.ranges:
            total = sum(
                ws.column_dimensions[get_column_letter(c)].width or 10.0
                for c in range(rng.min_col, rng.max_col + 1)
            )
            merged_width[(rng.min_row, rng.min_col)] = total
        for row in ws.iter_rows():
            lines_needed = 1
            for cell in row:
                if cell.value is None:
                    continue
                if not (cell.alignment and cell.alignment.wrap_text):
                    continue
                width = merged_width.get(
                    (cell.row, cell.column),
                    ws.column_dimensions[cell.column_letter].width or 10.0,
                )
                width = max(width - 1.0, 4.0)
                text = str(cell.value)
                needed = sum(
                    max(1, math.ceil(_display_width(seg) / width))
                    for seg in text.split("\n")
                )
                lines_needed = max(lines_needed, needed)
            if lines_needed > 1:
                height = min(14.0 * lines_needed + 6.0, 220.0)
                existing = ws.row_dimensions[row[0].row].height
                if existing is None or existing < height:
                    ws.row_dimensions[row[0].row].height = height

    def _finalize_sheet(self, ws: Worksheet, skip_autosize: bool) -> None:
        """统一收尾：冻结首行、列宽自适应、行高调整。"""
        ws.freeze_panes = "A2"
        if not skip_autosize:
            self._autosize(ws)
        self._adjust_row_heights(ws)

    def _verify_output(self, path: Path) -> None:
        """生成后自检：重新打开文件，校验 sheet 数量、顺序与非空内容。

        Raises:
            ReportGenerationError: 文件不可读、sheet 缺失或内容为空。
        """
        try:
            wb = load_workbook(path)
        except Exception as exc:  # noqa: BLE001 - 自检需捕获所有损坏情形
            raise ReportGenerationError(
                f"生成文件无法重新打开: {path} ({exc})"
            ) from exc
        try:
            if wb.sheetnames != SHEET_ORDER:
                raise ReportGenerationError(
                    f"自检失败: 工作表数量或顺序异常: {wb.sheetnames}"
                )
            for name in SHEET_ORDER:
                ws = wb[name]
                has_content = any(
                    cell.value not in (None, "")
                    for row in ws.iter_rows(max_row=min(ws.max_row, 30))
                    for cell in row
                )
                if not has_content:
                    raise ReportGenerationError(
                        f"自检失败: 工作表 {name!r} 无内容"
                    )
        finally:
            wb.close()


#: 兼容 formats 包 ``__init__`` 导入的历史命名
ExcelReportGenerator = ExcelGenerator
