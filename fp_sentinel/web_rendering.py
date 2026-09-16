"""DOCX 预览的零外部依赖降级渲染器。

提供 :class:`DocxPreview`，按优先级自动选择渲染后端：

1. LibreOffice headless（soffice --headless --convert-to）；
2. Edge/Chrome headless print-to-pdf；
3. 纯 python-docx → 极简 HTML 降级（零外部依赖）。

任何外部工具缺失均不抛异常，只记录 warnings 并返回当前可用降级产物。
输出路径受 S7 红线白名单约束（通过 ``allowed_roots`` 限制）。
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union

from fp_sentinel.mobile_reporting.formats.base_generator import PathNotAllowedError

logger = logging.getLogger(__name__)

__all__ = ["DocxPreview"]

#: Edge / Chrome headless 候选路径（Windows）
_BROWSER_CANDIDATES: List[str] = [
    r"C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    r"C:/Program Files/Microsoft/Edge/Application/msedge.exe",
    r"C:/Program Files/Google/Chrome/Application/chrome.exe",
    r"C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
]

#: 默认输出后缀白名单
_DEFAULT_ALLOWED_SUFFIXES = frozenset({".html", ".pdf", ".png"})


def _resolve_within_whitelist(
    path: Path,
    allowed_roots: Iterable[Path],
) -> Path:
    """解析路径并校验其落在至少一个白名单根目录之内。

    Args:
        path: 待校验路径（相对路径按当前工作目录解析）。
        allowed_roots: 白名单根目录集合。

    Returns:
        解析后的绝对路径。

    Raises:
        PathNotAllowedError: 路径逃逸出白名单。
    """
    raw = path
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    resolved = raw.expanduser().resolve(strict=False)
    roots = {r.expanduser().resolve(strict=False) for r in allowed_roots}
    for root in roots:
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    raise PathNotAllowedError(
        f"S7 红线: 输出路径 {resolved} 不在白名单根目录 "
        f"{sorted(str(r) for r in roots)} 之内。"
    )


class DocxPreview:
    """DOCX 预览渲染器（多后端自动降级）。

    Args:
        allowed_roots: 输出路径白名单根目录；仅当前工作目录时可不传。
    """

    def __init__(
        self,
        allowed_roots: Optional[Iterable[Union[str, Path]]] = None,
    ) -> None:
        roots = list(allowed_roots) if allowed_roots is not None else [Path.cwd()]
        if not roots:
            roots = [Path.cwd()]
        self._allowed_roots: List[Path] = [
            Path(r).expanduser().resolve(strict=False) for r in roots
        ]

    # ─────────────────────────── 公开接口 ───────────────────────────

    def to_html(
        self,
        docx_path: Union[str, Path],
        out_html: Optional[Union[str, Path]] = None,
    ) -> str:
        """将 docx 转为极简 HTML（inline CSS）。

        仅依赖 python-docx，零外部依赖。

        Args:
            docx_path: 输入 docx 路径。
            out_html: 若给定，HTML 写入该路径并返回路径 str；
                否则返回 HTML 字符串。

        Returns:
            HTML 字符串，或写入 out_html 后的路径字符串。
        """
        from docx import Document

        doc = Document(str(docx_path))
        parts: List[str] = []
        parts.append("<!DOCTYPE html>")
        parts.append('<html lang="zh-CN"><head><meta charset="utf-8">')
        parts.append(
            "<style>"
            "body{font-family:sans-serif;margin:24px;line-height:1.6;}"
            "h1,h2,h3{color:#1a1a1a;} "
            "table{border-collapse:collapse;width:100%;margin:12px 0;}"
            "th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;}"
            "th{background:#f5f5f5;}"
            "</style>"
            "</head><body>"
        )

        for para in doc.paragraphs:
            text = para.text.strip()
            if not text:
                continue
            style = (para.style.name or "").lower() if para.style else ""
            if "heading 1" in style or style == "title":
                parts.append(f"<h1>{_escape_html(text)}</h1>")
            elif "heading 2" in style:
                parts.append(f"<h2>{_escape_html(text)}</h2>")
            elif "heading 3" in style:
                parts.append(f"<h3>{_escape_html(text)}</h3>")
            else:
                parts.append(f"<p>{_escape_html(text)}</p>")

        for table in doc.tables:
            parts.append("<table>")
            for row_idx, row in enumerate(table.rows):
                parts.append("<tr>")
                for cell in row.cells:
                    cell_text = cell.text.strip()
                    if row_idx == 0:
                        parts.append(f"<th>{_escape_html(cell_text)}</th>")
                    else:
                        parts.append(f"<td>{_escape_html(cell_text)}</td>")
                parts.append("</tr>")
            parts.append("</table>")

        parts.append("</body></html>")
        html = "\n".join(parts)

        if out_html is not None:
            out_path = _resolve_within_whitelist(
                Path(out_html), self._allowed_roots
            )
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(html, encoding="utf-8")
            logger.info("HTML 已写入: %s", out_path)
            return str(out_path)

        return html

    def render(
        self,
        docx_path: Union[str, Path],
        out_path: Optional[Union[str, Path]] = None,
        fmt: str = "auto",
        scale: float = 1.5,
    ) -> dict:
        """按 fmt / 环境可用性选择渲染后端。

        返回 dict: ``{"format", "path", "backend", "warnings"}``。

        Args:
            docx_path: 输入 docx 路径。
            out_path: 输出路径；若 None 则使用 docx 同级目录同名的目标格式。
            fmt: ``auto`` / ``html`` / ``pdf`` / ``png``。
            scale: headless 打印缩放系数（仅 Edge/Chrome 后端使用）。

        Returns:
            结果字典，必含 format / path / backend / warnings 四个键。
        """
        docx_path = Path(docx_path)
        warnings: List[str] = []

        if not docx_path.exists():
            raise FileNotFoundError(f"docx 文件不存在: {docx_path}")

        # 确定目标格式
        if fmt == "auto":
            target_suffixes = [".pdf", ".html"]
        elif fmt == "html":
            target_suffixes = [".html"]
        elif fmt == "png":
            target_suffixes = [".png", ".html"]
        else:
            target_suffixes = [".pdf", ".html"]

        # 确定输出路径
        if out_path is not None:
            resolved_out = _resolve_within_whitelist(
                Path(out_path), self._allowed_roots
            )
        else:
            resolved_out = None

        # 尝试 LibreOffice
        if _has_libreoffice():
            for suffix in target_suffixes:
                if suffix == ".html":
                    continue
                target = resolved_out or docx_path.with_suffix(suffix)
                target = _resolve_within_whitelist(target, self._allowed_roots)
                try:
                    result = _render_libreoffice(docx_path, target)
                    logger.info("LibreOffice 渲染成功: %s", result)
                    return {
                        "format": suffix.lstrip("."),
                        "path": result,
                        "backend": "libreoffice",
                        "warnings": warnings,
                    }
                except Exception as exc:  # noqa: BLE001
                    logger.warning("LibreOffice 渲染失败: %s", exc)
                    warnings.append(f"LibreOffice 渲染失败: {exc}")

        # 尝试 Edge/Chrome headless
        browser = _find_browser()
        if browser and ".pdf" in target_suffixes:
            target = resolved_out or docx_path.with_suffix(".pdf")
            target = _resolve_within_whitelist(target, self._allowed_roots)
            try:
                result = _render_browser_pdf(
                    docx_path, target, browser, scale=scale
                )
                logger.info("浏览器 headless 渲染成功: %s", result)
                return {
                    "format": "pdf",
                    "path": result,
                    "browser": browser,
                    "backend": "browser-headless",
                    "warnings": warnings,
                }
            except Exception as exc:  # noqa: BLE001
                logger.warning("浏览器 headless 渲染失败: %s", exc)
                warnings.append(f"浏览器 headless 渲染失败: {exc}")

        # 降级到 HTML
        target = resolved_out or docx_path.with_suffix(".html")
        if target.suffix.lower() != ".html":
            target = target.with_suffix(".html")
        target = _resolve_within_whitelist(target, self._allowed_roots)
        html_path = self.to_html(docx_path, out_html=target)
        warn_msg = (
            "安装 LibreOffice 可转 PDF/PNG："
            "winget install TheDocumentFoundation.LibreOffice"
        )
        warnings.append(warn_msg)
        logger.info("降级 HTML 渲染: %s", html_path)
        return {
            "format": "html",
            "path": Path(html_path),
            "backend": "native-html",
            "warnings": warnings,
        }

    def render_findings_preview(
        self,
        findings: Union[List[dict], object],
        out_path: Optional[Union[str, Path]] = None,
    ) -> dict:
        """专用入口：把发现清单写成临时 docx，再走 :meth:`render`。

        供结果页内嵌预览。

        Args:
            findings: 发现清单 dict 列表，或 MobileSecurityReport 实例。
                每个 dict 至少需有 ``title`` / ``severity`` 键；
                可选 ``cvss_score`` / ``remediation``。
            out_path: 最终 docx / html 输出路径。

        Returns:
            :meth:`render` 的返回 dict。
        """
        from docx import Document
        from docx.shared import Pt, RGBColor  # noqa: F401  # Pt/RGBColor 预留给样式扩展

        tmp_dir = Path(tempfile.mkdtemp(prefix="fp_preview_"))
        docx_path = tmp_dir / "findings_preview.docx"

        doc = Document()
        doc.add_heading("安全发现预览", level=1)

        items: List[dict]
        if isinstance(findings, list):
            items = findings
        else:
            items = _report_to_dicts(findings)

        for idx, item in enumerate(items, 1):
            title = item.get("title", f"发现 #{idx}")
            severity = item.get("severity", "unknown")
            doc.add_heading(f"{idx}. {title} [{severity}]", level=3)
            if "cvss_score" in item:
                doc.add_paragraph(f"CVSS: {item['cvss_score']}")
            if "remediation" in item:
                doc.add_paragraph(f"修复建议: {item['remediation']}")

        doc.save(str(docx_path))
        logger.debug("临时 docx 已生成: %s", docx_path)

        target_fmt = "html"
        if out_path is not None:
            suffix = Path(out_path).suffix.lower()
            if suffix == ".pdf":
                target_fmt = "pdf"
            elif suffix == ".png":
                target_fmt = "png"

        result = self.render(docx_path, out_path=out_path, fmt=target_fmt)
        result["source_docx"] = docx_path
        return result


# ─────────────────────────── 内部辅助 ───────────────────────────


def _escape_html(text: str) -> str:
    """转义 HTML 特殊字符。"""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _has_libreoffice() -> bool:
    """检测 soffice 是否在 PATH 中可用。"""
    return shutil.which("soffice") is not None


def _find_browser() -> Optional[str]:
    """返回 Edge / Chrome 可执行文件路径，找不到返回 None。"""
    # 优先 PATH 中查找
    for name in ("msedge", "chrome", "chromium", "google-chrome"):
        path = shutil.which(name)
        if path:
            return path
    # 回退 Windows 安装目录
    for candidate in _BROWSER_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return None


def _render_libreoffice(docx_path: Path, out_path: Path) -> Path:
    """通过 LibreOffice headless 渲染 docx 到目标格式。

    Raises:
        RuntimeError: 渲染失败或超时。
    """
    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    target_suffix = out_path.suffix.lower().lstrip(".")
    cmd = [
        "soffice",
        "--headless",
        f"--convert-to:{target_suffix}",
        "--outdir",
        str(out_dir),
        str(docx_path),
    ]
    logger.debug("LibreOffice 命令: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"LibreOffice 退出码 {proc.returncode}: "
            f"{proc.stderr.strip()[:200]}"
        )
    # LibreOffice 按输入文件名改变后缀
    expected = out_dir / docx_path.with_suffix(out_path.suffix).name
    if out_path != expected and out_path.exists():
        return out_path
    if expected.exists():
        return expected
    raise RuntimeError("LibreOffice 未生成预期输出文件")


def _render_browser_pdf(
    docx_path: Path,
    out_path: Path,
    browser: str,
    scale: float = 1.5,
) -> Path:
    """通过 Edge/Chrome headless 将本地 docx 路径作为 file:// 打开并打印 PDF。

    Raises:
        RuntimeError: 渲染失败或超时。
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    file_url = docx_path.as_uri()
    cmd = [
        browser,
        "--headless=new",
        f"--print-to-pdf={out_path}",
        "--default-browser-check-disabled",
        "--disable-gpu",
        f"--scale-factor={scale}",
        file_url,
    ]
    logger.debug("Browser headless 命令: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Browser headless 退出码 {proc.returncode}: "
            f"{proc.stderr.strip()[:200]}"
        )
    if not out_path.exists():
        raise RuntimeError("Browser headless 未生成 PDF 文件")
    return out_path


def _report_to_dicts(report: object) -> List[dict]:
    """从 MobileSecurityReport 实例提取 findings dict 列表（最佳-effort）。"""
    results: List[dict] = []
    # 尝试常见属性
    findings_attr = getattr(report, "findings", None)
    if findings_attr is None:
        findings_attr = getattr(report, "vulnerabilities", None)
    if findings_attr is None:
        return results

    for item in findings_attr:
        if isinstance(item, dict):
            results.append(item)
        else:
            d: Dict[str, str] = {}
            for key in ("title", "severity", "cvss_score", "remediation"):
                val = getattr(item, key, None)
                if val is not None:
                    d[key] = str(val) if not isinstance(val, (int, float)) else val
            if d:
                results.append(d)
    return results
