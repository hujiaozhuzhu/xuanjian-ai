"""D-002: DocxPreview 降级渲染测试。

覆盖:
- to_html 正确解析段落与表格；
- render 在外部工具缺失时降级到 HTML；
- render_findings_preview 生成临时 docx 并降级渲染；
- 白名单校验 PathNotAllowedError。
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from fp_sentinel.mobile_reporting.formats.base_generator import PathNotAllowedError
from fp_sentinel.web_rendering import DocxPreview, _escape_html


# ─────────────────────────── helpers ───────────────────────────


def _make_docx(tmp_path: Path) -> Path:
    """创建最小 python-docx docx（几段 + 一表）。"""
    from docx import Document

    doc = Document()
    doc.add_heading("测试报告", level=1)
    doc.add_paragraph("第一段正文内容。")
    doc.add_paragraph("Second paragraph with <html> & special chars.")
    doc.add_heading("漏洞列表", level=2)

    table = doc.add_table(rows=2, cols=3)
    table.cell(0, 0).text = "名称"
    table.cell(0, 1).text = "严重度"
    table.cell(0, 2).text = "CVSS"
    table.cell(1, 0).text = "SQL 注入"
    table.cell(1, 1).text = "HIGH"
    table.cell(1, 2).text = "9.8"

    p = tmp_path / "test_report.docx"
    doc.save(str(p))
    return p


# ─────────────────────────── _escape_html ───────────────────────────


class TestEscapeHtml:
    def test_escape_special_chars(self) -> None:
        assert _escape_html("<script>") == "&lt;script&gt;"
        assert _escape_html("a & b") == "a &amp; b"
        assert _escape_html('"quoted"') == "&quot;quoted&quot;"


# ─────────────────────────── to_html ───────────────────────────


class TestDocxPreviewToHtml:
    def test_to_html_returns_string(self, tmp_path: Path) -> None:
        docx = _make_docx(tmp_path)
        preview = DocxPreview()
        html = preview.to_html(docx)
        assert isinstance(html, str)
        assert "<!DOCTYPE html>" in html
        assert "测试报告" in html
        assert "SQL 注入" in html

    def test_to_html_writes_file(self, tmp_path: Path) -> None:
        docx = _make_docx(tmp_path)
        out = tmp_path / "out.html"
        preview = DocxPreview(allowed_roots=[tmp_path])
        result = preview.to_html(docx, out_html=out)
        assert Path(result).exists()
        content = Path(result).read_text(encoding="utf-8")
        assert "测试报告" in content

    def test_to_html_escapes_inline(self, tmp_path: Path) -> None:
        docx = _make_docx(tmp_path)
        preview = DocxPreview()
        html = preview.to_html(docx)
        assert "&lt;html&gt;" in html
        assert "&amp;" in html


# ─────────────────────────── render 降级 ───────────────────────────


class TestDocxPreviewRender:
    def test_render_fallback_to_html_mock_all_missing(
        self, tmp_path: Path
    ) -> None:
        """外部工具全部缺失时，回退到 HTML 并包含 LibreOffice 提示。"""
        docx = _make_docx(tmp_path)
        preview = DocxPreview(allowed_roots=[tmp_path])

        with patch("fp_sentinel.web_rendering._has_libreoffice", return_value=False), \
             patch("fp_sentinel.web_rendering._find_browser", return_value=None):
            result = preview.render(docx)

        assert result["format"] == "html"
        assert result["backend"] == "native-html"
        assert result["path"].suffix == ".html"
        assert any("LibreOffice" in w for w in result["warnings"])

    def test_render_fmt_html_never_touches_external(
        self, tmp_path: Path
    ) -> None:
        """fmt=html 不应尝试外部工具。"""
        docx = _make_docx(tmp_path)
        preview = DocxPreview(allowed_roots=[tmp_path])

        with patch("fp_sentinel.web_rendering.subprocess.run") as mock_run:
            result = preview.render(docx, fmt="html")

        mock_run.assert_not_called()
        assert result["format"] == "html"

    def test_render_with_out_path(self, tmp_path: Path) -> None:
        docx = _make_docx(tmp_path)
        out = tmp_path / "preview.html"
        preview = DocxPreview(allowed_roots=[tmp_path])

        with patch("fp_sentinel.web_rendering._has_libreoffice", return_value=False), \
             patch("fp_sentinel.web_rendering._find_browser", return_value=None):
            result = preview.render(docx, out_path=out, fmt="html")

        assert result["path"] == out.resolve()

    def test_render_source_docx_preserved(self, tmp_path: Path) -> None:
        docx = _make_docx(tmp_path)
        preview = DocxPreview(allowed_roots=[tmp_path])

        with patch("fp_sentinel.web_rendering._has_libreoffice", return_value=False), \
             patch("fp_sentinel.web_rendering._find_browser", return_value=None):
            result = preview.render(docx)

        assert "source_docx" not in result  # render 本身不返回

    def test_render_file_not_found(self, tmp_path: Path) -> None:
        preview = DocxPreview()
        with pytest.raises(FileNotFoundError):
            preview.render(tmp_path / "nonexistent.docx")


# ─────────────────────────── 白名单校验 ───────────────────────────


class TestDocxPreviewWhitelist:
    def test_outside_whitelist_raises(self, tmp_path: Path) -> None:
        docx = _make_docx(tmp_path)
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside" / "out.html"
        outside.parent.mkdir()
        preview = DocxPreview(allowed_roots=[allowed])

        with pytest.raises(PathNotAllowedError):
            preview.to_html(docx, out_html=outside)

    def test_render_outside_whitelist_raises(self, tmp_path: Path) -> None:
        docx = _make_docx(tmp_path)
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside" / "out.html"
        outside.parent.mkdir()
        preview = DocxPreview(allowed_roots=[allowed])

        with pytest.raises(PathNotAllowedError):
            preview.render(docx, out_path=outside, fmt="html")


# ─────────────────────────── render_findings_preview ──────────────────────


class TestRenderFindingsPreview:
    def test_findings_list_of_dicts(self, tmp_path: Path) -> None:
        findings = [
            {"title": "SQLi", "severity": "HIGH", "cvss_score": "9.8"},
            {"title": "XSS", "severity": "MEDIUM"},
        ]
        out = tmp_path / "preview.html"
        preview = DocxPreview(allowed_roots=[tmp_path])

        with patch("fp_sentinel.web_rendering._has_libreoffice", return_value=False), \
             patch("fp_sentinel.web_rendering._find_browser", return_value=None):
            result = preview.render_findings_preview(findings, out_path=out)

        assert result["format"] == "html"
        assert "source_docx" in result

    def test_findings_minimal_dict(self, tmp_path: Path) -> None:
        findings = [{"title": "Test", "severity": "LOW"}]
        preview = DocxPreview(allowed_roots=[tmp_path])

        # mock render_findings_preview 的 fallback 路径：临时目录在 allowed_roots 之外
        # 直接验证 to_html 可工作，避免临时目录穿越白名单问题
        with patch("fp_sentinel.web_rendering._has_libreoffice", return_value=False), \
             patch("fp_sentinel.web_rendering._find_browser", return_value=None), \
             patch("fp_sentinel.web_rendering.tempfile.mkdtemp", return_value=str(tmp_path / "fp_preview_mock")):
            (tmp_path / "fp_preview_mock").mkdir(exist_ok=True)
            result = preview.render_findings_preview(findings)

        assert result["format"] == "html"
