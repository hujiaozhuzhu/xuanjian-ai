"""core.screenshot_manager 单元测试。

使用 struct 手工构造合法/损坏/截断的 PNG 与 JPEG 字节流（不依赖 PIL），
覆盖全部校验分支。
"""

from __future__ import annotations

import hashlib
import struct
import sys
import types
import zlib
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _ensure_reporting_importable() -> None:
    """formats.excel_generator 由并行开发提供，缺失时注入最小存根保证可导入。"""
    try:
        import fp_sentinel.mobile_reporting  # noqa: F401
    except ModuleNotFoundError:
        for name in [
            k for k in sys.modules if k.startswith("fp_sentinel.mobile_reporting")
        ]:
            del sys.modules[name]
        stub = types.ModuleType(
            "fp_sentinel.mobile_reporting.formats.excel_generator"
        )
        stub.OPENPYXL_AVAILABLE = False  # type: ignore[attr-defined]
        stub.ExcelReportGenerator = type(  # type: ignore[attr-defined]
            "ExcelReportGenerator", (), {}
        )
        sys.modules[stub.__name__] = stub
        import fp_sentinel.mobile_reporting  # noqa: F401


_ensure_reporting_importable()

from fp_sentinel.mobile_reporting.core.screenshot_manager import (  # noqa: E402
    PNG_SIGNATURE,
    ScreenshotManager,
)
from fp_sentinel.mobile_reporting.models import (  # noqa: E402
    FindingReport,
    MobileSecurityReport,
    ScreenshotRef,
)


# ---------------------------------------------------------------------------
# 手工构造图片字节流（纯 struct / zlib，不依赖 PIL）
# ---------------------------------------------------------------------------


def _png_chunk(ctype: bytes, data: bytes) -> bytes:
    """构造带长度与 CRC 的 PNG chunk。"""
    crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)


def make_png(width: int = 100, height: int = 80, with_iend: bool = True) -> bytes:
    """构造最小合法 PNG（可按需去掉 IEND 模拟截断）。"""
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    out = PNG_SIGNATURE + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", b"\x00x")
    if with_iend:
        out += _png_chunk(b"IEND", b"")
    return out


def make_jpeg(
    width: int = 100, height: int = 80, with_eoi: bool = True
) -> bytes:
    """构造最小合法 JPEG（APP0 + SOF0 + SOS，可去掉 EOI 模拟截断）。"""
    out = b"\xff\xd8"
    app0 = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    out += b"\xff\xe0" + struct.pack(">H", len(app0) + 2) + app0
    sof = struct.pack(">BHHB", 8, height, width, 1) + b"\x01\x11\x00"
    out += b"\xff\xc0" + struct.pack(">H", len(sof) + 2) + sof
    sos = b"\x01\x00\x02\x00\x00"
    out += b"\xff\xda" + struct.pack(">H", len(sos) + 2) + sos + b"\x00\x33"
    if with_eoi:
        out += b"\xff\xd9"
    return out


@pytest.fixture()
def manager() -> ScreenshotManager:
    """默认管理器。"""
    return ScreenshotManager()


# ---------------------------------------------------------------------------
# 登记 + 校验通过分支
# ---------------------------------------------------------------------------


class TestRegisterAndValidatePass:
    """正常通过分支。"""

    def test_register_png(self, manager: ScreenshotManager, tmp_path: Path) -> None:
        """登记 PNG 时计算哈希、嗅探格式并解析宽高。"""
        path = tmp_path / "ok.png"
        data = make_png()
        path.write_bytes(data)
        ref = manager.register_screenshot(str(path), "主界面", "VUL-001")
        assert ref.sha256 == hashlib.sha256(data).hexdigest()
        assert ref.format == "png"
        assert (ref.width, ref.height) == (100, 80)
        assert not ref.verified
        assert ref.id.startswith("SHOT-VUL-001")

    def test_validate_png_pass(
        self, manager: ScreenshotManager, tmp_path: Path
    ) -> None:
        """合法 PNG 校验通过。"""
        path = tmp_path / "ok.png"
        path.write_bytes(make_png())
        ref = manager.validate_screenshot(
            ScreenshotRef(id="S1", path=str(path), sha256="", format="png")
        )
        assert ref.verified, ref.verify_message
        assert "校验通过" in ref.verify_message
        assert ref.width == 100 and ref.height == 80

    def test_validate_jpeg_pass(
        self, manager: ScreenshotManager, tmp_path: Path
    ) -> None:
        """合法 JPEG 校验通过。"""
        path = tmp_path / "ok.jpg"
        path.write_bytes(make_jpeg())
        ref = manager.validate_screenshot(ScreenshotRef(id="S2", path=str(path)))
        assert ref.verified, ref.verify_message
        assert ref.format == "jpeg"
        assert (ref.width, ref.height) == (100, 80)

    def test_validate_all_pass(
        self, manager: ScreenshotManager, tmp_path: Path
    ) -> None:
        """validate_all 返回通过列表。"""
        path = tmp_path / "ok.png"
        path.write_bytes(make_png())
        ref = manager.register_screenshot(str(path), "截图", "VUL-001")
        report = MobileSecurityReport(
            findings=[
                FindingReport(
                    id="VUL-001", title="t", severity="LOW", screenshots=[ref]
                )
            ]
        )
        passed, failed = manager.validate_all(report)
        assert passed == [ref] and failed == []


# ---------------------------------------------------------------------------
# 失败分支
# ---------------------------------------------------------------------------


class TestValidateFailureBranches:
    """各失败分支均写入具体 verify_message。"""

    def test_file_not_found(self, manager: ScreenshotManager) -> None:
        """文件不存在分支。"""
        ref = manager.validate_screenshot(
            ScreenshotRef(id="S1", path="no/such/shot.png")
        )
        assert not ref.verified
        assert "文件不存在" in ref.verify_message

    def test_register_missing_file(
        self, manager: ScreenshotManager
    ) -> None:
        """登记缺失文件时降级为未校验状态。"""
        ref = manager.register_screenshot("no/such/shot.png", "标题", "VUL-001")
        assert not ref.verified
        assert ref.sha256 == ""

    def test_bad_magic(self, manager: ScreenshotManager, tmp_path: Path) -> None:
        """魔数错误分支（文本文件伪装图片）。"""
        path = tmp_path / "fake.png"
        path.write_bytes(b"this is not an image at all")
        ref = manager.validate_screenshot(ScreenshotRef(id="S1", path=str(path)))
        assert not ref.verified
        assert "魔数错误" in ref.verify_message

    def test_hash_mismatch(
        self, manager: ScreenshotManager, tmp_path: Path
    ) -> None:
        """哈希不匹配分支：登记后被篡改。"""
        path = tmp_path / "tampered.png"
        path.write_bytes(make_png(width=200, height=100))
        ref = manager.register_screenshot(str(path), "原始", "VUL-001")
        path.write_bytes(make_png(width=300, height=50))
        ref = manager.validate_screenshot(ref)
        assert not ref.verified
        assert "SHA256 不匹配" in ref.verify_message

    def test_truncated_png(
        self, manager: ScreenshotManager, tmp_path: Path
    ) -> None:
        """PNG 截断分支：缺少 IEND。"""
        path = tmp_path / "cut.png"
        path.write_bytes(make_png(with_iend=False))
        ref = manager.validate_screenshot(ScreenshotRef(id="S1", path=str(path)))
        assert not ref.verified
        assert "截断" in ref.verify_message and "IEND" in ref.verify_message

    def test_truncated_jpeg(
        self, manager: ScreenshotManager, tmp_path: Path
    ) -> None:
        """JPEG 截断分支：缺少 EOI。"""
        path = tmp_path / "cut.jpg"
        path.write_bytes(make_jpeg(with_eoi=False))
        ref = manager.validate_screenshot(ScreenshotRef(id="S1", path=str(path)))
        assert not ref.verified
        assert "截断" in ref.verify_message and "EOI" in ref.verify_message

    def test_dimension_too_small(
        self, manager: ScreenshotManager, tmp_path: Path
    ) -> None:
        """尺寸异常分支：低于 10x10。"""
        path = tmp_path / "tiny.png"
        path.write_bytes(make_png(width=5, height=8))
        ref = manager.validate_screenshot(ScreenshotRef(id="S1", path=str(path)))
        assert not ref.verified
        assert "尺寸异常" in ref.verify_message

    def test_empty_file(self, manager: ScreenshotManager, tmp_path: Path) -> None:
        """空文件分支。"""
        path = tmp_path / "empty.png"
        path.write_bytes(b"")
        ref = manager.validate_screenshot(ScreenshotRef(id="S1", path=str(path)))
        assert not ref.verified
        assert "文件为空" in ref.verify_message

    def test_corrupt_png_header(
        self, manager: ScreenshotManager, tmp_path: Path
    ) -> None:
        """PNG 头损坏分支：魔数正确但 IHDR 非法。"""
        path = tmp_path / "broken.png"
        path.write_bytes(PNG_SIGNATURE + b"\x00" * 64)
        ref = manager.validate_screenshot(ScreenshotRef(id="S1", path=str(path)))
        assert not ref.verified
        assert "解析宽高" in ref.verify_message

    def test_format_mismatch(
        self, manager: ScreenshotManager, tmp_path: Path
    ) -> None:
        """登记格式与实际内容不一致分支。"""
        path = tmp_path / "actually_jpeg.png"
        path.write_bytes(make_jpeg())
        ref = manager.validate_screenshot(
            ScreenshotRef(id="S1", path=str(path), format="png")
        )
        assert not ref.verified
        assert "格式不一致" in ref.verify_message


# ---------------------------------------------------------------------------
# validate_all 失败收集与关联复核
# ---------------------------------------------------------------------------


class TestValidateAllAndAssociation:
    """报告级校验与关联复核。"""

    def test_validate_all_mixed(
        self, manager: ScreenshotManager, tmp_path: Path
    ) -> None:
        """通过/失败截图分别归入两个列表。"""
        good = tmp_path / "good.png"
        good.write_bytes(make_png())
        bad = tmp_path / "bad.png"
        bad.write_bytes(b"junk")
        ref_good = ScreenshotRef(id="S1", path=str(good))
        ref_bad = ScreenshotRef(id="S2", path=str(bad))
        report = MobileSecurityReport(
            findings=[
                FindingReport(
                    id="VUL-001",
                    title="t",
                    severity="LOW",
                    screenshots=[ref_good, ref_bad],
                )
            ]
        )
        passed, failed = manager.validate_all(report)
        assert [r.id for r in passed] == ["S1"]
        assert [r.id for r in failed] == ["S2"]
        assert failed[0].verify_message

    def test_check_associations(
        self, manager: ScreenshotManager, tmp_path: Path
    ) -> None:
        """关联复核：未验证/缺 caption/文件缺失均被指出。"""
        ok = tmp_path / "ok.png"
        ok.write_bytes(make_png())
        ref_ok = ScreenshotRef(id="S1", path=str(ok))
        manager.validate_screenshot(ref_ok)
        ref_ok.caption = "已验证截图"
        ref_unverified = ScreenshotRef(id="S2", path=str(ok))
        ref_missing = ScreenshotRef(id="S3", path="no/such.png", caption="x")
        no_caption = ScreenshotRef(id="S4", path=str(ok))
        manager.validate_screenshot(no_caption)
        report = MobileSecurityReport(
            findings=[
                FindingReport(
                    id="VUL-001",
                    title="t",
                    severity="LOW",
                    screenshots=[ref_ok, ref_unverified, ref_missing, no_caption],
                )
            ]
        )
        problems = manager.check_associations(report)
        assert any("未通过验证" in p for p in problems)
        assert any("文件不存在" in p for p in problems)
        assert any("caption" in p for p in problems)
        # 已验证且带 caption 的 S1 不应出现在问题列表中
        assert not any("S1" in p for p in problems)

    def test_check_associations_no_screenshots(
        self, manager: ScreenshotManager
    ) -> None:
        """无截图的 finding 产生提示性 warning。"""
        report = MobileSecurityReport(
            findings=[FindingReport(id="VUL-001", title="t", severity="LOW")]
        )
        problems = manager.check_associations(report)
        assert any("未引用任何截图" in p for p in problems)


# ---------------------------------------------------------------------------
# 底层解析函数
# ---------------------------------------------------------------------------


class TestParsingHelpers:
    """detect_truncation / parse_dimensions / sniff_format。"""

    def test_detect_truncation_jpeg_tail(self) -> None:
        """JPEG 尾部含 EOI 即认为未截断，移除 EOI 后判为截断。"""
        data = make_jpeg() + b"\x00\x00"
        assert ScreenshotManager.detect_truncation(data, "jpeg") is False
        assert ScreenshotManager.detect_truncation(data[:-4], "jpeg") is True

    def test_detect_truncation_png_iend_length(self) -> None:
        """PNG IEND 长度非 0 视为异常。"""
        data = make_png()
        assert ScreenshotManager.detect_truncation(data, "png") is False
        broken = data.replace(b"IEND", b"IENX", 1)
        assert ScreenshotManager.detect_truncation(broken, "png") is True

    def test_parse_dimensions_unknown(self) -> None:
        """未知格式返回 None。"""
        assert ScreenshotManager.parse_dimensions(b"hello") is None
        assert ScreenshotManager.sniff_format(b"hello") is None

    def test_parse_jpeg_progressive(self) -> None:
        """SOF2（渐进式）同样可解析尺寸。"""
        width, height = 320, 240
        sof2 = struct.pack(">BHHB", 8, height, width, 1) + b"\x01\x11\x00"
        data = (
            b"\xff\xd8"
            + b"\xff\xc2"
            + struct.pack(">H", len(sof2) + 2)
            + sof2
            + b"\xff\xd9"
        )
        assert ScreenshotManager.parse_dimensions(data) == (width, height)


class TestStreamingHashAndSizeLimit:
    """流式哈希、单文件大小上限与登记哈希复用回归。"""

    def test_validate_oversized_file_fails_with_reason(
        self, manager: ScreenshotManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """超过大小上限的截图判定失败且原因明确。"""
        import fp_sentinel.mobile_reporting.core.screenshot_manager as sm

        path = tmp_path / "big.png"
        path.write_bytes(make_png())
        monkeypatch.setattr(sm, "MAX_SCREENSHOT_BYTES", 10)
        ref = manager.validate_screenshot(ScreenshotRef(id="S1", path=str(path)))
        assert not ref.verified
        assert "大小上限" in ref.verify_message
        assert "字节" in ref.verify_message

    def test_register_oversized_file_skips_hash(
        self, manager: ScreenshotManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """登记超限文件时不计算哈希并写明原因。"""
        import fp_sentinel.mobile_reporting.core.screenshot_manager as sm

        path = tmp_path / "big.png"
        path.write_bytes(make_png())
        monkeypatch.setattr(sm, "MAX_SCREENSHOT_BYTES", 10)
        ref = manager.register_screenshot(str(path), "超限", "VUL-001")
        assert ref.sha256 == ""
        assert "大小上限" in ref.verify_message

    def test_validate_reuses_registered_hash(
        self, manager: ScreenshotManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """size/mtime 未变时校验复用登记哈希，不重复计算。"""
        path = tmp_path / "ok.png"
        path.write_bytes(make_png())
        ref = manager.register_screenshot(str(path), "复用", "VUL-001")
        assert ref.sha256

        def _boom(_path: Path) -> str:
            raise AssertionError("不应重复计算 SHA256")

        monkeypatch.setattr(ScreenshotManager, "_stream_sha256", staticmethod(_boom))
        ref = manager.validate_screenshot(ref)
        assert ref.verified, ref.verify_message

    def test_tamper_same_size_still_recomputes(
        self, manager: ScreenshotManager, tmp_path: Path
    ) -> None:
        """同尺寸篡改（mtime 变化）时仍重算哈希并检出不匹配。"""
        import os

        path = tmp_path / "same_size.png"
        original = bytearray(make_png(width=100, height=80))
        original[-16] ^= 0xFF  # 翻转 IDAT 区域字节，保持文件长度不变
        path.write_bytes(bytes(original))
        os.utime(path, (1000000000, 1000000000))
        ref = manager.register_screenshot(str(path), "原始", "VUL-001")
        tampered = bytearray(make_png(width=100, height=80))
        tampered[-17] ^= 0xFF  # 与原始翻转的字节不同，同尺寸不同内容
        path.write_bytes(bytes(tampered))
        os.utime(path, (2000000000, 2000000000))
        ref = manager.validate_screenshot(ref)
        assert not ref.verified
        assert "SHA256 不匹配" in ref.verify_message
