"""截图登记与完整性校验管理器。

ScreenshotManager 是移动安全报告截图证据的唯一入口，负责：

1. 登记：读取截图文件计算 SHA256、嗅探格式、解析宽高并生成 ScreenshotRef；
2. 校验：文件存在 / 可读 / 非空 / 魔数正确 / 尺寸可解析且合理 /
   SHA256 与登记值一致 / 无截断（PNG 检查 IEND、JPEG 检查 EOI）；
3. 报告级复核：报告生成后逐一检查每个 finding 引用的截图均存在且通过校验。

全部解析基于 struct 纯标准库实现；PIL 可用时作为可选增强做交叉校验，
PIL 缺失不影响任何核心校验能力。
"""

from __future__ import annotations

import hashlib
import logging
import struct
from pathlib import Path
from typing import Any, List, Optional, Tuple

from ..models.report_models import MobileSecurityReport, ScreenshotRef

try:  # PIL 为可选增强依赖，缺失时静默降级
    from PIL import Image  # type: ignore[import-untyped]

    _PIL_AVAILABLE = True
except ImportError:  # pragma: no cover - 取决于运行环境
    Image = None  # type: ignore[assignment]
    _PIL_AVAILABLE = False

__all__ = ["ScreenshotManager", "PNG_SIGNATURE", "JPEG_SIGNATURE"]

logger = logging.getLogger(__name__)

#: PNG 文件签名（魔数）
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
#: JPEG 文件签名（魔数前 3 字节）
JPEG_SIGNATURE = b"\xff\xd8\xff"
#: PNG IEND chunk 的固定 CRC（IEND 内容为空，CRC 恒定）
_PNG_IEND_CHUNK = b"IEND"
#: JPEG EOI（文件结束）标记
_JPEG_EOI = b"\xff\xd9"
#: 尺寸合理性下限（宽高均不得小于该值）
MIN_DIMENSION = 10
#: JPEG SOF 帧标记集合（携带图像尺寸信息；排除 DHT/H 函数/JPG 扩展）
_JPEG_SOF_MARKERS = frozenset(
    {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
)


class ScreenshotManager:
    """截图登记与完整性校验管理器。

    Args:
        min_dimension: 截图宽/高的最小合理值，默认 10。
    """

    def __init__(self, min_dimension: int = MIN_DIMENSION) -> None:
        self._min_dimension = max(1, int(min_dimension))
        self._seq = 0

    # ─────────────────────────── 登记 ────────────────────────────

    def register_screenshot(
        self,
        path: str,
        caption: str = "",
        finding_id: str = "",
    ) -> ScreenshotRef:
        """登记一张截图，生成 ScreenshotRef。

        登记时尽力读取文件计算 SHA256、嗅探格式并解析宽高；
        文件缺失或损坏时登记为未校验状态，具体问题留给
        :meth:`validate_screenshot` 给出结论。

        Args:
            path: 截图文件路径。
            caption: 截图标题。
            finding_id: 关联的漏洞发现 id（用于日志与命名，不落入模型字段）。

        Returns:
            ScreenshotRef: 已登记的截图引用（verified=False，待校验）。
        """
        self._seq += 1
        ref_id = f"SHOT-{self._seq:03d}"
        if finding_id:
            ref_id = f"SHOT-{finding_id}-{self._seq:03d}"
        ref = ScreenshotRef(id=ref_id, path=str(path), caption=caption)
        file_path = Path(path)
        if not file_path.is_file():
            ref.verify_message = "登记时文件不存在，尚未通过校验"
            logger.warning("截图登记失败（文件不存在）: %s", path)
            return ref
        try:
            data = file_path.read_bytes()
        except OSError as exc:
            ref.verify_message = f"登记时文件不可读: {exc}"
            logger.warning("截图登记失败（不可读）: %s (%s)", path, exc)
            return ref
        ref.sha256 = hashlib.sha256(data).hexdigest()
        fmt = self.sniff_format(data)
        ref.format = fmt
        size = self.parse_dimensions(data)
        if size is not None:
            ref.width, ref.height = size
        ref.verify_message = "已登记，尚未通过完整校验"
        logger.debug("截图已登记: %s (%s, %dx%d)", ref_id, path, ref.width, ref.height)
        return ref

    # ─────────────────────────── 单张校验 ────────────────────────

    def validate_screenshot(self, ref: ScreenshotRef) -> ScreenshotRef:
        """对单张截图执行完整性与真实性校验。

        校验项（任一失败即 verified=False，全部原因汇总到 verify_message）：
        文件存在、可读、非空、魔数正确、格式与登记值一致、
        无截断、尺寸可解析且不低于最小合理值、SHA256 与登记值一致。

        Args:
            ref: 待校验的截图引用（原地更新 verified/verify_message 等字段）。

        Returns:
            ScreenshotRef: 更新后的同一引用对象。
        """
        reasons: List[str] = []
        file_path = Path(ref.path)
        if not file_path.is_file():
            ref.verified = False
            ref.verify_message = f"文件不存在: {ref.path}"
            logger.warning("截图校验失败: %s", ref.verify_message)
            return ref
        try:
            data = file_path.read_bytes()
        except OSError as exc:
            ref.verified = False
            ref.verify_message = f"文件不可读: {exc}"
            logger.warning("截图校验失败: %s", ref.verify_message)
            return ref
        if not data:
            ref.verified = False
            ref.verify_message = "文件为空"
            logger.warning("截图校验失败: %s (%s)", ref.path, ref.verify_message)
            return ref

        fmt = self.sniff_format(data)
        if fmt is None:
            reasons.append(
                "魔数错误: 文件既非合法 PNG 也非合法 JPEG 头部"
            )
        else:
            if ref.format and ref.format != fmt:
                reasons.append(
                    f"格式不一致: 登记为 {ref.format!r}，实际为 {fmt!r}"
                )
            ref.format = fmt
            if self.detect_truncation(data, fmt):
                tail = "IEND" if fmt == "png" else "EOI"
                reasons.append(f"文件疑似截断: 未找到 {tail} 结束标记")
            size = self.parse_dimensions(data)
            if size is None:
                reasons.append("无法从文件头解析宽高（文件可能损坏）")
            else:
                width, height = size
                ref.width, ref.height = width, height
                if width < self._min_dimension or height < self._min_dimension:
                    reasons.append(
                        f"尺寸异常: {width}x{height} 低于最小要求 "
                        f"{self._min_dimension}x{self._min_dimension}"
                    )
                if _PIL_AVAILABLE and Image is not None:
                    reasons.extend(self._pil_cross_check(file_path, width, height))

        actual_sha = hashlib.sha256(data).hexdigest()
        if ref.sha256 and ref.sha256.lower() != actual_sha:
            reasons.append(
                f"SHA256 不匹配（文件可能被篡改）: "
                f"期望 {ref.sha256[:16]}... 实际 {actual_sha[:16]}..."
            )
        elif not ref.sha256:
            logger.debug("截图 %s 登记时未提供 SHA256，已回填当前计算值", ref.id)
        ref.sha256 = actual_sha

        ref.verified = not reasons
        ref.verify_message = (
            "校验通过: {fmt} {w}x{h}, sha256={sha}".format(
                fmt=ref.format or "?", w=ref.width, h=ref.height, sha=actual_sha[:16]
            )
            if ref.verified
            else "; ".join(reasons)
        )
        if ref.verified:
            logger.debug("截图校验通过: %s (%s)", ref.id, ref.path)
        else:
            logger.warning("截图校验失败 %s: %s", ref.id, ref.verify_message)
        return ref

    # ─────────────────────────── 报告级校验 ──────────────────────

    def validate_all(
        self, report: MobileSecurityReport
    ) -> Tuple[List[ScreenshotRef], List[ScreenshotRef]]:
        """校验报告内所有 finding 引用的截图。

        同一截图引用（按 id 去重）只校验一次。

        Args:
            report: 移动安全报告。

        Returns:
            Tuple[List[ScreenshotRef], List[ScreenshotRef]]:
                (通过列表, 失败列表)。失败项的 verify_message 写明具体原因。
        """
        passed: List[ScreenshotRef] = []
        failed: List[ScreenshotRef] = []
        seen: set[str] = set()
        for finding in self._iter_findings(report):
            for ref, _ in self._iter_screenshots(finding):
                key = ref.id or ref.path
                if key in seen:
                    continue
                seen.add(key)
                self.validate_screenshot(ref)
                if ref.verified:
                    passed.append(ref)
                else:
                    failed.append(ref)
        logger.info(
            "报告截图校验完成: 通过 %d 张, 失败 %d 张", len(passed), len(failed)
        )
        return passed, failed

    def check_associations(self, report: MobileSecurityReport) -> List[str]:
        """caption 与 finding 关联复核。

        报告生成后二次检查：每个 finding 引用的截图必须文件存在且已验证
        通过；已通过的截图必须具备非空 caption 以保证报告可读性。

        Args:
            report: 移动安全报告。

        Returns:
            List[str]: 关联问题 warning 列表（不抛异常）。
        """
        problems: List[str] = []
        for index, finding in enumerate(self._iter_findings(report), start=1):
            fid = getattr(finding, "id", None) or getattr(
                finding, "vuln_id", ""
            ) or "<无id>"
            prefix = f"finding[{index}]({fid})"
            refs = self._iter_screenshots(finding)
            if not refs:
                problems.append(f"{prefix} 未引用任何截图证据")
                continue
            for ref, has_state in refs:
                if not Path(ref.path).exists():
                    problems.append(f"{prefix} 引用的截图文件不存在: {ref.path}")
                    continue
                if has_state:
                    # 共享模型：尊重已有验证状态（由 validate_all 等流程回填）
                    verified = bool(ref.verified)
                else:
                    # 回退模型无状态字段，现场校验一次
                    self.validate_screenshot(ref)
                    verified = ref.verified
                if not verified:
                    problems.append(
                        f"{prefix} 引用的截图未通过验证: {ref.id}"
                        f"（{ref.verify_message}）"
                    )
                elif not ref.caption.strip():
                    problems.append(f"{prefix} 引用的截图缺少 caption: {ref.id}")
        return problems

    # ─────────────────────── 模型兼容层 ────────────────────────

    @staticmethod
    def _iter_findings(report: object) -> List[Any]:
        """读取漏洞列表，兼容共享模型 ``findings`` 与回退模型 ``vulnerabilities``。"""
        findings = getattr(report, "findings", None)
        if not findings:
            findings = getattr(report, "vulnerabilities", None)
        return list(findings or [])

    def _iter_screenshots(self, finding: object) -> List[Tuple[ScreenshotRef, bool]]:
        """读取 finding 的截图列表，返回 ``(归一化引用, 是否共享模型)`` 二元组。

        兼容回退模型 :class:`Screenshot`（仅 ``path``/``description``）
        与共享模型 :class:`ScreenshotRef`。回退对象会被归一化为新的
        :class:`ScreenshotRef`；归一化仅在本次校验内生效，不回写
        原报告对象，避免改变调用方数据结构。
        """
        refs: List[Tuple[ScreenshotRef, bool]] = []
        for item in getattr(finding, "screenshots", None) or []:
            if isinstance(item, ScreenshotRef):
                refs.append((item, True))
                continue
            path = str(getattr(item, "path", "") or "")
            caption = str(
                getattr(item, "caption", None)
                or getattr(item, "description", "")
                or ""
            )
            ref = ScreenshotRef(id=path or "<未命名>", path=path, caption=caption)
            sha = getattr(item, "sha256", None)
            if sha:
                ref.sha256 = str(sha)
            fmt = getattr(item, "format", None)
            if fmt:
                ref.format = str(fmt)
            refs.append((ref, False))
        return refs

    # ─────────────────────────── 底层解析 ────────────────────────

    @staticmethod
    def sniff_format(data: bytes) -> Optional[str]:
        """根据魔数嗅探图片格式。

        Returns:
            "png" / "jpeg"，无法识别时返回 None。
        """
        if data.startswith(PNG_SIGNATURE):
            return "png"
        if data.startswith(JPEG_SIGNATURE):
            return "jpeg"
        return None

    @staticmethod
    def detect_truncation(data: bytes, fmt: str) -> bool:
        """检测文件是否被截断。

        PNG 检查 IEND chunk 是否存在（含长度字段 0 与合法位置）；
        JPEG 检查文件结尾是否存在 EOI 标记。

        Args:
            data: 文件完整字节内容。
            fmt: 嗅探出的格式（"png" / "jpeg"）。

        Returns:
            bool: True 表示已截断（缺少结束标记）。
        """
        if fmt == "png":
            idx = data.find(_PNG_IEND_CHUNK)
            if idx < 4:
                return True
            length = struct.unpack(">I", data[idx - 4:idx])[0]
            return length != 0
        if fmt == "jpeg":
            tail = data[-8:] if len(data) >= 8 else data
            return _JPEG_EOI not in tail
        return True

    @staticmethod
    def parse_dimensions(data: bytes) -> Optional[Tuple[int, int]]:
        """从文件头解析 (宽, 高)。

        PNG 解析 IHDR chunk；JPEG 遍历段标记定位 SOF 帧。
        纯 struct 实现，不依赖 PIL。

        Returns:
            Optional[Tuple[int, int]]: (宽, 高)；解析失败返回 None。
        """
        if data.startswith(PNG_SIGNATURE):
            return ScreenshotManager._parse_png_size(data)
        if data.startswith(JPEG_SIGNATURE):
            return ScreenshotManager._parse_jpeg_size(data)
        return None

    @staticmethod
    def _parse_png_size(data: bytes) -> Optional[Tuple[int, int]]:
        """解析 PNG IHDR chunk 得到 (宽, 高)。"""
        if len(data) < 24:
            return None
        try:
            length = struct.unpack(">I", data[8:12])[0]
            chunk_type = data[12:16]
            if chunk_type != b"IHDR" or length != 13:
                return None
            width, height = struct.unpack(">II", data[16:24])
        except struct.error:
            return None
        return int(width), int(height)

    @staticmethod
    def _parse_jpeg_size(data: bytes) -> Optional[Tuple[int, int]]:
        """遍历 JPEG 段标记，从首个 SOF 帧解析 (宽, 高)。"""
        n = len(data)
        i = 2  # 跳过 SOI (FF D8)
        while i + 2 <= n:
            if data[i] != 0xFF:
                return None
            # 跳过连续的填充 0xFF
            while i < n and data[i] == 0xFF:
                i += 1
            if i >= n:
                return None
            marker = data[i]
            i += 1
            # 无长度字段的标记：D8(SOI)/D9(EOI)/D0-D7(RST)/01(TEM)
            if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7 or marker == 0x01:
                continue
            if i + 2 > n:
                return None
            try:
                seg_len = struct.unpack(">H", data[i:i + 2])[0]
            except struct.error:
                return None
            if seg_len < 2:
                return None
            if marker in _JPEG_SOF_MARKERS:
                if i + 7 > n:
                    return None
                try:
                    height, width = struct.unpack(">HH", data[i + 3:i + 7])
                except struct.error:
                    return None
                return int(width), int(height)
            i += seg_len
        return None

    @staticmethod
    def _pil_cross_check(
        file_path: Path, width: int, height: int
    ) -> List[str]:
        """PIL 可用时交叉校验宽高，不一致时返回原因列表。"""
        reasons: List[str] = []
        if Image is None:  # pragma: no cover - PIL 缺失时不会进入
            return reasons
        try:
            with Image.open(file_path) as img:  # type: ignore[union-attr]
                pil_size = img.size
        except Exception as exc:  # noqa: BLE001 - PIL 异常类型多样，仅降级
            logger.debug("PIL 交叉校验失败（忽略）: %s", exc)
            return reasons
        if pil_size != (width, height):
            reasons.append(
                f"PIL 交叉校验尺寸不一致: struct={width}x{height}, "
                f"PIL={pil_size[0]}x{pil_size[1]}"
            )
        return reasons
