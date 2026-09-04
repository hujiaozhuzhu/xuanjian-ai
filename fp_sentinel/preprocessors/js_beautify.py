"""Safe, static preprocessing for minified JavaScript bundles.

This module never evaluates JavaScript, resolves source maps, decrypts content,
or writes back to the scanned file. It only reformats eligible text in memory.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, Optional

try:
    import jsbeautifier
except ImportError:  # Optional dependency: normal source scanning remains available.
    jsbeautifier = None


MIN_FILE_BYTES = 10 * 1024
MAX_NEWLINES = 4
MIN_AVERAGE_LINE_LENGTH = 2000
SUSPICIOUS_BASE64_RUN = 256


@dataclass(frozen=True)
class JSPreprocessResult:
    """In-memory content plus enough metadata to explain location quality."""

    content: str
    used_beautifier: bool = False
    original_line_count: int = 0
    original_size_bytes: int = 0
    original_content: str = ""
    warning: Optional[str] = None
    reason: Optional[str] = None
    line_starts: tuple[int, ...] = field(default_factory=tuple)

    def location_metadata(self, beautified_line: int) -> Dict[str, Any]:
        """Describe a result position without claiming a false source line mapping."""
        if not self.used_beautifier:
            return {}

        original_line_range = (
            "1"
            if self.original_line_count <= 1
            else f"1-{self.original_line_count}"
        )
        return {
            "preprocessed": True,
            "preprocessor": "jsbeautifier",
            "original_line_range": original_line_range,
            "beautified_line": beautified_line,
            "original_offset_hint": _offset_hint(
                self.original_content, self.content, self.line_starts, beautified_line
            ),
        }


def looks_minified(content: str) -> bool:
    """Return True only for large, nearly single-line JavaScript content."""
    if len(content.encode("utf-8")) <= MIN_FILE_BYTES:
        return False

    line_count = content.count("\n") + 1
    average_line_length = len(content) / line_count
    return line_count <= MAX_NEWLINES and average_line_length > MIN_AVERAGE_LINE_LENGTH


def looks_heavily_obfuscated(content: str) -> bool:
    """Identify text worth warning about, without attempting to decode it."""
    compact = "".join(content.split())
    has_long_base64 = any(
        len(match.group(0)) >= SUSPICIOUS_BASE64_RUN
        for match in re.finditer(r"[A-Za-z0-9+/=]{%d,}" % SUSPICIOUS_BASE64_RUN, compact)
    )
    return has_long_base64 and ("atob(" in content or "fromCharCode" in content)


def preprocess_javascript(content: str) -> JSPreprocessResult:
    """Beautify an eligible bundle in memory and return transparent metadata."""
    original_lines = content.count("\n") + 1
    original_size = len(content.encode("utf-8"))

    if not looks_minified(content):
        return JSPreprocessResult(
            content=content,
            original_line_count=original_lines,
            original_size_bytes=original_size,
            original_content=content,
        )

    if jsbeautifier is None:
        return JSPreprocessResult(
            content=content,
            original_line_count=original_lines,
            original_size_bytes=original_size,
            original_content=content,
            warning="检测到压缩 JavaScript，但未安装可选 jsbeautifier；建议扫描原始源码或安装 fp-sentinel[preprocess]。",
            reason="beautifier_unavailable",
        )

    try:
        beautified = jsbeautifier.beautify(content)
    except Exception:
        return JSPreprocessResult(
            content=content,
            original_line_count=original_lines,
            original_size_bytes=original_size,
            original_content=content,
            warning="文件疑似压缩或混淆，静态格式化失败；建议扫描原始源码或提供 source map。",
            reason="beautifier_failed",
        )

    if not beautified.strip() or beautified == content:
        return JSPreprocessResult(
            content=content,
            original_line_count=original_lines,
            original_size_bytes=original_size,
            original_content=content,
            warning="文件疑似压缩或混淆，静态格式化未产生可用定位；建议扫描原始源码或提供 source map。",
            reason="beautifier_no_change",
        )

    return JSPreprocessResult(
        content=beautified,
        used_beautifier=True,
        original_line_count=original_lines,
        original_size_bytes=original_size,
        original_content=content,
        line_starts=tuple(_line_starts(beautified)),
    )


def _line_starts(content: str) -> list[int]:
    starts = [0]
    for index, char in enumerate(content):
        if char == "\n":
            starts.append(index + 1)
    return starts


def _offset_hint(
    original: str, beautified: str, line_starts: tuple[int, ...], line: int
) -> Dict[str, int]:
    if not line_starts:
        return {}

    index = min(max(line - 1, 0), len(line_starts) - 1)
    start = line_starts[index]
    end = line_starts[index + 1] - 1 if index + 1 < len(line_starts) else len(beautified)
    fragment = beautified[start:end].strip()
    normalized_fragment = re.sub(r"\s+", "", fragment)
    expected_start = int(start * len(original) / max(len(beautified), 1))
    original_offset = _nearest_offset(original, normalized_fragment, expected_start)
    offset_hint: Dict[str, int] = {
        "beautified_start": start,
        "beautified_end": end,
    }
    if original_offset >= 0:
        offset_hint["original_start"] = original_offset
        offset_hint["original_end"] = original_offset + len(normalized_fragment)
    return offset_hint


def _nearest_offset(original: str, fragment: str, expected_start: int) -> int:
    """Find a nearby static offset, including repeated snippets in a bundle."""
    if not fragment:
        return -1

    search_start = max(0, expected_start - len(fragment) * 4)
    candidate = original.find(fragment, search_start)
    if candidate < 0:
        return original.find(fragment)

    closest = candidate
    while candidate >= 0 and candidate <= expected_start + len(fragment) * 4:
        if abs(candidate - expected_start) < abs(closest - expected_start):
            closest = candidate
        candidate = original.find(fragment, candidate + 1)
    return closest
