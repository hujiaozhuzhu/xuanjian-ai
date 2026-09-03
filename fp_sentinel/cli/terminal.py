"""CLI terminal compatibility helpers.

The CLI never changes the host terminal code page. Instead, output is safely
transcoded and Unicode status symbols are replaced when the active stream
cannot represent them.
"""

import sys
from typing import Optional, TextIO

from rich.console import Console


ASCII_ENCODINGS = {"ascii", "us-ascii", "ansi_x3.4-1968"}
EMOJI_MAP = {
    "\u26a0\ufe0f": "[WARN]",
    "\u26a0": "[WARN]",
    "\U0001f50d": "[SCAN]",
    "\u2705": "[OK]",
    "\u2713": "[OK]",
    "\u2717": "[ERROR]",
    "\U0001f4ca": "[STATS]",
    "\U0001f4c4": "[REPORT]",
    "\U0001f464": "[PROFILE]",
    "\U0001f512": "[LOCK]",
    "\U0001f9ea": "[TEST]",
    "\U0001f6e1\ufe0f": "[SAFE]",
    "\U0001f6e1": "[SAFE]",
    "\U0001f3af": "[TARGET]",
}


def supports_unicode(stream: Optional[TextIO] = None) -> bool:
    """Return whether a text stream can safely render Unicode status symbols."""
    encoding = (getattr(stream or sys.stdout, "encoding", None) or "").lower()
    return encoding.startswith("utf") or encoding.startswith("utf-")


def _ascii_markers(text: str) -> str:
    for symbol, replacement in EMOJI_MAP.items():
        text = text.replace(symbol, replacement)
    return text


class EncodingSafeStream:
    """Proxy a text stream while preventing encoding errors from terminating CLI output."""

    def __init__(self, stream: Optional[TextIO] = None):
        self._stream = stream

    @property
    def stream(self) -> TextIO:
        return self._stream or sys.stdout

    @property
    def encoding(self) -> Optional[str]:
        return getattr(self.stream, "encoding", None)

    def write(self, text: str) -> int:
        if not supports_unicode(self.stream):
            text = _ascii_markers(text)

        encoding = self.encoding
        if encoding:
            text = text.encode(encoding, errors="backslashreplace").decode(encoding)
        return self.stream.write(text)

    def flush(self) -> None:
        self.stream.flush()

    def isatty(self) -> bool:
        return bool(getattr(self.stream, "isatty", lambda: False)())

    def fileno(self) -> int:
        return self.stream.fileno()

    def __getattr__(self, name: str):
        return getattr(self.stream, name)


def create_console(stream: Optional[TextIO] = None) -> Console:
    """Build a Rich console that safely degrades on legacy Windows encodings."""
    unicode_supported = supports_unicode(stream)
    return Console(
        file=EncodingSafeStream(stream),
        emoji=unicode_supported,
        legacy_windows=not unicode_supported,
    )
