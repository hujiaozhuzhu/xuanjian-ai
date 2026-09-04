"""CLI terminal compatibility tests."""

import io

from fp_sentinel.cli.terminal import EncodingSafeStream, create_console, supports_unicode


class _GBKStream(io.StringIO):
    encoding = "gbk"


class _ASCIIStream(io.StringIO):
    encoding = "ascii"


class _UTF8Stream(io.StringIO):
    encoding = "utf-8"


def test_gbk_stream_preserves_chinese_and_replaces_status_symbols():
    stream = _GBKStream()
    safe_stream = EncodingSafeStream(stream)

    safe_stream.write("\U0001f50d 正在扫描 \u2713")

    assert stream.getvalue() == "[SCAN] 正在扫描 [OK]"


def test_ascii_stream_never_raises_for_unicode_output():
    stream = _ASCIIStream()
    safe_stream = EncodingSafeStream(stream)

    safe_stream.write("\u26a0\ufe0f 玄鉴")

    assert stream.getvalue() == "[WARN] \\u7384\\u9274"


def test_legacy_encoding_degrades_console_output():
    stream = _GBKStream()

    assert supports_unicode(stream) is False
    create_console(stream).print("\U0001f50d 正在扫描")
    assert "[SCAN] 正在扫描" in stream.getvalue()


def test_utf8_stream_keeps_unicode_rendering():
    assert supports_unicode(_UTF8Stream()) is True
