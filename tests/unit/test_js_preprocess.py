"""Static preprocessing tests for minified JavaScript bundles."""

from unittest.mock import patch

import pytest

from fp_sentinel.preprocessors.js_beautify import (
    looks_heavily_obfuscated,
    looks_minified,
    preprocess_javascript,
)
from fp_sentinel.scanners.js_scanner import JSScanner


def _minified_bundle(statement: str) -> str:
    return (statement + ";") * 2048


def test_only_large_nearly_single_line_files_are_eligible():
    assert looks_minified(_minified_bundle("var a=1")) is True
    assert looks_minified("eval(userInput)") is False
    assert looks_minified(("var a=1;\n") * 2048) is False


def test_preprocessor_never_changes_regular_source():
    source = "const userInput = req.query.input;\neval(userInput);\n"

    result = preprocess_javascript(source)

    assert result.content == source
    assert result.used_beautifier is False
    assert result.warning is None


def test_heavy_obfuscation_detection_is_static_only():
    payload = "A" * 300

    assert looks_heavily_obfuscated(f"const x = atob('{payload}');") is True
    assert looks_heavily_obfuscated("const x = 1;") is False


def test_missing_beautifier_warns_and_keeps_original_content():
    source = _minified_bundle("eval(userInput)")
    with patch("fp_sentinel.preprocessors.js_beautify.jsbeautifier", None):
        result = preprocess_javascript(source)

    assert result.content == source
    assert result.used_beautifier is False
    assert result.reason == "beautifier_unavailable"
    assert "jsbeautifier" in result.warning


@pytest.mark.asyncio
async def test_minified_bundle_results_keep_original_line_and_add_formatted_line(tmp_path):
    bundle = tmp_path / "bundle.js"
    bundle.write_text(_minified_bundle("eval(userInput)"), encoding="utf-8")
    scanner = JSScanner(config={"check_dependencies": False, "check_hardcoded_secrets": False})

    results = await scanner.scan(str(bundle))
    eval_results = [result for result in results if "eval" in result.rule_id.lower()]

    assert len(eval_results) > 1
    first, result = eval_results[:2]
    assert result.line == 1
    assert result.metadata["preprocessed"] is True
    assert result.metadata["beautified_line"] > 1
    assert result.metadata["original_offset_hint"]["original_start"] > first.metadata["original_offset_hint"]["original_start"]


@pytest.mark.asyncio
async def test_heavily_obfuscated_bundle_warns_without_dynamic_processing(tmp_path):
    bundle = tmp_path / "obfuscated.js"
    payload = "A" * 300
    bundle.write_text(_minified_bundle(f"const x=atob('{payload}')"), encoding="utf-8")
    scanner = JSScanner(config={"check_dependencies": False, "check_hardcoded_secrets": False})

    await scanner.scan(str(bundle))

    assert any("不会动态解包或解密" in warning for warning in scanner.get_preprocess_warnings())
