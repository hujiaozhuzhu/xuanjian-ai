"""Static, opt-in-safe preprocessors used by scanners."""

from .js_beautify import JSPreprocessResult, looks_heavily_obfuscated, looks_minified, preprocess_javascript

__all__ = [
    "JSPreprocessResult",
    "looks_heavily_obfuscated",
    "looks_minified",
    "preprocess_javascript",
]
