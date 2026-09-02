"""
指纹工具单元测试
"""

import pytest
from fp_sentinel.utils.fingerprint import compute_fingerprint


class TestFingerprint:
    """指纹测试"""

    def test_compute_fingerprint_basic(self):
        """基本指纹计算"""
        fp = compute_fingerprint("semgrep", "js.xss.innerhtml", "app.js", "element.innerHTML = x", 10)
        assert isinstance(fp, str)
        assert len(fp) == 32  # MD5 hex

    def test_compute_fingerprint_deterministic(self):
        """相同输入产生相同指纹"""
        fp1 = compute_fingerprint("semgrep", "js.xss.innerhtml", "app.js", "element.innerHTML = x", 10)
        fp2 = compute_fingerprint("semgrep", "js.xss.innerhtml", "app.js", "element.innerHTML = x", 10)
        assert fp1 == fp2

    def test_compute_fingerprint_different(self):
        """不同输入产生不同指纹"""
        fp1 = compute_fingerprint("semgrep", "js.xss.innerhtml", "app.js", "element.innerHTML = x", 10)
        fp2 = compute_fingerprint("semgrep", "js.injection.eval", "app.js", "eval(x)", 20)
        assert fp1 != fp2
