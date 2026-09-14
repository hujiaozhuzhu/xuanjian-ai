"""pytest 共享 fixture（pytest 只从 conftest.py 收集 fixture）。"""

from __future__ import annotations

import pytest

from . import INSECURE_BANK_APK, suppress_androguard_logs


@pytest.fixture(scope="session")
def insecure_bank_parser():
    """会话级共享 DexParser（真实 APK，不强制 xref；与 CLI 共享 lru 缓存）。"""
    if INSECURE_BANK_APK is None:  # pragma: no cover
        pytest.skip("测试靶场 APK 不可用")
    suppress_androguard_logs()
    from fp_sentinel.mobile_decompile.parsers.dex_parser import get_dex_parser

    return get_dex_parser(str(INSECURE_BANK_APK))
