"""mobile_decompile 测试共享工具。

- 定位真实测试靶场 APK（InsecureBankv2.apk），缺失时相关集成测试自动跳过；
- 进程级共享 DexParser（避免重复解析同一 APK）；
- 压制 androguard 的 loguru 调试日志。
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
TEST_APPS_DIR = REPO_ROOT / "test_apps"
INSECURE_BANK_NAME = "InsecureBankv2.apk"


def find_insecure_bank_apk() -> Optional[Path]:
    """在 test_apps 下递归定位 InsecureBankv2.apk。"""
    root = os.environ.get("XUANJIAN_TEST_APK")
    if root and Path(root).exists():
        return Path(root)
    if not TEST_APPS_DIR.exists():
        return None
    hits = sorted(TEST_APPS_DIR.rglob(INSECURE_BANK_NAME))
    return hits[0] if hits else None


INSECURE_BANK_APK = find_insecure_bank_apk()

requires_insecure_bank = pytest.mark.skipif(
    INSECURE_BANK_APK is None,
    reason=f"测试靶场 APK 不可用: {INSECURE_BANK_NAME} (test_apps)",
)


def suppress_androguard_logs() -> None:
    """移除 loguru 默认 handler，避免 androguard 刷屏。"""
    try:
        from loguru import logger

        logger.remove()
    except Exception:  # pragma: no cover - 未安装 loguru 时忽略
        pass


@pytest.fixture(scope="session")
def insecure_bank_parser():
    """会话级共享 DexParser（真实 APK，不强制 xref）。"""
    if INSECURE_BANK_APK is None:  # pragma: no cover
        pytest.skip("测试靶场 APK 不可用")
    suppress_androguard_logs()
    from fp_sentinel.mobile_decompile.parsers.dex_parser import get_dex_parser

    # 通过 lru_cache 获取，与 CLI 子命令共享同一实例
    return get_dex_parser(str(INSECURE_BANK_APK))
