# -*- coding: utf-8 -*-
"""RD-001 回归测试 —— 统一日志配置与 stdout 纯净性。

覆盖:
- configure_logging 幂等；重复调用不重复挂 sink;
- androguard / pyaxmlparser stdlib logger 被压到 ERROR;
- loguru 默认 DEBUG sink 被移除（androguard 55MB stderr 元凶）;
- FP_SENTINEL_MOBILE_VERBOSE 环境开关;
- 端到端: 真实 APK 上以子进程运行 insight scan，stdout 必须是可解析的纯 JSON
  （Round 1 失败场景: shell detect stdout 混入 128KB DEBUG 日志）。
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from fp_sentinel.mobile_common import QUIET_ENV_VAR, configure_logging
from fp_sentinel.mobile_common.logging_config import suppress_androguard_noise

REPO_ROOT = Path(__file__).resolve().parents[3]
SAMPLE_APK = (
    REPO_ROOT / "test_apps" / "2023移动安全培训：资料" / "3、第三阶段app漏洞"
    / "8.Android APP组件安全之Broadcast Receiver常见风险" / "InsecureBankv2.apk"
)


class TestConfigureLogging:
    def test_idempotent(self):
        configure_logging(force=True)
        n = len(logging.getLogger().handlers)
        assert n >= 1
        # 非强制调用幂等: handler 数量不变
        configure_logging()
        configure_logging()
        assert len(logging.getLogger().handlers) == n
        # force 重配后同样不叠加
        configure_logging(force=True)
        assert len(logging.getLogger().handlers) == n

    def test_noisy_loggers_suppressed(self):
        suppress_androguard_noise()
        for name in ("androguard", "androguard.core", "pyaxmlparser"):
            assert logging.getLogger(name).level == logging.ERROR

    def test_loguru_default_sink_removed(self):
        pytest.importorskip("loguru")
        from loguru import logger

        suppress_androguard_noise()
        # 只剩我们挂的受控 WARNING sink
        assert len(logger._core.handlers) <= 2
        # androguard 命名空间已被 disable：以该模块名记录 DEBUG 不进任何 sink
        import io
        import types

        buf = io.StringIO()
        logger.add(buf, level="DEBUG")
        mod = types.ModuleType("androguard.core.dex_probe")
        exec("from loguru import logger; logger.debug('RD001-SPAM')", mod.__dict__)
        assert "RD001-SPAM" not in buf.getvalue()

    def test_verbose_env_switch(self, monkeypatch):
        monkeypatch.setenv(QUIET_ENV_VAR, "1")
        configure_logging(force=True)
        assert logging.getLogger().level == logging.INFO
        monkeypatch.delenv(QUIET_ENV_VAR, raising=False)
        configure_logging(force=True)
        assert logging.getLogger().level == logging.WARNING

    def test_log_file_written(self, tmp_path):
        log_file = tmp_path / "run.log"
        configure_logging(force=True, log_file=str(log_file))
        logging.getLogger("fp_sentinel.test").info("hello-file")
        for h in logging.getLogger().handlers:
            h.flush()
        assert log_file.exists()


class TestStdoutPurity:
    def test_insight_scan_stdout_is_pure_json(self, tmp_path):
        """RD-001 端到端: 真实 APK + androguard 场景下 stdout 只含 JSON。"""
        if not SAMPLE_APK.exists():
            pytest.skip("InsecureBankv2.apk 不在测试靶场")
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run(
            [sys.executable, "-m", "fp_sentinel.mobile_insight.cli",
             "scan", str(SAMPLE_APK)],
            cwd=str(REPO_ROOT), env=env, capture_output=True, text=True,
            timeout=600,
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        # 核心断言: stdout 整体可解析为 JSON（Round 1 因混入日志而失败）
        payload = json.loads(proc.stdout)
        assert payload["insight_count"] > 0
        assert payload["rules_total"] == 67
