"""统一日志配置（RD-001 修复）。

问题背景（Round 1 专家反馈 RD-001）:
    androguard 4.x 经 loguru 向 stderr 透传海量 DEBUG 日志 ——
    ``hook recommend`` 单次运行 stderr 达 55MB；``shell detect`` stdout
    混入 128KB DEBUG 日志导致 ``json.load`` 解析失败。

本模块提供全移动端统一的日志出口:

1. **loguru**（androguard 4.x 的日志后端）:
   - 移除默认 stderr sink；
   - ``logger.disable("androguard")`` 直接禁用 androguard 噪音；
   - 默认仅 WARNING 级以上输出到 stderr，可用 ``verbose=True`` 放开。
2. **stdlib logging**:
   - root 级别 WARNING；
   - ``androguard`` 及其子 logger 强制 ERROR；
   - 可选 ``log_file`` 把业务/调试日志写入文件（DEBUG 级）。
3. **环境开关**: ``FP_SENTINEL_MOBILE_VERBOSE=1`` 等价 ``verbose=True``，
   便于 CI / 排障时不改代码。

铁律: 任何情况下 stdout 只承载业务结果；日志只进 stderr 或日志文件。
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Optional

__all__ = ["configure_logging", "QUIET_ENV_VAR", "suppress_androguard_noise"]

#: 设为 ``1``/``true`` 时放开 INFO 级日志（stderr），便于排障。
QUIET_ENV_VAR = "FP_SENTINEL_MOBILE_VERBOSE"

_CONFIGURED = False

# androguard 及其高频噪音子 logger 一律压到 ERROR
_NOISY_LOGGERS = (
    "androguard",
    "androguard.core",
    "androguard.core.dex",
    "androguard.core.analysis",
    "androguard.core.api",
    "pyaxmlparser",
)


def _env_verbose() -> bool:
    return os.environ.get(QUIET_ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


def suppress_androguard_noise() -> None:
    """压制 androguard / loguru 的 DEBUG 噪音（幂等，可重复调用）。

    - loguru: 移除默认 sink 并禁用 androguard 记录器；
    - stdlib: androguard 相关 logger 强制 ERROR 级。
    """
    # ---- loguru（androguard 4.x 后端） ----
    try:
        from loguru import logger as loguru_logger

        # 移除 loguru 默认 stderr handler（DEBUG 级，Round 1 的 55MB 元凶）
        loguru_logger.remove()
        # 直接禁用 androguard 命名空间，任何级别都不再产出
        loguru_logger.disable("androguard")
        # 重新挂一个受控 stderr sink: 仅 WARNING+，且排除 androguard
        loguru_logger.add(
            sys.stderr,
            level="WARNING",
            filter=lambda record: not record["name"].startswith("androguard"),
            enqueue=False,
        )
    except Exception:  # pragma: no cover - 未安装 loguru 时忽略
        pass

    # ---- stdlib logging ----
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.ERROR)
    # 兜底: androguard 的任何子 logger 也压到 ERROR
    logging.getLogger("androguard").setLevel(logging.ERROR)


def configure_logging(
    verbose: bool = False,
    log_file: Optional[str] = None,
    force: bool = False,
) -> None:
    """移动端 CLI 统一日志入口（幂等）。

    Parameters
    ----------
    verbose:
        True 时 stderr 放开到 INFO 级（业务结果仍在 stdout，互不污染）。
    log_file:
        若给出，DEBUG 级全量日志写入该文件（供排障留档）。
    force:
        重复调用时是否强制重配（默认幂等跳过）。
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return
    _CONFIGURED = True

    if _env_verbose():
        verbose = True

    suppress_androguard_noise()

    root = logging.getLogger()
    root.setLevel(logging.INFO if verbose else logging.WARNING)
    # 清掉 stdlib 默认 handler，重建到 stderr（绝不进 stdout）
    for handler in list(root.handlers):
        root.removeHandler(handler)
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    root.addHandler(stream)

    if log_file:
        try:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            )
            root.addHandler(fh)
        except OSError:  # 日志文件不可写不应阻断业务
            root.warning("日志文件不可写: %s", log_file)
