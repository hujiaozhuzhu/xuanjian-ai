"""mobile_common —— 玄鉴 v4.0 移动端模块共享基础设施。

当前提供:
- logging_config.configure_logging: 统一日志出口（RD-001 修复）。

约束: 业务结果走 stdout，日志一律走 stderr 或文件；
androguard/loguru 的 DEBUG 噪音默认全部压制。
"""

from .logging_config import configure_logging, QUIET_ENV_VAR

__all__ = ["configure_logging", "QUIET_ENV_VAR"]
