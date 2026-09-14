"""fp_sentinel.mobile_reporting.core —— 移动报告核心处理层。

提供：
- ScreenshotManager: 截图登记与完整性校验；
- DataCollector: 扫描产物 JSON -> MobileSecurityReport；
- PocExpIntegrator: POC/EXP 集成与安全红线检查；
- ReproducibilityManager: 环境采集与双平台复现脚本生成。
"""

from .data_collector import DataCollector
from .poc_exp_integrator import DANGEROUS_PATTERNS, PocExpIntegrator
from .reproducibility import ReproducibilityManager
from .screenshot_manager import ScreenshotManager

__all__ = [
    "ScreenshotManager",
    "DataCollector",
    "PocExpIntegrator",
    "DANGEROUS_PATTERNS",
    "ReproducibilityManager",
]
