"""
扫描器模块

提供多扫描器适配、结果归一化、统一调度
"""

from .base import BaseScanner
from .semgrep_scanner import SemgrepScanner
from .bandit_scanner import BanditScanner
from .findsecbugs_scanner import FindSecBugsScanner
from .manager import ScannerManager
from .normalizer import ResultNormalizer

# JS 扫描器（可选）
try:
    from .js_scanner import JSScanner
except ImportError:
    JSScanner = None

# Python 扫描器（可选）
try:
    from .python_scanner import PythonScanner
except ImportError:
    PythonScanner = None

__all__ = [
    "BaseScanner",
    "SemgrepScanner",
    "BanditScanner",
    "FindSecBugsScanner",
    "JSScanner",
    "PythonScanner",
    "ScannerManager",
    "ResultNormalizer",
]
