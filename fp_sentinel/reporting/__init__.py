"""
报告输出模块

支持 SARIF 2.1.0 等标准格式的结果导出
"""

from .sarif import to_sarif

__all__ = ["to_sarif"]
