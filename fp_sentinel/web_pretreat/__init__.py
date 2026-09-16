"""web_pretreat —— 玄鉴AI Web 侧预处理能力。

提供：
- JS 压缩格式化、字符串提取、API 端点发现、可疑片段识别；
- 依赖环境审计（详见 :mod:`fp_sentinel.mobile_common.env_check`）；
- 与 :class:`~fp_sentinel.mobile_reporting.models.report_models.FindingReport` 的集成。
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
