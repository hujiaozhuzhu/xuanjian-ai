"""玄鉴 fp_sentinel - Web API 安全审计模块。

提供 API 端点发现、敏感度分级、越权只读探测和报告汇总，
产出标准 :class:`FindingReport`，可被移动端报告模块直接渲染。

子模块：

- :mod:`fp_sentinel.web_api.api_discovery`：多源端点发现
- :mod:`fp_sentinel.web_api.endpoints_models`：统一端点数据模型
- :mod:`fp_sentinel.web_api.classifier`：端点敏感度分类
- :mod:`fp_sentinel.web_api.privilege_scan`：越权只读探测
- :mod:`fp_sentinel.web_api.report`：报告聚合
- :mod:`fp_sentinel.web_api.cli`：命令行入口
"""

from __future__ import annotations

from .endpoints_models import ApiEndpoint, FindingReport

__version__ = "1.0.0"
__all__ = ["ApiEndpoint", "FindingReport"]
