# -*- coding: utf-8 -*-
"""玄鉴 v4.0 —— mobile_hook 自动化 Hook 定位引擎。

能力定义（规划文档 2.3）：基于反编译结果 + 静态分析 + 动态追踪，
自动化推荐最优 Hook 点位。

- 7 种定位技法（隐雾课程体系）：keyword / collection / toast / log /
  json / string / base64；
- 关键性评分：包名相关 30% + 方法特征 25% + 调用链 15% +
  字符串特征 20% + 历史经验 10%；
- 调用链分析：基于 androguard 的类间调用关系，深度默认 12（>=10）；
- Frida 不可用时自动降级为纯静态分析；Hook 验证为 mock 化，不连设备；
- Native Hook 模板引擎：ssl_pinning_bypass / jni_function_trace / crypto_native /
  okhttp3_interceptor / shared_preferences_dump / sqlite_query_hook；
- 抓包事件导出器（CaptureExporter）：HAR 1.2 / JSONL / Markdown 摘要。

CLI::

    fp-sentinel mobile hook recommend|technique|scan|verify
"""

__version__ = "4.0.0"

from .core.capture_exporter import CaptureEvent, CaptureExporter, export_events

__all__ = [
    "__version__",
    "CaptureEvent",
    "CaptureExporter",
    "export_events",
]
