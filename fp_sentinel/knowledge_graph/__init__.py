"""
玄鉴 v2.5.1 — 知识图谱查询与自动归档模块 (Knowledge Graph)

提供两项子功能：
(a) 查询插件  —— 扫描时按规则 CWE / 分类自动从归档中匹配同类漏洞、修复建议、CVE 案例，
                 并把命中结果注入 Finding.metadata 与扫描报告的「⑦ 知识图谱参考」章节。
(b) 自动归档 —— 每次扫描完成后自动将完整报告 + 漏洞数据归档到本地 SQLite 知识图谱，
                 支持按项目 / 版本 / 漏洞类型 / 时间范围快速检索。

零网络、零代码修改、零文件写入源目录（S1 / S2 / S7 全部满足）。
"""

from .features.query_plugin import KnowledgeQueryPlugin, score_match
from .features.report_enricher import (
    append_reference_to_report,
    build_reference_section,
    inject_finding_metadata,
    summarize,
)
from .features.auto_archive import AutoArchiver, archive_scan
from .models import (
    ArchiveQuery,
    FixRecord,
    FixSnapshot,
    KnowledgeMatch,
)

__all__ = [
    "KnowledgeQueryPlugin",
    "score_match",
    "AutoArchiver",
    "archive_scan",
    "inject_finding_metadata",
    "build_reference_section",
    "append_reference_to_report",
    "summarize",
    "FixRecord",
    "FixSnapshot",
    "KnowledgeMatch",
    "ArchiveQuery",
]
