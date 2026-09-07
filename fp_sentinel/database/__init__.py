"""
数据库层

SQLite 异步数据库，WAL 模式，包含连接管理和仓库层
"""

from .connection import Database, get_database
from .repositories import ProjectRepo, FindingRepo, FPMarkRepo, ScanHistoryRepo
from .enterprise_init import (
    DEFAULT_ADMIN_USERNAME,
    _ADMIN_INIT_DETAIL,
    create_default_admin,
    initialize_all_enterprise_dbs,
    initialize_enterprise_database,
)

__all__ = [
    "Database",
    "get_database",
    "ProjectRepo",
    "FindingRepo",
    "FPMarkRepo",
    "ScanHistoryRepo",
    # v2.5.1 企业统一初始化
    "initialize_enterprise_database",
    "initialize_all_enterprise_dbs",
    "create_default_admin",
    "DEFAULT_ADMIN_USERNAME",
    "_ADMIN_INIT_DETAIL",
]
