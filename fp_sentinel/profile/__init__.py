"""
开发者画像（核三）

安全红线：
- git 命令只读（log/blame/show），禁止任何 git 写操作；
- 画像数据仅本地 SQLite，禁止网络上传；
- 默认 SHA256 别名化，不存明文 email。
"""

from .models import (  # noqa: F401
    AttributionRecord,
    DeveloperProfile,
    FindingStatus,
    ProfileRepo,
    TeamProfile,
    UNKNOWN_ALIAS,
    alias_hash,
    ensure_profile_tables,
)
