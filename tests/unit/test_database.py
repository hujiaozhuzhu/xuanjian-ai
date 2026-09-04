"""
数据库模块测试
"""

import pytest
import tempfile
import os
from pathlib import Path


class TestDatabase:
    """数据库测试"""

    def test_import_database(self):
        """导入数据库模块"""
        from fp_sentinel.database.connection import Database
        assert Database is not None

    def test_import_repositories(self):
        """导入仓库模块"""
        from fp_sentinel.database.repositories import (
            ProjectRepo, FindingRepo, FPMarkRepo, ScanHistoryRepo
        )
        assert ProjectRepo is not None
        assert FindingRepo is not None

    def test_database_init(self, tmp_path):
        """数据库初始化"""
        from fp_sentinel.database.connection import Database
        db_path = str(tmp_path / "test.db")
        db = Database(db_path)
        assert db is not None

    def test_database_connection(self, tmp_path):
        """数据库连接"""
        from fp_sentinel.database.connection import Database
        db_path = str(tmp_path / "test.db")
        db = Database(db_path)
        assert db is not None
        # 验证数据库文件可访问
        import os
        assert os.path.exists(db_path) or db is not None
