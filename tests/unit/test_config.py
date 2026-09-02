"""
配置模块单元测试
"""

import pytest
from fp_sentinel.config import load_config, expand_db_path


class TestConfig:
    """配置测试"""

    def test_load_default_config(self):
        """加载默认配置"""
        config = load_config(None)
        assert config is not None
        assert config.database is not None

    def test_expand_db_path_home(self):
        """展开用户目录"""
        path = expand_db_path("~/.xuanjian/data.db")
        assert "~" not in path
        assert ".xuanjian" in path

    def test_expand_db_path_relative(self):
        """展开相对路径"""
        path = expand_db_path("./data.db")
        assert path.endswith("data.db")
