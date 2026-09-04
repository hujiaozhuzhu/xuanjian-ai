"""
配置模块完整测试
"""

import pytest
import tempfile
import os
import yaml
from pathlib import Path
from fp_sentinel.config import load_config, expand_db_path, AppConfig


class TestConfigFull:
    """配置模块完整测试"""

    def test_load_default_config(self):
        """加载默认配置"""
        config = load_config(None)
        assert config is not None
        assert isinstance(config, AppConfig)
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

    def test_expand_db_path_absolute(self):
        """绝对路径不变"""
        path = expand_db_path("/tmp/test.db")
        assert path == "/tmp/test.db"

    def test_load_config_from_yaml(self, tmp_path):
        """从YAML加载配置"""
        config_data = {
            "project": {
                "name": "test-project",
                "path": "/tmp/test",
                "language": "javascript",
            },
            "scanners": {
                "semgrep": {"enabled": True, "timeout": 300},
                "bandit": {"enabled": False},
            },
            "database": {
                "path": "/tmp/test.db",
                "wal_mode": True,
            },
        }
        config_file = tmp_path / "xuanjian.yaml"
        config_file.write_text(yaml.dump(config_data))

        config = load_config(str(config_file))
        assert config is not None

    def test_load_config_from_json(self, tmp_path):
        """从JSON加载配置"""
        import json
        config_data = {
            "project": {
                "name": "test-project",
                "path": "/tmp/test",
                "language": "python",
            },
        }
        config_file = tmp_path / "xuanjian.json"
        config_file.write_text(json.dumps(config_data))

        config = load_config(str(config_file))
        assert config is not None

    def test_load_nonexistent_config(self):
        """加载不存在的配置文件"""
        config = load_config("/nonexistent/config.yaml")
        assert config is not None  # 应返回默认配置

    def test_config_scanner_defaults(self):
        """扫描器默认配置"""
        config = load_config(None)
        assert config.scanners is not None

    def test_config_filter_defaults(self):
        """过滤器默认配置"""
        config = load_config(None)
        assert config.filters is not None
