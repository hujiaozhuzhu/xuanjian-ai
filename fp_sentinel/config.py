"""
配置管理

支持 YAML 配置文件加载、环境变量覆盖、默认配置回退
"""

import os
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ─────────────────────── 默认配置 ───────────────────────

DEFAULT_CONFIG: Dict[str, Any] = {
    "project": {
        "name": "default",
        "path": ".",
        "language": "auto",
    },
    "scanners": {
        "semgrep": {
            "enabled": True,
            "timeout": 300,
            "jobs": 2,
            "ignore_paths": [],
        },
        "bandit": {
            "enabled": True,
            "timeout": 300,
            "ignore_paths": [],
        },
        "findsecbugs": {
            "enabled": True,
            "spotbugs_path": "spotbugs",
            "findsecbugs_jar": "",
            "timeout": 600,
            "effort": "max",
        },
    },
    "filters": {
        "rule_filter": {
            "enabled": True,
            "path_whitelist": [],
            "code_ignore_patterns": [],
            "custom_rules": [],
        },
        "context_filter": {
            "enabled": True,
        },
        "ml_filter": {
            "enabled": False,
        },
    },
    "database": {
        "path": "~/.xuanjian/data.db",
        "wal_mode": True,
    },
    "output": {
        "format": "table",
        "verbose": False,
    },
}


# ─────────────────────── 配置数据类 ───────────────────────

class DatabaseConfig(BaseModel):
    """数据库配置"""
    path: str = Field("~/.xuanjian/data.db", description="SQLite 数据库路径")
    wal_mode: bool = Field(True, description="启用 WAL 模式")


class ScannerEntryConfig(BaseModel):
    """单个扫描器配置"""
    enabled: bool = Field(True, description="是否启用")
    timeout: int = Field(300, description="超时(秒)")
    jobs: int = Field(2, description="并行度")
    ignore_paths: List[str] = Field(default_factory=list, description="忽略路径")
    spotbugs_path: str = Field("spotbugs", description="SpotBugs 可执行文件路径")
    findsecbugs_jar: str = Field("", description="FindSecBugs JAR 路径")
    effort: str = Field("max", description="SpotBugs 分析力度")


class FiltersConfig(BaseModel):
    """过滤器配置"""
    rule_filter: Dict[str, Any] = Field(default_factory=dict)
    context_filter: Dict[str, Any] = Field(default_factory=dict)
    ml_filter: Dict[str, Any] = Field(default_factory=dict)


class AppConfig(BaseModel):
    """应用主配置"""
    project: Dict[str, Any] = Field(default_factory=dict)
    scanners: Dict[str, Any] = Field(default_factory=dict)
    filters: FiltersConfig = Field(default_factory=FiltersConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    output: Dict[str, Any] = Field(default_factory=dict)


# ─────────────────────── 配置加载 ───────────────────────

def deep_merge(base: dict, override: dict) -> dict:
    """
    深度合并两个字典，override 优先
    """
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _apply_env_overrides(config: dict) -> dict:
    """
    从环境变量覆盖配置
    例如 XUANJIAN_DB_PATH -> database.path
    """
    env_map = {
        "XUANJIAN_DB_PATH": ("database", "path"),
        "XUANJIAN_DB_WAL": ("database", "wal_mode"),
        "XUANJIAN_SEMGREP_ENABLED": ("scanners", "semgrep", "enabled"),
        "XUANJIAN_SEMGREP_TIMEOUT": ("scanners", "semgrep", "timeout"),
        "XUANJIAN_BANDIT_ENABLED": ("scanners", "bandit", "enabled"),
        "XUANJIAN_FINDSECBUGS_ENABLED": ("scanners", "findsecbugs", "enabled"),
        "XUANJIAN_FINDSECBUGS_JAR": ("scanners", "findsecbugs", "findsecbugs_jar"),
        "XUANJIAN_PROJECT_PATH": ("project", "path"),
        "XUANJIAN_PROJECT_LANGUAGE": ("project", "language"),
    }
    for env_var, path in env_map.items():
        value = os.environ.get(env_var)
        if value is not None:
            # 类型转换
            if value.lower() in ("true", "1", "yes"):
                value = True
            elif value.lower() in ("false", "0", "no"):
                value = False
            elif value.isdigit():
                value = int(value)

            # 逐层设置
            d = config
            for key in path[:-1]:
                d = d.setdefault(key, {})
            d[path[-1]] = value

    return config


def load_config(
    config_path: Optional[str] = None,
    overrides: Optional[Dict[str, Any]] = None,
) -> AppConfig:
    """
    加载配置

    优先级: defaults < yaml file < env vars < explicit overrides

    Args:
        config_path: YAML 配置文件路径，None 则使用默认路径
        overrides: 编程方式传入的覆盖值

    Returns:
        AppConfig: 解析后的配置对象
    """
    # 从默认值开始
    config = DEFAULT_CONFIG.copy()

    # 尝试加载 YAML 文件
    paths_to_try = []
    if config_path:
        paths_to_try.append(config_path)
    else:
        paths_to_try.extend([
            os.path.join(os.getcwd(), "xuanjian.yaml"),
            os.path.join(os.getcwd(), "xuanjian.yml"),
            os.path.expanduser("~/.xuanjian/config.yaml"),
            os.path.expanduser("~/.xuanjian/config.yml"),
        ])

    for p in paths_to_try:
        p = os.path.expanduser(p)
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    file_config = yaml.safe_load(f) or {}
                config = deep_merge(config, file_config)
                logger.info(f"Loaded config from: {p}")
                break
            except Exception as e:
                logger.warning(f"Failed to load config from {p}: {e}")

    # 环境变量覆盖
    config = _apply_env_overrides(config)

    # 编程方式覆盖
    if overrides:
        config = deep_merge(config, overrides)

    # 构建 AppConfig 对象
    try:
        return AppConfig(**config)
    except Exception as e:
        logger.error(f"Failed to parse config: {e}, falling back to defaults")
        return AppConfig()


def get_scanner_config(config: AppConfig, scanner_name: str) -> Dict[str, Any]:
    """
    获取特定扫描器的配置

    Args:
        config: 应用配置
        scanner_name: 扫描器名称

    Returns:
        dict: 扫描器配置字典
    """
    return config.scanners.get(scanner_name, {})


def get_filter_config(config: AppConfig, filter_name: str) -> Dict[str, Any]:
    """
    获取特定过滤器的配置

    Args:
        config: 应用配置
        filter_name: 过滤器名称

    Returns:
        dict: 过滤器配置字典
    """
    return getattr(config.filters, filter_name, {})


def expand_db_path(path: str) -> str:
    """
    展开数据库路径中的 ~ 和环境变量

    Args:
        path: 原始路径

    Returns:
        str: 展开后的绝对路径
    """
    expanded = os.path.expanduser(os.path.expandvars(path))
    os.makedirs(os.path.dirname(expanded), exist_ok=True)
    return expanded
