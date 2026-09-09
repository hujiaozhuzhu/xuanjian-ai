"""
玄鉴 v3.1 — 设置页面 REST API 路由

挂载于 /api/settings/
支持配置项的自定义更新和掩码返回（敏感字段脱敏）。

路由清单：
  GET  /api/settings/                 — 获取全部配置（敏感项掩码）
  GET  /api/settings/{section}        — 获取指定配置段
  PUT  /api/settings/{section}        — 更新配置段
  GET  /api/settings/masked-fields    — 获取已掩码字段列表
  POST /api/settings/validate         — 验证配置有效性
  POST /api/settings/reset            — 重置为默认配置

安全红线：
- API Token、密码等敏感字段始终掩码返回
- 配置更新需符合类型约束
- 重置操作需confirm参数
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

settings_router = APIRouter(prefix="/api/settings", tags=["settings"])

# ─────────────────────────── 敏感字段定义 ───────────────────────────

# 需要掩码的敏感字段名（匹配规则：包含以下子字符串即视为敏感）
_SENSITIVE_KEY_PATTERNS: List[str] = [
    "token", "api_token", "secret", "password", "private_key",
    "credential", "access_key", "secret_key", "api_key",
    "auth_token", "client_secret", "encryption_key",
]

# 完全匹配即视为敏感的字段名
_SENSITIVE_EXACT: Set[str] = {
    "token", "api_token", "secret", "password", "private_key",
    "credential", "access_key", "secret_key", "api_key",
}


def _is_sensitive_field(field_name: str) -> bool:
    """判断字段是否为敏感字段"""
    name_lower = field_name.lower()
    if name_lower in _SENSITIVE_EXACT:
        return True
    for pattern in _SENSITIVE_KEY_PATTERNS:
        if pattern in name_lower:
            return True
    return False


def _mask_value(value: Any) -> str:
    """对敏感值进行掩码处理"""
    str_val = str(value)
    if len(str_val) <= 4:
        return "****"
    elif len(str_val) <= 12:
        return str_val[:2] + "*" * (len(str_val) - 4) + str_val[-2:]
    else:
        visible_prefix = min(4, len(str_val) // 4)
        visible_suffix = min(4, len(str_val) // 4)
        return str_val[:visible_prefix] + "*" * (len(str_val) - visible_prefix - visible_suffix) + str_val[-visible_suffix:]


def _mask_config_recursive(config: Dict[str, Any]) -> Dict[str, Any]:
    """递归掩码配置中的敏感字段"""
    masked = {}
    for key, value in config.items():
        if _is_sensitive_field(key):
            masked[key] = _mask_value(value)
        elif isinstance(value, dict):
            masked[key] = _mask_config_recursive(value)
        elif isinstance(value, list):
            masked[key] = [
                _mask_config_recursive(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            masked[key] = value
    return masked


# ─────────────────────────── 默认配置 ───────────────────────────

_DEFAULT_CONFIG: Dict[str, Any] = {
    "system": {
        "version": "3.1.0",
        "app_name": "玄鉴 XuanJian AI",
        "environment": "production",
        "debug": False,
        "listen_host": "127.0.0.1",
        "listen_port": 8080,
        "api_key_header": "X-API-Key",
    },
    "scan": {
        "default_scanners": ["semgrep", "bandit"],
        "max_file_size_mb": 5,
        "scan_timeout_seconds": 600,
        "parallel_workers": 4,
        "auto_baseline": True,
        "default_languages": ["python", "java", "javascript"],
    },
    "security": {
        "target_lock_localhost": True,
        "poc_generation_enabled": False,
        "poc_enable_env": "XUANJIAN_POC_ENABLE",
        "max_poc_targets": 10,
        "session_timeout_minutes": 30,
        "enable_audit_log": True,
    },
    "auto_pr": {
        "provider": "gitlab",
        "base_url": "",
        "api_token": "",
        "project_id": "",
        "default_branch": "main",
        "fix_branch_prefix": "xuanjian-fix/",
        "auto_verify": True,
        "auto_submit_pr": False,
        "dry_run_default": True,
        "max_fix_per_run": 50,
    },
    "industry_benchmark": {
        "auto_update": False,
        "update_interval_days": 30,
        "retention_days": 180,
    },
    "federated": {
        "default_encryption": "dp_noise",
        "default_epsilon": 1.0,
        "max_rounds": 100,
        "min_participants": 2,
    },
    "devops": {
        "default_provider": "gitlab",
        "webhook_secret": "",
        "auto_sync_findings": True,
        "auto_close_tickets": False,
    },
    "notifications": {
        "enabled": False,
        "webhook_url": "",
        "notify_on_critical": True,
        "channels": [],
    },
    "reporting": {
        "default_format": "html",
        "theme": "dark",
        "max_findings_per_report": 1000,
        "retention_days": 90,
    },
}

# 运行时配置存储
_runtime_config: Dict[str, Any] = {}


# ─────────────────────────── 请求模型 ─────────────────────────────

class UpdateSettingRequest(BaseModel):
    """更新配置请求"""
    model_config = ConfigDict(extra="ignore")

    values: Dict[str, Any] = Field(default_factory=dict, description="更新的配置值")


class ValidateConfigRequest(BaseModel):
    """验证配置请求"""
    model_config = ConfigDict(extra="ignore")

    section: str = Field(default="", description="配置段（空则验证全部）")
    values: Dict[str, Any] = Field(default_factory=dict, description="待验证值")


# ─────────────────────────── 配置获取 API ───────────────────────────

@settings_router.get("/")
async def get_all_settings():
    """
    获取全部配置（敏感项自动掩码）。

    Returns:
        全部配置（敏感字段已脱敏）
    """
    config = _get_effective_config()
    masked = _mask_config_recursive(config)

    return {
        "version": "3.1.0",
        "masked_fields": _get_masked_fields(config),
        "config": masked,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@settings_router.get("/{section}")
async def get_setting_section(section: str):
    """
    获取指定配置段（敏感项自动掩码）。

    Args:
        section: 配置段名称

    Returns:
        配置段内容（敏感字段已脱敏）
    """
    config = _get_effective_config()
    section_data = config.get(section)

    if section_data is None:
        available = list(config.keys())
        raise HTTPException(
            status_code=404,
            detail=f"配置段 '{section}' 不存在。可用段: {available}"
        )

    if isinstance(section_data, dict):
        masked = _mask_config_recursive(section_data)
    else:
        masked = section_data

    return {
        "section": section,
        "masked_fields": _get_masked_fields({section: section_data}).get(section, []),
        "config": masked,
    }


# ─────────────────────────── 配置更新 API ───────────────────────────

@settings_router.put("/{section}")
async def update_setting_section(section: str, request: UpdateSettingRequest):
    """
    更新指定配置段。

    Args:
        section: 配置段名称
        request: 更新请求

    Returns:
        更新后配置（敏感项自动掩码）
    """
    config = _get_effective_config()

    if section not in config:
        raise HTTPException(
            status_code=404,
            detail=f"配置段 '{section}' 不存在"
        )

    section_config = config.get(section, {})
    if not isinstance(section_config, dict):
        raise HTTPException(status_code=400, detail=f"配置段 '{section}' 不是对象类型")

    # 更新值
    for k, v in request.values.items():
        if k in section_config:
            # 类型检查
            old_val = section_config[k]
            if old_val is not None and not isinstance(v, type(old_val)):
                try:
                    v = type(old_val)(v)
                except (ValueError, TypeError):
                    raise HTTPException(
                        status_code=400,
                        detail=f"字段 '{k}' 类型不匹配，期望 {type(old_val).__name__}"
                    )
        section_config[k] = v

    config[section] = section_config
    _runtime_config[section] = section_config

    masked = _mask_config_recursive(section_config)

    return {
        "status": "updated",
        "section": section,
        "updated_fields": list(request.values.keys()),
        "config": masked,
    }


# ─────────────────────────── 掩码字段列表 API ───────────────────────────

@settings_router.get("/masked-fields")
async def list_masked_fields():
    """
    获取当前配置中已被掩码的字段列表。

    Returns:
        掩码字段清单
    """
    config = _get_effective_config()
    masked = _get_masked_fields(config)

    total_count = sum(len(v) for v in masked.values())

    return {
        "total_masked_fields": total_count,
        "masked_by_section": masked,
        "sensitive_patterns": _SENSITIVE_KEY_PATTERNS,
    }


# ─────────────────────────── 配置验证 API ───────────────────────────

@settings_router.post("/validate")
async def validate_config(request: ValidateConfigRequest):
    """
    验证配置有效性。

    Args:
        request: 验证请求

    Returns:
        验证结果
    """
    config = _get_effective_config()
    errors: List[str] = []
    warnings: List[str] = []

    if request.section:
        section_data = config.get(request.section, {})
        section_values = request.values if request.values else section_data
    else:
        section_values = request.values if request.values else {}

    for k, v in section_values.items():
        # 端口范围检查
        if "port" in k.lower() and isinstance(v, int):
            if v < 0 or v > 65535:
                errors.append(f"字段 '{k}': 端口值 {v} 超出有效范围 0-65535")

        # 超时范围检查
        if "timeout" in k.lower() and isinstance(v, int):
            if v <= 0:
                warnings.append(f"字段 '{k}': 超时值 {v} 不合理（建议 > 0）")

        # 严重度检查
        if k.lower() == "severity" and isinstance(v, str):
            valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
            if v.upper() not in valid_severities:
                errors.append(f"字段 '{k}': 无效严重度 '{v}'")

    is_valid = len(errors) == 0

    return {
        "valid": is_valid,
        "errors": errors,
        "warnings": warnings,
        "checked_fields": list(request.values.keys()) if request.values else list(config.keys()),
    }


# ─────────────────────────── 配置重置 API ───────────────────────────

@settings_router.post("/reset")
async def reset_config(
    section: str = Query("", description="重置指定段（空则重置全部）"),
    confirm: bool = Query(False, description="确认重置（必须为True）"),
):
    """
    重置配置为默认值。

    Args:
        section: 配置段名称（空则重置全部）
        confirm: 确认标志（必须为True）

    Returns:
        重置后的配置
    """
    if not confirm:
        raise HTTPException(
            status_code=403,
            detail="重置操作需要设置 confirm=true 确认"
        )

    if section:
        if section not in _DEFAULT_CONFIG:
            raise HTTPException(status_code=404, detail=f"配置段 '{section}' 不存在")
        _runtime_config[section] = dict(_DEFAULT_CONFIG[section])
        reset_data = _DEFAULT_CONFIG[section]
    else:
        _runtime_config.clear()
        reset_data = _DEFAULT_CONFIG

    masked = _mask_config_recursive(reset_data) if isinstance(reset_data, dict) else reset_data

    return {
        "status": "reset",
        "section": section or "all",
        "config": masked,
    }


# ─────────────────────────── 辅助函数 ───────────────────────────

def _get_effective_config() -> Dict[str, Any]:
    """获取有效配置（合并默认和运行时配置）"""
    import copy
    config = copy.deepcopy(_DEFAULT_CONFIG)

    # 合并运行时配置
    for section, values in _runtime_config.items():
        if section in config and isinstance(config[section], dict):
            config[section].update(values)
        else:
            config[section] = values

    # 环境变量覆盖
    env_mappings = {
        ("system", "debug"): "XUANJIAN_DEBUG",
        ("system", "listen_port"): "XUANJIAN_PORT",
        ("system", "listen_host"): "XUANJIAN_HOST",
        ("auto_pr", "api_token"): "XUANJIAN_PR_TOKEN",
        ("auto_pr", "base_url"): "XUANJIAN_PR_URL",
        ("devops", "webhook_secret"): "XUANJIAN_WEBHOOK_SECRET",
    }

    for (section, key), env_var in env_mappings.items():
        env_val = os.environ.get(env_var)
        if env_val is not None and section in config:
            if isinstance(config[section], dict):
                # 类型转换
                default_val = _DEFAULT_CONFIG.get(section, {}).get(key)
                if isinstance(default_val, bool):
                    config[section][key] = env_val.lower() in ("true", "1", "yes")
                elif isinstance(default_val, int):
                    try:
                        config[section][key] = int(env_val)
                    except ValueError:
                        config[section][key] = env_val
                else:
                    config[section][key] = env_val

    # 更新版本号
    if "system" in config and isinstance(config["system"], dict):
        config["system"]["version"] = "3.1.0"

    return config


def _get_masked_fields(config: Dict[str, Any], prefix: str = "") -> Dict[str, List[str]]:
    """获取配置中所有被掩码的字段"""
    result: Dict[str, List[str]] = {}

    for key, value in config.items():
        full_key = f"{prefix}.{key}" if prefix else key

        if isinstance(value, dict):
            nested = _get_masked_fields(value, full_key)
            for k, v in nested.items():
                result[k] = v
        elif _is_sensitive_field(key):
            section = prefix.split(".")[0] if prefix else "_root"
            if section not in result:
                result[section] = []
            result[section].append(key)

    return result
