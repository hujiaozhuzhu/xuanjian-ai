"""
玄鉴 v3.0 — 自动化修复模块 (Auto PR)

核心能力：
- 自动修复代码生成：基于漏洞类型自动生成可落地的修复代码，支持Diff预览、自定义修改
- Git仓库对接：自动将修复代码提交到GitLab/GitHub，创建修复PR，自动关联对应漏洞工单
- 修复验证：提交PR前自动验证修复代码的有效性，确保不会引入新的漏洞
- PR管理：支持查看PR状态、合并结果、修复历史记录

安全红线：
- S1: 外部调用全部通过适配器注入，测试可 mock
- S2: 不直接修改被扫描源文件（仅生成修复patch/PR）
- S3: 不删除文件（本地操作只增不改不删）
- S5: 数据保留周期可配置
- S7: 数据库路径固定于 ~/.xuanjian/
"""

from .models import (
    AutoPRConfig,
    FixDiff,
    FixPatch,
    FixPreview,
    FixRecord,
    FixStatus,
    FixVerificationResult,
    PRStats,
    PullRequestRecord,
    VerificationStatus,
    VulnerabilityType,
)
from .auto_fix_generator import AutoFixGenerator, generate_fix_preview
from .fix_validator import FixValidator
from .pr_manager import PRManager
from .service import AutoPRService

__all__ = [
    "AutoPRConfig",
    "FixDiff",
    "FixPatch",
    "FixPreview",
    "FixRecord",
    "FixStatus",
    "FixVerificationResult",
    "PRStats",
    "PullRequestRecord",
    "VerificationStatus",
    "VulnerabilityType",
    "AutoFixGenerator",
    "generate_fix_preview",
    "FixValidator",
    "PRManager",
    "AutoPRService",
]

__version__ = "3.1.0"
