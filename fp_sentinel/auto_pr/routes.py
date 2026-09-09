"""
玄鉴 v3.1 — 自动修复PR模块 REST API 路由

FastAPI 路由组，统一挂载于 /api/auto-pr/
所有端点符合安全红线，PR提交强制dry_run优先。

路由清单：
  POST /api/auto-pr/preview              — 修复预览（批量生成Diff预览）
  POST /api/auto-pr/verify               — 三重校验（原漏洞修复+新漏洞引入+语法）
  POST /api/auto-pr/create               — 创建PR（强制dry_run优先，需confirm二次确认）
  GET  /api/auto-pr/status/{record_id}   — 查询修复状态
  GET  /api/auto-pr/history               — 修复历史记录
  GET  /api/auto-pr/stats                — PR统计
  GET  /api/auto-pr/config               — 当前配置（敏感项掩码返回）
  PUT  /api/auto-pr/config               — 更新配置

安全红线：
- PR创建强制 dry_run 模式优先，confirm=true 才可执行真实提交
- 三重校验：原漏洞修复 + 无新漏洞引入 + 语法有效
- 所有Git操作通过适配器注入，可mock测试
- 不修改源文件、不删除文件
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

auto_pr_router = APIRouter(prefix="/api/auto-pr", tags=["auto-pr"])

# ─────────────────────────── 请求模型 ───────────────────────────

class PreviewRequest(BaseModel):
    """修复预览请求"""
    model_config = ConfigDict(extra="ignore")

    findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="发现列表，每项包含finding_id/rule_id/severity/file_path/code_snippet等"
    )


class VerifyRequest(BaseModel):
    """修复验证请求"""
    model_config = ConfigDict(extra="ignore")

    patch_id: str = Field(default="", description="补丁ID")
    finding_id: str = Field(..., description="发现ID")
    original_code: str = Field("", description="原始代码")
    fixed_code: str = Field("", description="修复后代码")
    rule_id: str = Field("", description="规则ID")
    vuln_type: str = Field("generic", description="漏洞类型")


class VerifyTripleRequest(BaseModel):
    """三重校验请求"""
    model_config = ConfigDict(extra="ignore")

    patch_id: str = Field(default="", description="补丁ID")
    finding_id: str = Field(..., description="发现ID")
    original_code: str = Field("", description="原始代码")
    fixed_code: str = Field("", description="修复后代码")
    rule_id: str = Field("", description="规则ID")
    vuln_type: str = Field("generic", description="漏洞类型")
    file_path: str = Field("", description="文件路径")


class CreatePRRequest(BaseModel):
    """创建PR请求（安全红线：强制dry_run优先）"""
    model_config = ConfigDict(extra="ignore")

    patch_ids: List[str] = Field(default_factory=list, description="补丁IDs")
    finding_ids: List[str] = Field(default_factory=list, description="发现IDs")
    title: str = Field("", description="PR标题")
    description: str = Field("", description="PR描述")
    provider: str = Field("gitlab", description="Git平台: gitlab/github")
    dry_run: bool = Field(True, description="是否为干运行模式（默认True）")
    confirm: bool = Field(False, description="二次确认（必须为True且dry_run=False才可执行真实提交）")
    config: Dict[str, Any] = Field(default_factory=dict, description="PR配置")
    ticket_ids: List[str] = Field(default_factory=list, description="关联工单IDs")
    labels: List[str] = Field(default_factory=list, description="PR标签")

    @property
    def is_real_submit(self) -> bool:
        """判断是否为真实提交（非dry_run且已确认）"""
        return not self.dry_run and self.confirm


class UpdateConfigRequest(BaseModel):
    """更新配置请求"""
    model_config = ConfigDict(extra="ignore")

    provider: Optional[str] = Field(None, description="Git平台")
    base_url: Optional[str] = Field(None, description="API基础URL")
    api_token: Optional[str] = Field(None, description="API Token（将被掩码存储）")
    project_id: Optional[str] = Field(None, description="项目ID")
    default_branch: Optional[str] = Field(None, description="默认分支")
    auto_verify: Optional[bool] = Field(None, description="提交前自动验证")
    auto_submit_pr: Optional[bool] = Field(None, description="验证后自动提交PR")
    dry_run: Optional[bool] = Field(None, description="默认干运行模式")
    max_fix_per_run: Optional[int] = Field(None, ge=1, le=200, description="单次最大修复数")


# ─────────────────────────── 修复预览 API ───────────────────────────

@auto_pr_router.post("/preview")
async def preview_fixes(request: PreviewRequest):
    """
    生成修复预览（Diff预览）。

    基于发现列表自动生成修复代码的Unified Diff预览，
    不包含任何Git操作或文件修改。

    Args:
        request: 修复预览请求，包含发现列表

    Returns:
        修复预览列表（含Diff文本）
    """
    from .auto_fix_generator import AutoFixGenerator
    from .models import GenerateFixRequest, FixPreview

    generator = AutoFixGenerator()
    previews = []

    for finding in request.findings:
        try:
            gen_req = GenerateFixRequest(
                finding_id=finding.get("finding_id", ""),
                rule_id=finding.get("rule_id", "unknown"),
                severity=finding.get("severity", ""),
                file_path=finding.get("file_path", ""),
                code_snippet=finding.get("code_snippet", ""),
                message=finding.get("message", ""),
                category=finding.get("category", ""),
                language=finding.get("language", ""),
                cwe=finding.get("cwe", ""),
            )
            preview = generator.generate_preview(gen_req)
            if preview:
                previews.append(preview.model_dump())
        except Exception as e:
            logger.warning("生成预览失败 finding=%s: %s", finding.get("finding_id"), e)
            previews.append({
                "finding_id": finding.get("finding_id", ""),
                "error": str(e),
                "status": "failed",
            })

    return {
        "total_requested": len(request.findings),
        "total_generated": len([p for p in previews if "error" not in p]),
        "total_failed": len([p for p in previews if "error" in p]),
        "previews": previews,
    }


# ─────────────────────────── 三重校验 API ───────────────────────────

@auto_pr_router.post("/verify")
async def verify_fix(request: VerifyRequest):
    """
    验证单个修复。

    检查：原漏洞是否已修复 + 语法是否有效。

    Args:
        request: 验证请求

    Returns:
        验证结果
    """
    from .fix_validator import FixValidator
    from .models import VerifyFixRequest, VulnerabilityType

    validator = FixValidator()
    try:
        vt = VulnerabilityType(request.vuln_type)
    except ValueError:
        vt = VulnerabilityType.GENERIC

    verify_req = VerifyFixRequest(
        patch_id=request.patch_id,
        finding_id=request.finding_id,
        original_code=request.original_code,
        fixed_code=request.fixed_code,
        rule_id=request.rule_id,
        vuln_type=vt,
    )

    result = validator.verify(verify_req)
    return result.model_dump()


@auto_pr_router.post("/verify/triple")
async def verify_triple(request: VerifyTripleRequest):
    """
    三重校验：原漏洞修复 + 无新漏洞引入 + 语法有效。

    这是PR提交前必须通过的完整验证流程：
    1. 原漏洞修复确认：坏模式不再出现
    2. 新漏洞引入检查：修复代码不含危险模式
    3. 语法有效性验证：修复代码语法正确

    Args:
        request: 三重校验请求

    Returns:
        三重校验结果，含每步详情
    """
    from .fix_validator import FixValidator
    from .models import VerifyFixRequest, VulnerabilityType, VerificationStatus

    validator = FixValidator()
    try:
        vt = VulnerabilityType(request.vuln_type)
    except ValueError:
        vt = VulnerabilityType.GENERIC

    verify_req = VerifyFixRequest(
        patch_id=request.patch_id,
        finding_id=request.finding_id,
        original_code=request.original_code,
        fixed_code=request.fixed_code,
        rule_id=request.rule_id,
        vuln_type=vt,
    )

    # 执行三重校验
    result = validator.verify(verify_req)

    # 构建三重校验响应
    triple_result = {
        "finding_id": request.finding_id,
        "patch_id": request.patch_id,
        "file_path": request.file_path,
        "vuln_type": request.vuln_type,
        "overall_status": result.status.value,
        "checks": {
            "original_vuln_resolved": {
                "passed": result.original_vuln_resolved,
                "detail": "原漏洞已确认修复" if result.original_vuln_resolved else "原漏洞仍然存在",
            },
            "no_new_vulns": {
                "passed": result.new_vulns_introduced == 0,
                "new_vulns_count": result.new_vulns_introduced,
                "detail": f"新引入漏洞数: {result.new_vulns_introduced}",
            },
            "syntax_valid": {
                "passed": result.syntax_valid,
                "detail": "语法有效" if result.syntax_valid else "语法错误",
            },
            "security_check": {
                "passed": result.security_check_passed,
                "detail": "安全检查通过" if result.security_check_passed else "安全检查未通过",
            },
        },
        "details": result.details,
        "warnings": result.warnings,
        "verified_at": result.verified_at,
    }

    return triple_result


# ─────────────────────────── 创建 PR API ───────────────────────────

@auto_pr_router.post("/create")
async def create_pr(request: CreatePRRequest):
    """
    创建修复PR（安全红线：强制dry_run优先，需confirm二次确认）。

    安全规则：
    - dry_run=True（默认）：仅模拟生成PR信息，不实际提交
    - dry_run=False 且 confirm=True：执行真实提交
    - dry_run=False 且 confirm=False：拒绝执行，返回错误提示

    Args:
        request: 创建PR请求

    Returns:
        PR创建结果或dry_run预览
    """
    from .service import AutoPRService
    from .models import AutoPRConfig

    # 安全红线：dry_run=False 但 confirm=False 时拒绝
    if not request.dry_run and not request.confirm:
        raise HTTPException(
            status_code=403,
            detail=(
                "安全拦截：真实PR提交需要同时满足 dry_run=False 且 confirm=True。"
                "请先使用 dry_run=True 预览确认后再执行。"
            ),
        )

    # 构建 PR 配置
    pr_config = AutoPRConfig(
        provider=request.provider,
        dry_run=request.dry_run,
    )
    if request.config:
        for k, v in request.config.items():
            if hasattr(pr_config, k):
                setattr(pr_config, k, v)

    # 如果是 dry_run 模式，覆盖确保安全
    effective_dry_run = request.dry_run or not request.confirm

    service = AutoPRService()

    if effective_dry_run:
        # Dry run 模式：仅返回操作预览
        return {
            "status": "dry_run",
            "message": "干运行模式：PR信息已生成但未提交",
            "would_submit": not request.dry_run and request.confirm,
            "preview": {
                "title": request.title or f"[XuanJian] 自动修复 {len(request.finding_ids)} 个漏洞",
                "description": request.description or "由玄鉴自动生成修复PR",
                "provider": request.provider,
                "patch_count": len(request.patch_ids),
                "finding_count": len(request.finding_ids),
                "ticket_count": len(request.ticket_ids),
                "labels": request.labels or ["xuanjian", "auto-fix"],
                "config": {
                    "provider": pr_config.provider,
                    "default_branch": pr_config.default_branch,
                    "dry_run": pr_config.dry_run,
                },
            },
            "next_steps": [
                "确认无误后，设置 dry_run=false 且 confirm=true 重新提交",
                "或者调用 /api/auto-pr/verify/triple 先执行三重校验",
            ],
        }

    # 真实提交（已通过 dry_run=False 且 confirm=True 检查）
    try:
        result = await service.submit_fix_pr(
            patch_ids=request.patch_ids,
            finding_ids=request.finding_ids,
            title=request.title,
            description=request.description,
            config=pr_config,
            ticket_ids=request.ticket_ids,
            labels=request.labels,
        )
        return {
            "status": "submitted",
            "message": "PR已提交",
            "pr_record": result,
        }
    except Exception as e:
        logger.error("创建PR失败: %s", e)
        raise HTTPException(status_code=500, detail=f"创建PR失败: {str(e)}")


# ─────────────────────────── 修复状态与历史 API ───────────────────────────

@auto_pr_router.get("/status/{record_id}")
async def get_fix_status(record_id: str):
    """
    查询修复记录状态。

    Args:
        record_id: 修复记录ID

    Returns:
        修复记录详情
    """
    from .service import AutoPRService

    service = AutoPRService()
    record = await service.get_fix_record(record_id)

    if not record:
        raise HTTPException(status_code=404, detail=f"修复记录 {record_id} 不存在")

    return record.model_dump()


@auto_pr_router.get("/history")
async def get_fix_history(
    status_filter: Optional[str] = Query(None, description="按状态过滤"),
    limit: int = Query(50, ge=1, le=200, description="返回数量限制"),
    offset: int = Query(0, ge=0, description="偏移量"),
):
    """
    查询修复历史记录。

    Args:
        status_filter: 状态过滤（pending/ready/verified/submitted/merged等）
        limit: 数量限制
        offset: 分页偏移

    Returns:
        修复历史记录列表
    """
    from .service import AutoPRService

    service = AutoPRService()
    records = await service.get_fix_history(
        status=status_filter,
        limit=limit,
    )

    return {
        "total": len(records),
        "limit": limit,
        "offset": offset,
        "records": [r.model_dump() for r in records],
    }


# ─────────────────────────── API统计 API ───────────────────────────

@auto_pr_router.get("/stats")
async def get_pr_stats():
    """
    获取PR管理统计信息。

    Returns:
        PR统计数据
    """
    from .service import AutoPRService

    service = AutoPRService()
    stats = await service.get_pr_stats()

    return stats.model_dump()


# ─────────────────────────── 配置管理 API ───────────────────────────

# 内存配置存储（实际部署时使用持久化）
_pr_config_store: Dict[str, Any] = {}


@auto_pr_router.get("/config")
async def get_pr_config():
    """
    获取当前PR配置（敏感项掩码返回）。

    API Token 等敏感字段会被掩码处理。

    Returns:
        配置信息（安全掩码）
    """
    from .models import AutoPRConfig

    config = _pr_config_store or AutoPRConfig().model_dump()

    # 对敏感字段进行掩码处理
    masked = _mask_sensitive_config(config)

    return {
        "config": masked,
        "sensitive_fields": ["api_token"],
        "masked": True,
    }


@auto_pr_router.put("/config")
async def update_pr_config(request: UpdateConfigRequest):
    """
    更新PR配置。

    Args:
        request: 更新配置请求（仅包含需要更新的字段）

    Returns:
        更新后的配置（敏感项掩码）
    """
    current = _pr_config_store or {}

    update_data = request.model_dump(exclude_unset=True)
    for k, v in update_data.items():
        if v is not None:
            current[k] = v

    _pr_config_store = current

    # 对敏感字段进行掩码处理
    masked = _mask_sensitive_config(current)

    return {
        "status": "updated",
        "config": masked,
        "updated_fields": list(update_data.keys()),
    }


def _mask_sensitive_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """对配置中的敏感字段进行掩码处理"""
    masked = dict(config)
    sensitive_keys = {"api_token", "token", "secret", "password"}
    for key in masked:
        if any(sk in key.lower() for sk in sensitive_keys):
            value = str(masked[key])
            if len(value) > 8:
                masked[key] = value[:4] + "*" * (len(value) - 8) + value[-4:]
            else:
                masked[key] = "****"
    return masked
