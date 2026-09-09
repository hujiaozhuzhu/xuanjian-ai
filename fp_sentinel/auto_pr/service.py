"""
玄鉴 v3.0 — 自动化修复业务编排服务

编排修复生成、验证、PR提交的完整工作流：
- generate_and_preview: 生成修复预览
- generate_and_verify: 生成修复并验证
- submit_fix_pr: 提交修复PR
- get_fix_history: 查询修复历史
- get_pr_stats: PR统计

安全红线：
- S1: 外部调用通过适配器注入
- S2: 不直接修改被扫描源文件
- S3: 不删除文件
- S5: 数据保留周期可配置
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .auto_fix_generator import AutoFixGenerator
from .fix_validator import FixValidator
from .models import (
    AutoPRConfig,
    FixPatch,
    FixRecord,
    FixStatus,
    FixVerificationResult,
    GenerateFixRequest,
    PRStats,
    PullRequestRecord,
    SubmitPRRequest,
    VerificationStatus,
    VerifyFixRequest,
    VulnerabilityType,
)
from .pr_manager import PRManager

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AutoPRService:
    """自动修复业务编排服务"""

    def __init__(
        self,
        generator: Optional[AutoFixGenerator] = None,
        validator: Optional[FixValidator] = None,
        pr_manager: Optional[PRManager] = None,
    ):
        self.generator = generator or AutoFixGenerator()
        self.validator = validator or FixValidator()
        self.pr_manager = pr_manager or PRManager()
        self._fix_records: Dict[str, FixRecord] = {}  # finding_id -> record
        self._verification_results: Dict[str, FixVerificationResult] = {}  # patch_id -> result

    # ─────────────────── 生成修复预览 ───────────────────

    async def generate_and_preview(
        self,
        requests: List[GenerateFixRequest],
    ) -> List[Dict[str, Any]]:
        """
        生成修复预览列表

        Args:
            requests: 修复生成请求列表

        Returns:
            预览结果列表
        """
        results = []
        for req in requests:
            preview = self.generator.generate_fix_preview(req)
            finding_id = req.finding_id or preview.finding_id

            # 创建修复记录
            record = FixRecord(
                finding_id=finding_id,
                rule_id=req.rule_id,
                severity=req.severity,
                file_path=req.file_path,
                vuln_type=preview.vuln_type,
                status=FixStatus.READY,
                fix_title=preview.title,
                fix_diff_summary=preview.unified_diff[:200],
                effort_minutes=preview.effort_minutes,
                verification_status=VerificationStatus.NOT_VERIFIED,
            )
            self._fix_records[finding_id] = record

            results.append({
                "finding_id": finding_id,
                "rule_id": req.rule_id,
                "file_path": req.file_path,
                "severity": req.severity,
                "vuln_type": preview.vuln_type.value,
                "title": preview.title,
                "unified_diff": preview.unified_diff,
                "effort_minutes": preview.effort_minutes,
                "reference_cve": preview.reference_cve,
                "can_customize": preview.can_customize,
            })

        return results

    # ─────────────────── 生成修复并验证 ───────────────────

    async def generate_and_verify(
        self,
        requests: List[GenerateFixRequest],
        original_codes: Optional[Dict[str, str]] = None,
        custom_codes: Optional[Dict[str, str]] = None,
        auto_verify: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        生成修复补丁并可选自动验证

        Args:
            requests: 修复生成请求列表
            original_codes: finding_id -> 原始代码映射
            custom_codes: finding_id -> 自定义修复代码映射
            auto_verify: 是否自动验证

        Returns:
            生成+验证结果列表
        """
        results = []
        original_codes = original_codes or {}
        custom_codes = custom_codes or {}

        for req in requests:
            finding_id = req.finding_id
            custom_code = custom_codes.get(finding_id)

            # 生成补丁
            patch = self.generator.generate_patch(req, custom_fix_code=custom_code)

            result_item: Dict[str, Any] = {
                "finding_id": finding_id,
                "patch_id": patch.id,
                "title": patch.title,
                "vuln_type": patch.vuln_type.value,
                "effort_minutes": patch.effort_minutes,
                "confidence": patch.confidence,
                "reference_cve": patch.reference_cve,
                "diffs": [
                    {
                        "file_path": d.file_path,
                        "original_code": d.original_code,
                        "fixed_code": d.fixed_code,
                        "description": d.description,
                    }
                    for d in patch.diffs
                ],
            }

            # 创建或更新修复记录
            if finding_id not in self._fix_records:
                self._fix_records[finding_id] = FixRecord(
                    finding_id=finding_id,
                    rule_id=req.rule_id,
                    severity=req.severity,
                    file_path=req.file_path,
                    vuln_type=patch.vuln_type,
                    status=FixStatus.READY,
                    patch_id=patch.id,
                    fix_title=patch.title,
                    fix_diff_summary=patch.diffs[0].fixed_code[:200] if patch.diffs else "",
                    effort_minutes=patch.effort_minutes,
                )

            # 自动验证
            if auto_verify:
                original_code = original_codes.get(finding_id, req.code_snippet)
                verification = self.validator.verify_patch(patch, original_code)
                self._verification_results[patch.id] = verification
                result_item["verification"] = {
                    "status": verification.status.value,
                    "original_vuln_resolved": verification.original_vuln_resolved,
                    "new_vulns_introduced": verification.new_vulns_introduced,
                    "syntax_valid": verification.syntax_valid,
                    "security_check_passed": verification.security_check_passed,
                    "details": verification.details,
                    "warnings": verification.warnings,
                }

                # 更新修复记录
                if finding_id in self._fix_records:
                    record = self._fix_records[finding_id]
                    record.patch_id = patch.id
                    record.verification_status = verification.status
                    if verification.status == VerificationStatus.PASS:
                        record.status = FixStatus.VERIFIED
                    elif verification.status == VerificationStatus.FAIL:
                        record.status = FixStatus.VERIFICATION_FAILED

            results.append(result_item)

        return results

    # ─────────────────── 提交修复 PR ───────────────────

    async def submit_fix_pr(
        self,
        config: AutoPRConfig,
        finding_ids: List[str],
        title: str = "",
        description: str = "",
        ticket_ids: Optional[List[str]] = None,
        labels: Optional[List[str]] = None,
        skip_verification: bool = False,
    ) -> Dict[str, Any]:
        """
        提交修复PR

        Args:
            config: PR配置
            finding_ids: 要修复的Finding IDs
            title: PR标题
            description: PR描述
            ticket_ids: 关联工单IDs
            labels: PR标签
            skip_verification: 是否跳过验证

        Returns:
            提交结果
        """
        # 收集补丁
        patches: List[FixPatch] = []
        verification_results: List[FixVerificationResult] = []
        errors: List[str] = []

        for fid in finding_ids:
            patch = self._find_patch_for_finding(fid)
            if not patch:
                errors.append(f"未找到Finding {fid}对应的补丁")
                continue

            # 检查验证状态
            if not skip_verification:
                verification = self._verification_results.get(patch.id)
                if verification and verification.status == VerificationStatus.FAIL:
                    errors.append(f"Finding {fid}的修复验证未通过，请修复后重试")
                    continue

            patches.append(patch)
            if patch.id in self._verification_results:
                verification_results.append(self._verification_results[patch.id])

        if errors:
            return {
                "status": "error",
                "errors": errors,
                "patches_found": len(patches),
            }

        if not patches:
            return {
                "status": "error",
                "errors": ["没有可提交的修复补丁"],
            }

        # 提交PR
        pr_record = await self.pr_manager.submit_pull_request(
            config=config,
            patches=patches,
            title=title,
            description=description,
            ticket_ids=ticket_ids,
            labels=labels,
        )

        # 更新修复记录状态
        now = _now_iso()
        for fid in finding_ids:
            if fid in self._fix_records:
                record = self._fix_records[fid]
                record.status = FixStatus.SUBMITTED
                record.pr_id = pr_record.pr_id
                record.pr_url = pr_record.pr_url
                record.updated_at = now

        # 关联工单
        linked_tickets: List[str] = []
        if ticket_ids and pr_record.pr_id:
            for tid in ticket_ids:
                linked_tickets.append(tid)

        return {
            "status": "submitted",
            "pr_id": pr_record.pr_id,
            "pr_url": pr_record.pr_url,
            "pr_title": pr_record.pr_title,
            "branch": pr_record.branch,
            "patches_submitted": len(patches),
            "verifications_passed": sum(
                1 for v in verification_results
                if v.status == VerificationStatus.PASS
            ),
            "linked_tickets": linked_tickets,
        }

    # ─────────────────── 修复历史 ───────────────────

    async def get_fix_record(self, record_id: str) -> Optional[FixRecord]:
        """获取单条修复记录（按finding_id查找）"""
        return self._fix_records.get(record_id)

    async def get_fix_history(
        self,
        finding_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[FixRecord]:
        """
        获取修复历史记录

        Args:
            finding_id: 按Finding ID过滤
            status: 按状态过滤
            limit: 最大记录数

        Returns:
            修复记录列表
        """
        records = list(self._fix_records.values())

        if finding_id:
            records = [r for r in records if r.finding_id == finding_id]
        if status:
            records = [r for r in records if r.status.value == status]

        records.sort(key=lambda r: r.updated_at, reverse=True)
        return records[:limit]

    # ─────────────────── PR统计 ───────────────────

    async def get_pr_stats(self) -> PRStats:
        """获取PR管理统计"""
        stats = PRStats()
        records = list(self._fix_records.values())

        stats.total_fixes = len(records)
        stats.pending_fixes = sum(1 for r in records if r.status == FixStatus.PENDING)
        stats.verified_fixes = sum(1 for r in records if r.status == FixStatus.VERIFIED)
        stats.failed_verifications = sum(
            1 for r in records if r.status == FixStatus.VERIFICATION_FAILED
        )
        stats.submitted_prs = sum(1 for r in records if r.status == FixStatus.SUBMITTED)
        stats.merged_prs = sum(1 for r in records if r.status == FixStatus.MERGED)
        stats.closed_prs = sum(1 for r in records if r.status == FixStatus.CLOSED)

        # 平均工时
        efforts = [r.effort_minutes for r in records if r.effort_minutes > 0]
        stats.avg_effort_minutes = sum(efforts) / len(efforts) if efforts else 0.0

        # 按漏洞类型统计
        for r in records:
            vt = r.vuln_type.value
            stats.by_vuln_type[vt] = stats.by_vuln_type.get(vt, 0) + 1

        # 按严重度统计
        for r in records:
            sev = r.severity or "UNKNOWN"
            stats.by_severity[sev] = stats.by_severity.get(sev, 0) + 1

        return stats

    # ─────────────────── 自定义修改 ───────────────────

    async def customize_fix(
        self,
        finding_id: str,
        custom_code: str,
        original_code: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        自定义修改修复代码

        Args:
            finding_id: Finding ID
            custom_code: 自定义修复代码
            original_code: 原始代码（用于重新验证）

        Returns:
            更新后的修复信息和验证结果
        """
        # 查找对应的预览
        preview = self.generator.get_preview(finding_id)
        if not preview:
            return None

        # 重新生成补丁（使用自定义代码）
        request = GenerateFixRequest(
            finding_id=finding_id,
            rule_id=preview.rule_id,
            severity=preview.severity,
            file_path=preview.file_path,
            code_snippet=original_code,
        )
        patch = self.generator.generate_patch(request, custom_fix_code=custom_code)

        # 重新验证
        verification = self.validator.verify_patch(patch, original_code)

        return {
            "finding_id": finding_id,
            "patch_id": patch.id,
            "custom_code": custom_code,
            "verification_status": verification.status.value,
            "warnings": verification.warnings,
        }

    # ─────────────────── PR状态查询 ───────────────────

    async def get_pr_status(self, pr_id: str) -> Dict[str, Any]:
        """
        获取PR状态

        Args:
            pr_id: PR ID

        Returns:
            PR状态信息
        """
        record = self.pr_manager.get_record(pr_id)
        if not record:
            return {"status": "not_found"}

        return {
            "pr_id": record.pr_id,
            "pr_url": record.pr_url,
            "pr_title": record.pr_title,
            "status": record.status,
            "branch": record.branch,
            "created_at": record.created_at,
            "patch_count": len(record.patch_ids),
            "finding_count": len(record.finding_ids),
            "ticket_count": len(record.ticket_ids),
        }

    async def list_prs(self, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出所有PR记录"""
        records = self.pr_manager.list_records()
        if status_filter:
            records = [r for r in records if r.status == status_filter]

        return [
            {
                "pr_id": r.pr_id,
                "pr_url": r.pr_url,
                "pr_title": r.pr_title,
                "status": r.status,
                "branch": r.branch,
                "created_at": r.created_at,
            }
            for r in records
        ]

    # ─────────────────── 内部方法 ───────────────────

    def _find_patch_for_finding(self, finding_id: str) -> Optional[FixPatch]:
        """查找finding对应的已生成补丁"""
        for patch in self.generator._patches.values():
            if patch.finding_id == finding_id:
                return patch
        return None
