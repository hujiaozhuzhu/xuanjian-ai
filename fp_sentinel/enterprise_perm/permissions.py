"""
企业权限管理 — 权限检查引擎

提供角色到权限的校验逻辑，支持全局角色和项目级角色覆盖。
所有权限检查自动写入审计日志（denied 操作强制记录）。

安全红线：
- 权限校验纯本地，零网络调用
- 所有 check/denied 均写入审计日志（audit_log 表）
"""

import logging
from typing import Optional

from .models import (
    ROLE_PERMISSIONS,
    AuditAction,
    AuditResult,
    Permission,
    PermissionCheckResult,
    Role,
)
from .repo import AuditRepo, ProjectRoleRepo, UserRepo
from ..database.connection import Database

logger = logging.getLogger(__name__)


class PermissionChecker:
    """
    权限检查器

    检查流程：
    1. 查找用户全局角色
    2. 若有项目级角色覆盖，使用项目级角色
    3. 根据角色-权限矩阵判断权限
    4. 记录审计日志（denied 强制记录，allowed 可选）
    """

    def __init__(self, db: Database):
        self.db = db
        self.user_repo = UserRepo(db)
        self.project_role_repo = ProjectRoleRepo(db)
        self.audit_repo = AuditRepo(db)

    async def check(
        self,
        user_id: str,
        permission: Permission,
        project_id: Optional[str] = None,
        log_allowed: bool = True,
    ) -> PermissionCheckResult:
        """
        检查用户是否拥有某权限。

        Args:
            user_id: 用户ID
            permission: 请求的权限
            project_id: 项目ID（None 则仅校验全局角色）
            log_allowed: 是否记录 allowed 审计日志

        Returns:
            PermissionCheckResult: 检查结果
        """
        # 查找用户
        user = await self.user_repo.get_by_id(user_id)
        if user is None:
            result = PermissionCheckResult(
                allowed=False, user_id=user_id, permission=permission,
                role=None, source="global",
            )
            await self._log_denied(result, project_id, "user_not_found")
            return result

        if not user.is_active:
            result = PermissionCheckResult(
                allowed=False, user_id=user_id, permission=permission,
                role=user.role, source="global",
            )
            await self._log_denied(result, project_id, "user_inactive")
            return result

        # 确定生效角色：优先项目级覆盖
        effective_role = user.role
        source = "global"
        if project_id:
            project_role = await self.project_role_repo.get_project_role(user_id, project_id)
            if project_role is not None:
                effective_role = project_role.role
                source = "project"

        # 检查权限矩阵
        role_perms = ROLE_PERMISSIONS.get(effective_role, set())
        allowed = permission in role_perms

        result = PermissionCheckResult(
            allowed=allowed, user_id=user_id, permission=permission,
            role=effective_role, source=source,
        )

        # 记录审计日志
        if allowed and log_allowed:
            await self.audit_repo.log(
                action=AuditAction.PERM_CHECK.value,
                result=AuditResult.ALLOWED.value,
                user_id=user_id,
                username=user.username,
                resource_type="permission",
                resource_id=permission.value,
                details={"source": source, "project_id": project_id},
            )
        elif not allowed:
            await self._log_denied(result, project_id, "insufficient_permission")

        return result

    async def require(
        self,
        user_id: str,
        permission: Permission,
        project_id: Optional[str] = None,
    ) -> None:
        """
        要求用户拥有某权限，否则抛出 PermissionDeniedError。

        Raises:
            PermissionDeniedError: 当用户无权限或被停用时
        """
        result = await self.check(user_id, permission, project_id, log_allowed=True)
        if not result.allowed:
            raise PermissionDeniedError(
                f"用户 {user_id} 缺少权限 {permission.value}"
                + (f" (项目 {project_id})" if project_id else "")
                + f"，当前角色: {result.role}"
            )

    async def check_batch(
        self,
        user_id: str,
        permissions,
        project_id: Optional[str] = None,
    ) -> dict:
        """批量检查多个权限，返回 {permission: bool}"""
        results = {}
        for perm in permissions:
            result = await self.check(user_id, perm, project_id, log_allowed=False)
            results[perm] = result.allowed
        return results

    async def _log_denied(
        self,
        result: PermissionCheckResult,
        project_id: Optional[str],
        reason: str,
    ) -> None:
        """记录 denied 审计日志"""
        try:
            user = await self.user_repo.get_by_id(result.user_id)
            username = user.username if user else None
            await self.audit_repo.log(
                action=AuditAction.PERM_DENIED.value,
                result=AuditResult.DENIED.value,
                user_id=result.user_id,
                username=username,
                resource_type="permission",
                resource_id=result.permission.value,
                details={
                    "reason": reason,
                    "role": result.role.value if result.role else None,
                    "source": result.source,
                    "project_id": project_id,
                },
            )
        except Exception:
            logger.warning("审计日志写入失败（denied 记录）", exc_info=True)


class PermissionDeniedError(Exception):
    """权限不足异常"""
    pass