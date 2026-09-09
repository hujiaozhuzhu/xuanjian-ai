"""
玄鉴 v3.0 — PR 管理器

管理修复PR的全生命周期：
- 创建修复分支并提交修复代码
- 在GitLab/GitHub上创建PR
- 查看PR状态、合并结果
- 修复历史记录
- 自动关联漏洞工单

安全红线：
- S1: 外部调用通过适配器层注入
- S2: 不修改被扫描代码（仅操作PR和分支）
- S3: 不删除文件
- S5: 数据保留周期可配置
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from .models import (
    AutoPRConfig,
    FixPatch,
    PullRequestRecord,
    VerifyFixRequest,
)

logger = logging.getLogger(__name__)


# ─────────────────────── HTTP Client Provider ───────────────────────

class GitHTTPProvider:
    """HTTP 客户端提供者 — 便于测试时注入 mock"""

    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        self._client = client

    async def get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient()
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None


# ─────────────────────── Git Provider Adapters ───────────────────────

class GitProviderAdapter:
    """Git 平台适配器基类"""

    def __init__(self, config: AutoPRConfig, http_provider: Optional[GitHTTPProvider] = None):
        self.config = config
        self.http = http_provider or GitHTTPProvider()

    async def test_connection(self) -> tuple:
        """检测连通性"""
        ...  # pragma: no cover

    async def create_pull_request(
        self,
        title: str,
        description: str,
        source_branch: str,
        target_branch: str,
        labels: Optional[List[str]] = None,
    ) -> tuple:
        """创建 PR，返回 (pr_id, pr_url)"""
        ...  # pragma: no cover

    async def get_pr_status(self, pr_id: str) -> str:
        """获取 PR 状态"""
        ...  # pragma: no cover

    async def add_pr_comment(self, pr_id: str, comment: str) -> bool:
        """添加 PR 评论"""
        ...  # pragma: no cover

    async def close(self) -> None:
        await self.http.close()


class GitLabPRAadapter(GitProviderAdapter):
    """GitLab PR 适配器"""

    def __init__(self, config: AutoPRConfig, http_provider: Optional[GitHTTPProvider] = None):
        super().__init__(config, http_provider)
        self.api_base = config.base_url.rstrip("/") + "/api/v4"

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_token:
            headers["PRIVATE-TOKEN"] = self.config.api_token
        return headers

    async def test_connection(self) -> tuple:
        try:
            client = await self.http.get_client()
            resp = await client.get(
                f"{self.api_base}/version",
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code == 200:
                ver = resp.json().get("version", "unknown")
                return True, f"GitLab v{ver}"
            if resp.status_code == 401:
                return False, "认证失败: 无效 Token"
            return False, f"HTTP {resp.status_code}"
        except httpx.TimeoutException:
            return False, "连接超时"
        except Exception as e:
            return False, f"连接异常: {e}"

    async def create_pull_request(
        self,
        title: str,
        description: str,
        source_branch: str,
        target_branch: str,
        labels: Optional[List[str]] = None,
    ) -> tuple:
        payload: Dict[str, Any] = {
            "title": title,
            "description": description,
            "source_branch": source_branch,
            "target_branch": target_branch,
        }
        if labels:
            payload["labels"] = ",".join(labels)

        try:
            client = await self.http.get_client()
            resp = await client.post(
                f"{self.api_base}/projects/{self.config.project_id}/merge_requests",
                json=payload,
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                pr_id = str(data.get("iid", data.get("id", "")))
                pr_url = data.get("web_url", "")
                return pr_id, pr_url
            else:
                logger.error("GitLab create MR failed: %s", resp.status_code)
                return "", ""
        except Exception as e:
            logger.exception("GitLab create MR exception")
            return "", ""

    async def get_pr_status(self, pr_id: str) -> str:
        try:
            client = await self.http.get_client()
            resp = await client.get(
                f"{self.api_base}/projects/{self.config.project_id}/merge_requests/{pr_id}",
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code == 200:
                state = resp.json().get("state", "unknown")
                return state
            return "unknown"
        except Exception:
            return "unknown"

    async def add_pr_comment(self, pr_id: str, comment: str) -> bool:
        try:
            payload = {"body": comment}
            client = await self.http.get_client()
            resp = await client.post(
                f"{self.api_base}/projects/{self.config.project_id}/merge_requests/{pr_id}/notes",
                json=payload,
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 201)
        except Exception:
            return False


class GitHubPRAdapter(GitProviderAdapter):
    """GitHub PR 适配器"""

    def __init__(self, config: AutoPRConfig, http_provider: Optional[GitHTTPProvider] = None):
        super().__init__(config, http_provider)
        self.api_base = "https://api.github.com"

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/vnd.github.v3+json",
        }
        if self.config.api_token:
            headers["Authorization"] = f"Bearer {self.config.api_token}"
        return headers

    async def test_connection(self) -> tuple:
        try:
            client = await self.http.get_client()
            resp = await client.get(
                f"{self.api_base}/user",
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code == 200:
                login = resp.json().get("login", "unknown")
                return True, f"GitHub 用户: {login}"
            if resp.status_code == 401:
                return False, "认证失败: 无效 Token"
            return False, f"HTTP {resp.status_code}"
        except httpx.TimeoutException:
            return False, "连接超时"
        except Exception as e:
            return False, f"连接异常: {e}"

    async def create_pull_request(
        self,
        title: str,
        description: str,
        source_branch: str,
        target_branch: str,
        labels: Optional[List[str]] = None,
    ) -> tuple:
        payload: Dict[str, Any] = {
            "title": title,
            "body": description,
            "head": source_branch,
            "base": target_branch,
        }
        if labels:
            payload["labels"] = labels

        try:
            client = await self.http.get_client()
            resp = await client.post(
                f"{self.api_base}/repos/{self.config.project_id}/pulls",
                json=payload,
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                pr_id = str(data.get("number", data.get("id", "")))
                pr_url = data.get("html_url", "")
                return pr_id, pr_url
            else:
                logger.error("GitHub create PR failed: %s", resp.status_code)
                return "", ""
        except Exception as e:
            logger.exception("GitHub create PR exception")
            return "", ""

    async def get_pr_status(self, pr_id: str) -> str:
        try:
            client = await self.http.get_client()
            resp = await client.get(
                f"{self.api_base}/repos/{self.config.project_id}/pulls/{pr_id}",
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code == 200:
                data = resp.json()
                state = data.get("state", "unknown")
                if data.get("merged_at"):
                    return "merged"
                return state
            return "unknown"
        except Exception:
            return "unknown"

    async def add_pr_comment(self, pr_id: str, comment: str) -> bool:
        try:
            payload = {"body": comment}
            client = await self.http.get_client()
            resp = await client.post(
                f"{self.api_base}/repos/{self.config.project_id}/issues/{pr_id}/comments",
                json=payload,
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 201)
        except Exception:
            return False


def create_pr_adapter(
    provider: str,
    config: AutoPRConfig,
    http_provider: Optional[GitHTTPProvider] = None,
) -> GitProviderAdapter:
    """创建PR适配器"""
    if provider == "gitlab":
        return GitLabPRAadapter(config, http_provider)
    if provider == "github":
        return GitHubPRAdapter(config, http_provider)
    raise ValueError(f"不支持的Git平台: {provider}")


# ─────────────────────── PR Manager ───────────────────────

class PRManager:
    """PR管理器"""

    def __init__(self):
        self._pr_records: Dict[str, PullRequestRecord] = {}

    def create_pr_record(
        self,
        provider: str,
        project_id: str,
        repository_url: str,
        pr_id: str = "",
        pr_url: str = "",
        pr_title: str = "",
        branch: str = "",
        base_branch: str = "main",
        patch_ids: Optional[List[str]] = None,
        finding_ids: Optional[List[str]] = None,
        ticket_ids: Optional[List[str]] = None,
        verification_id: str = "",
        commit_hash: str = "",
        description: str = "",
    ) -> PullRequestRecord:
        """创建PR记录"""
        now = datetime.now(timezone.utc).isoformat()
        record = PullRequestRecord(
            pr_id=pr_id,
            pr_url=pr_url,
            pr_title=pr_title,
            provider=provider,
            project_id=project_id,
            repository_url=repository_url,
            branch=branch,
            base_branch=base_branch,
            status="draft" if not pr_id else "open",
            patch_ids=patch_ids or [],
            finding_ids=finding_ids or [],
            ticket_ids=ticket_ids or [],
            verification_id=verification_id,
            commit_hash=commit_hash,
            description=description,
            created_at=now,
            updated_at=now,
        )
        self._pr_records[pr_id or record.branch] = record
        return record

    async def submit_pull_request(
        self,
        config: AutoPRConfig,
        patches: List[FixPatch],
        title: str = "",
        description: str = "",
        ticket_ids: Optional[List[str]] = None,
        labels: Optional[List[str]] = None,
        adapter: Optional[GitProviderAdapter] = None,
    ) -> PullRequestRecord:
        """
        提交修复 PR

        Args:
            config: PR配置
            patches: 修复补丁列表
            title: PR标题
            description: PR描述
            ticket_ids: 关联工单IDs
            labels: PR标签
            adapter: 可选适配器（不传则根据config创建）

        Returns:
            PullRequestRecord
        """
        should_close = False
        if adapter is None:
            adapter = create_pr_adapter(config.provider, config)
            should_close = True

        try:
            # 生成分支名
            branch_name = _generate_branch_name(config.fix_branch_prefix)

            # 生成PR标题和描述
            pr_title = title or _generate_pr_title(patches)
            pr_description = description or _generate_pr_description(patches, ticket_ids)
            pr_labels = labels or ["security", "auto-fix"]

            if config.dry_run:
                logger.info("[dry-run] Would create PR: %s on branch %s", pr_title, branch_name)
                record = self.create_pr_record(
                    provider=config.provider,
                    project_id=config.project_id,
                    repository_url="",
                    pr_title=pr_title,
                    branch=branch_name,
                    patch_ids=[p.id for p in patches],
                    finding_ids=[p.finding_id for p in patches],
                    ticket_ids=ticket_ids or [],
                    description=pr_description,
                )
                record.pr_url = f"dry-run://{branch_name}"
                return record

            # 调用适配器创建PR
            pr_id, pr_url = await adapter.create_pull_request(
                title=pr_title,
                description=pr_description,
                source_branch=branch_name,
                target_branch=config.default_branch,
                labels=pr_labels,
            )

            record = self.create_pr_record(
                provider=config.provider,
                project_id=config.project_id,
                repository_url="",
                pr_id=pr_id,
                pr_url=pr_url,
                pr_title=pr_title,
                branch=branch_name,
                patch_ids=[p.id for p in patches],
                finding_ids=[p.finding_id for p in patches],
                ticket_ids=ticket_ids or [],
                description=pr_description,
            )
            return record
        finally:
            if should_close:
                await adapter.close()

    async def check_pr_status(
        self,
        pr_id: str,
        adapter: GitProviderAdapter,
    ) -> str:
        """检查PR状态"""
        return await adapter.get_pr_status(pr_id)

    async def link_ticket_to_pr(
        self,
        pr_id: str,
        ticket_id: str,
        adapter: GitProviderAdapter,
    ) -> bool:
        """
        关联工单到PR（通过评论）
        """
        comment = f"关联漏洞工单: {ticket_id}\n由玄鉴 v3.0 自动修复模块关联"
        return await adapter.add_pr_comment(pr_id, comment)

    def get_record(self, pr_id: str) -> Optional[PullRequestRecord]:
        """获取PR记录"""
        return self._pr_records.get(pr_id)

    def list_records(self) -> List[PullRequestRecord]:
        """列出所有PR记录"""
        return list(self._pr_records.values())

    def update_record_status(self, pr_id: str, status: str, **kwargs) -> bool:
        """更新PR记录状态"""
        record = self._pr_records.get(pr_id)
        if not record:
            return False
        record.status = status
        record.updated_at = datetime.now(timezone.utc).isoformat()
        for k, v in kwargs.items():
            if hasattr(record, k):
                setattr(record, k, v)
        return True


# ─────────────────────── 工具函数 ───────────────────────

def _generate_branch_name(prefix: str) -> str:
    """生成修复分支名"""
    short_id = uuid.uuid4().hex[:8]
    return f"{prefix}fix-{short_id}"


def _generate_pr_title(patches: List[FixPatch]) -> str:
    """生成PR标题"""
    if not patches:
        return "[玄鉴] 安全修复"
    vuln_types = list(set(p.title for p in patches if p.title))
    if len(vuln_types) == 1:
        return f"[玄鉴] 修复: {vuln_types[0]}"
    return f"[玄鉴] 修复 {len(patches)} 个安全问题 ({', '.join(vuln_types[:3])})"


def _generate_pr_description(
    patches: List[FixPatch],
    ticket_ids: Optional[List[str]] = None,
) -> str:
    """生成PR描述"""
    lines = [
        "## 玄鉴 v3.0 自动安全修复",
        "",
        "### 修复内容",
        "",
    ]

    for i, patch in enumerate(patches, 1):
        lines.append(f"**{i}. {patch.title}**")
        lines.append(f"- 漏洞类型: `{patch.vuln_type.value}`")
        lines.append(f"- 预计工时: {patch.effort_minutes} 分钟")
        if patch.reference_cve:
            lines.append(f"- 参考: {patch.reference_cve}")
        if patch.incident_note:
            lines.append(f"- 说明: {patch.incident_note}")
        if patch.diffs:
            d = patch.diffs[0]
            lines.append(f"- 文件: `{d.file_path}`")
            lines.append("")
            lines.append("```diff")
            lines.append(f"-{d.original_code}")
            lines.append(f"+{d.fixed_code}")
            lines.append("```")
        lines.append("")

    if ticket_ids:
        lines.append("### 关联工单")
        lines.append("")
        for tid in ticket_ids:
            lines.append(f"- {tid}")
        lines.append("")

    lines.append("---")
    lines.append("*由玄鉴 v3.0 自动化修复模块提交*")
    return "\n".join(lines)
