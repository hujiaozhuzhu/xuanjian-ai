"""
DevSecOps 对接模块 — API 适配器层

封装 GitLab / Jira / GitHub 的外部 API 调用：
- GitLab: Issues API (Create / Update / Close)、Commit References
- Jira: Issues API (Create / Update / Close / Comment)、Project Validate
- GitHub: Issues API (Create / Update / Close)、Commit Check Runs

安全红线：
- S1: 测试可注入 mock HTTP client（httpx.AsyncClient 子类）
- S2: 不修改被扫描代码（sync 仅对外发送 Issue，不写磁盘代码）
- S3: 不删除文件（工单联动仅调用外部 API，本地操作只增不改不删）
- S5: 同步记录保留周期可配置，默认 90 天
"""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .models import (
    DevOpsConfig,
    DevOpsProvider,
    FindingRef,
    FindingTicketMapping,
    SyncRecord,
    SyncStatus,
    TicketStatus,
)

logger = logging.getLogger(__name__)


# ─────────────────────── HTTP Client 抽象 ───────────────────────

class HTTPClientProvider:  # pragma: no cover - 测试时总是注入 mock，不直接测试
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


# ─────────────────────── 适配器抽象基类 ───────────────────────

class DevOpsAdapter(ABC):
    """DevOps 平台适配器抽象基类"""

    def __init__(self, config: DevOpsConfig, http_provider: Optional[HTTPClientProvider] = None):
        self.config = config
        self.http = http_provider or HTTPClientProvider()

    @abstractmethod
    async def test_connection(self) -> Tuple[bool, str]:
        """检测连通性，返回 (是否成功, 消息)"""
        ...  # pragma: no cover

    @abstractmethod
    async def create_issue(
        self,
        finding: FindingRef,
        repository_url: str,
        commit_hash: str,
        branch: str,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        创建 Issue/工单
        返回: (ticket_id, ticket_key, ticket_url) — 任一可为 None
        """
        ...  # pragma: no cover

    @abstractmethod
    async def close_issue(
        self,
        ticket_id: str,
        resolution: str = "fixed",
        comment: str = "",
        commit_hash: str = "",
    ) -> bool:
        """关闭 Issue/工单"""
        ...  # pragma: no cover

    @abstractmethod
    async def add_comment(
        self,
        ticket_id: str,
        comment: str,
    ) -> bool:
        """给工单添加评论"""
        ...  # pragma: no cover

    @abstractmethod
    async def update_issue_status(
        self,
        ticket_id: str,
        new_status: TicketStatus,
        comment: str = "",
    ) -> bool:
        """更新工单状态"""
        ...  # pragma: no cover

    def _headers(self) -> Dict[str, str]:  # pragma: no cover - 基类默认实现被子类覆盖
        return {"Content-Type": "application/json"}

    def _issue_title(self, finding: FindingRef) -> str:
        """格式化工单标题"""
        severity_tag = finding.severity.upper() if finding.severity else "UNKNOWN"
        return f"[{severity_tag}] {finding.rule_id} — {finding.message[:80]}"

    def _issue_body(self, finding: FindingRef, repository_url: str, commit_hash: str, branch: str) -> str:
        """格式化工单正文"""
        lines = [
            "## 漏洞详情",
            "",
            f"- **严重度**: {finding.severity}",
            f"- **规则 ID**: `{finding.rule_id}`",
            f"- **文件**: `{finding.file_path}:{finding.line_start}`",
            f"- **CWE**: {finding.cwe or 'N/A'}",
            f"- **描述**: {finding.message}",
            "",
        ]
        if repository_url:
            lines.append(f"- **仓库**: {repository_url}")
        if commit_hash:
            lines.append(f"- **触发提交**: `{commit_hash}`")
        if branch:
            lines.append(f"- **分支**: {branch}")
        lines.extend([
            "",
            "---",
            "*由玄鉴 v3.0 DevSecOps 模块自动同步*",
            f"*Mapping UUID: {uuid.uuid4().hex[:12]}*",
        ])
        return "\n".join(lines)

    async def close(self) -> None:  # pragma: no cover - 基类方法通过子类覆盖测试
        await self.http.close()


# ─────────────────────── GitLab Adapter ───────────────────────

class GitLabAdapter(DevOpsAdapter):
    """
    GitLab Issues API 封装
    文档: https://docs.gitlab.com/ee/api/issues.html
    """

    def __init__(self, config: DevOpsConfig, http_provider: Optional[HTTPClientProvider] = None):
        super().__init__(config, http_provider)
        self.api_base = config.base_url.rstrip("/") + "/api/v4"

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_token:
            headers["PRIVATE-TOKEN"] = self.config.api_token
        return headers

    async def test_connection(self) -> Tuple[bool, str]:
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
            return False, f"HTTP {resp.status_code}"  # pragma: no cover
        except httpx.TimeoutException:
            return False, "连接超时"
        except Exception as e:  # pragma: no cover
            return False, f"连接异常: {e}"

    async def create_issue(
        self,
        finding: FindingRef,
        repository_url: str,
        commit_hash: str,
        branch: str,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        title = self._issue_title(finding)
        body = self._issue_body(finding, repository_url, commit_hash, branch)
        labels = ",".join(self.config.default_labels) if self.config.default_labels else "security"

        payload: Dict[str, Any] = {
            "title": title,
            "description": body,
            "labels": labels,
        }

        try:
            client = await self.http.get_client()
            resp = await client.post(
                f"{self.api_base}/projects/{self.config.project_id}/issues",
                json=payload,
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                ticket_id = str(data.get("id", ""))
                ticket_key = data.get("iid", ticket_id)
                ticket_url = data.get("web_url", "")
                return ticket_id, str(ticket_key), ticket_url
            else:
                logger.error("GitLab create_issue failed: %s %s", resp.status_code, resp.text[:200])
                return None, None, None
        except Exception as e:
            logger.exception("GitLab create_issue exception")
            return None, None, None

    async def close_issue(
        self,
        ticket_id: str,
        resolution: str = "fixed",
        comment: str = "",
        commit_hash: str = "",
    ) -> bool:
        try:
            # 先添加关闭评论
            if comment or commit_hash:
                await self.add_comment(
                    ticket_id,
                    _close_comment(resolution, comment, commit_hash),
                )
            payload = {"state_event": "close"}
            client = await self.http.get_client()
            resp = await client.put(
                f"{self.api_base}/projects/{self.config.project_id}/issues/{ticket_id}",
                json=payload,
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 201)
        except Exception as e:
            logger.exception("GitLab close_issue exception")
            return False

    async def add_comment(self, ticket_id: str, comment: str) -> bool:
        try:
            payload = {"body": comment}
            client = await self.http.get_client()
            resp = await client.post(
                f"{self.api_base}/projects/{self.config.project_id}/issues/{ticket_id}/notes",
                json=payload,
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 201)
        except Exception as e:
            logger.exception("GitLab add_comment exception")
            return False

    async def update_issue_status(
        self,
        ticket_id: str,
        new_status: TicketStatus,
        comment: str = "",
    ) -> bool:
        try:
            if new_status == TicketStatus.RESOLVED:
                payload = {"state_event": "close"}
            elif new_status == TicketStatus.REOPENED:
                payload = {"state_event": "reopen"}
            else:
                # 用 labels 标记进展状态
                payload = {}
            client = await self.http.get_client()
            resp = await client.put(
                f"{self.api_base}/projects/{self.config.project_id}/issues/{ticket_id}",
                json=payload,
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            ok = resp.status_code in (200, 201)
            if ok and comment:
                await self.add_comment(ticket_id, comment)
            return ok
        except Exception as e:
            logger.exception("GitLab update_issue_status exception")
            return False


# ─────────────────────── Jira Adapter ───────────────────────

class JiraAdapter(DevOpsAdapter):
    """
    Jira Issues API 封装 (Jira Cloud / Server REST API v2)
    文档: https://developer.atlassian.com/cloud/jira/platform/rest/v2/
    """

    def __init__(self, config: DevOpsConfig, http_provider: Optional[HTTPClientProvider] = None):
        super().__init__(config, http_provider)
        self.api_base = config.base_url.rstrip("/") + "/rest/api/2"

    def _headers(self) -> Dict[str, str]:
        import base64
        headers = {"Content-Type": "application/json"}
        if self.config.api_token:
            # Jira Cloud: username:token base64
            token_bytes = f"xuanjian:{self.config.api_token}".encode()
            headers["Authorization"] = f"Basic {base64.b64encode(token_bytes).decode()}"
        return headers

    async def test_connection(self) -> Tuple[bool, str]:
        try:
            client = await self.http.get_client()
            resp = await client.get(
                f"{self.api_base}/myself",
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code == 200:
                data = resp.json()
                name = data.get("displayName", data.get("name", "unknown"))
                return True, f"Jira 用户: {name}"
            if resp.status_code == 401:
                return False, "认证失败: 无效 Token"
            return False, f"HTTP {resp.status_code}"  # pragma: no cover
        except httpx.TimeoutException:
            return False, "连接超时"
        except Exception as e:  # pragma: no cover
            return False, f"连接异常: {e}"

    async def create_issue(
        self,
        finding: FindingRef,
        repository_url: str,
        commit_hash: str,
        branch: str,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        title = self._issue_title(finding)
        body_text = self._issue_body(finding, repository_url, commit_hash, branch)

        # Jira Document Format ( Atlassian Document Format ADF-lite 或纯文本 )
        payload = {
            "fields": {
                "project": {"key": self.config.jira_project_key},
                "summary": title,
                "description": body_text,
                "issuetype": {"name": "Bug"},
            }
        }
        if self.config.default_labels:
            payload["fields"]["labels"] = self.config.default_labels

        try:
            client = await self.http.get_client()
            resp = await client.post(
                f"{self.api_base}/issue",
                json=payload,
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                ticket_id = str(data.get("id", ""))
                ticket_key = data.get("key", ticket_id)
                ticket_url = f"{self.config.base_url.rstrip('/')}/browse/{ticket_key}"
                return ticket_id, ticket_key, ticket_url
            else:
                logger.error("Jira create_issue failed: %s %s", resp.status_code, resp.text[:200])
                return None, None, None
        except Exception as e:
            logger.exception("Jira create_issue exception")
            return None, None, None

    async def close_issue(
        self,
        ticket_id: str,
        resolution: str = "fixed",
        comment: str = "",
        commit_hash: str = "",
    ) -> bool:
        try:
            if comment or commit_hash:
                await self.add_comment(ticket_id, _close_comment(resolution, comment, commit_hash))
            # 查找 "关闭" 或 "Done" 的 transition id
            transition_id = await self._find_close_transition(ticket_id)
            if transition_id:
                payload = {"transition": {"id": transition_id}}
                client = await self.http.get_client()
                resp = await client.post(
                    f"{self.api_base}/issue/{ticket_id}/transitions",
                    json=payload,
                    headers=self._headers(),
                    timeout=self.config.timeout_seconds,
                )
                return resp.status_code in (200, 201, 204)
            return False
        except Exception as e:
            logger.exception("Jira close_issue exception")
            return False

    async def _find_close_transition(self, ticket_id: str) -> Optional[str]:
        """查找可用的 '关闭/Done' transition ID"""
        try:
            client = await self.http.get_client()
            resp = await client.get(
                f"{self.api_base}/issue/{ticket_id}/transitions",
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code == 200:
                transitions = resp.json().get("transitions", [])
                for t in transitions:
                    name = t.get("name", "").lower()
                    if name in ("close", "close issue", "done", "resolved", "resolve issue"):
                        return t.get("id")
                # fallback: 取最后一个
                if transitions:
                    return transitions[-1].get("id")
        except Exception:
            pass
        return None

    async def add_comment(self, ticket_id: str, comment: str) -> bool:
        try:
            payload = {"body": comment}
            client = await self.http.get_client()
            resp = await client.post(
                f"{self.api_base}/issue/{ticket_id}/comment",
                json=payload,
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 201)
        except Exception as e:
            logger.exception("Jira add_comment exception")
            return False

    async def update_issue_status(
        self,
        ticket_id: str,
        new_status: TicketStatus,
        comment: str = "",
    ) -> bool:
        try:
            status_name = _ticket_status_to_jira(new_status)
            if status_name:
                # 找到匹配的 transition
                transition_id = await self._find_transition_by_name(ticket_id, status_name)
                if transition_id:
                    payload = {"transition": {"id": transition_id}}
                    client = await self.http.get_client()
                    resp = await client.post(
                        f"{self.api_base}/issue/{ticket_id}/transitions",
                        json=payload,
                        headers=self._headers(),
                        timeout=self.config.timeout_seconds,
                    )
                    ok = resp.status_code in (200, 201, 204)
                    if ok and comment:
                        await self.add_comment(ticket_id, comment)
                    return ok
            return False
        except Exception as e:
            logger.exception("Jira update_issue_status exception")
            return False

    async def _find_transition_by_name(self, ticket_id: str, status_name: str) -> Optional[str]:
        """按状态名查找 transition"""
        try:
            client = await self.http.get_client()
            resp = await client.get(
                f"{self.api_base}/issue/{ticket_id}/transitions",
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code == 200:
                for t in resp.json().get("transitions", []):
                    if status_name.lower() in t.get("name", "").lower():
                        return t.get("id")
        except Exception:
            pass
        return None


# ─────────────────────── GitHub Adapter ───────────────────────

class GitHubAdapter(DevOpsAdapter):
    """
    GitHub Issues API 封装
    文档: https://docs.github.com/en/rest/issues/issues
    """

    def __init__(self, config: DevOpsConfig, http_provider: Optional[HTTPClientProvider] = None):
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

    async def test_connection(self) -> Tuple[bool, str]:
        try:
            client = await self.http.get_client()
            resp = await client.get(
                f"{self.api_base}/user",
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code == 200:
                data = resp.json()
                login = data.get("login", "unknown")
                return True, f"GitHub 用户: {login}"
            if resp.status_code == 401:
                return False, "认证失败: 无效 Token"
            return False, f"HTTP {resp.status_code}"
        except httpx.TimeoutException:
            return False, "连接超时"
        except Exception as e:
            return False, f"连接异常: {e}"

    async def create_issue(
        self,
        finding: FindingRef,
        repository_url: str,
        commit_hash: str,
        branch: str,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        title = self._issue_title(finding)
        body = self._issue_body(finding, repository_url, commit_hash, branch)
        labels = self.config.default_labels if self.config.default_labels else ["security"]

        payload: Dict[str, Any] = {
            "title": title,
            "body": body,
            "labels": labels,
        }

        project = self.config.project_id  # e.g. "owner/repo"
        try:
            client = await self.http.get_client()
            resp = await client.post(
                f"{self.api_base}/repos/{project}/issues",
                json=payload,
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                ticket_id = str(data.get("id", ""))
                ticket_key = data.get("number", ticket_id)
                ticket_url = data.get("html_url", "")
                return ticket_id, str(ticket_key), ticket_url
            else:
                logger.error("GitHub create_issue failed: %s %s", resp.status_code, resp.text[:200])
                return None, None, None
        except Exception as e:
            logger.exception("GitHub create_issue exception")
            return None, None, None

    async def close_issue(
        self,
        ticket_id: str,
        resolution: str = "fixed",
        comment: str = "",
        commit_hash: str = "",
    ) -> bool:
        try:
            if comment or commit_hash:
                await self.add_comment(ticket_id, _close_comment(resolution, comment, commit_hash))
            payload = {"state": "closed"}
            client = await self.http.get_client()
            resp = await client.patch(
                f"{self.api_base}/repos/{self.config.project_id}/issues/{ticket_id}",
                json=payload,
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception as e:
            logger.exception("GitHub close_issue exception")
            return False

    async def add_comment(self, ticket_id: str, comment: str) -> bool:
        try:
            payload = {"body": comment}
            client = await self.http.get_client()
            resp = await client.post(
                f"{self.api_base}/repos/{self.config.project_id}/issues/{ticket_id}/comments",
                json=payload,
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code in (200, 201)
        except Exception as e:
            logger.exception("GitHub add_comment exception")
            return False

    async def update_issue_status(
        self,
        ticket_id: str,
        new_status: TicketStatus,
        comment: str = "",
    ) -> bool:
        try:
            if new_status == TicketStatus.CLOSED:
                payload = {"state": "closed"}
            elif new_status == TicketStatus.REOPENED:
                payload = {"state": "open"}
            else:
                # GitHub 不支持自定义状态，仅评论记录
                if comment:
                    await self.add_comment(ticket_id, comment)
                return True
            client = await self.http.get_client()
            resp = await client.patch(
                f"{self.api_base}/repos/{self.config.project_id}/issues/{ticket_id}",
                json=payload,
                headers=self._headers(),
                timeout=self.config.timeout_seconds,
            )
            ok = resp.status_code == 200
            if ok and comment:
                await self.add_comment(ticket_id, comment)
            return ok
        except Exception as e:
            logger.exception("GitHub update_issue_status exception")
            return False


# ─────────────────────── 适配器工厂 ───────────────────────

def create_adapter(
    provider: DevOpsProvider,
    config: DevOpsConfig,
    http_provider: Optional[HTTPClientProvider] = None,
) -> DevOpsAdapter:
    """根据平台类型创建适配器"""
    if provider == DevOpsProvider.GITLAB:
        return GitLabAdapter(config, http_provider)
    if provider == DevOpsProvider.JIRA:
        return JiraAdapter(config, http_provider)
    if provider == DevOpsProvider.GITHUB:
        return GitHubAdapter(config, http_provider)
    raise ValueError(f"不支持的平台: {provider}")


# ─────────────────────── 工具函数 ───────────────────────

def _close_comment(resolution: str, comment: str, commit_hash: str) -> str:
    """生成关闭评论"""
    parts = []
    if comment:
        parts.append(comment)
    parts.append(f"**解决方式**: {resolution}")
    if commit_hash:
        parts.append(f"**修复提交**: `{commit_hash}`")
    parts.append("*由玄鉴 v3.0 DevSecOps 模块自动更新*")
    return "\n\n".join(parts)


def _ticket_status_to_jira(status: TicketStatus) -> Optional[str]:
    """TicketStatus → Jira 状态名映射"""
    return {
        TicketStatus.OPEN: "To Do",
        TicketStatus.IN_PROGRESS: "In Progress",
        TicketStatus.RESOLVED: "Done",
        TicketStatus.CLOSED: "Done",
        TicketStatus.REOPENED: "To Do",
    }.get(status)


def fingerprint_finding(finding: FindingRef) -> str:
    """生成 Finding 指纹 (去重用)"""
    import hashlib
    raw = f"{finding.rule_id}|{finding.file_path}|{finding.line_start}|{finding.severity}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
