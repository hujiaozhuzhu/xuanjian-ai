"""
DevSecOps 对接模块 - Webhook 事件处理

接收来自 GitLab/Jira/GitHub 的 Webhook 回调，驱动：
- 工单状态变更 -> 更新本地 mapping
- 合并请求事件 -> 可触发增量扫描
- 流水线结果 -> 归档到本地记录

安全红线：
- S1: 仅处理事件，不主动发起外部请求
- S3: 本地操作只更新状态字段
- HMAC 签名验证防止伪造
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Any, Callable, Dict, Optional

from .models import (
    DevOpsProvider,
    TicketStatus,
    TicketStatusChangeEvent,
    WebhookEventType,
    WebhookPayload,
)

logger = logging.getLogger(__name__)


def verify_gitlab_webhook(payload_body: bytes, token: str, header_value: str) -> bool:
    """
    验证 GitLab Webhook Token (简单 token 比较)
    GitLab 使用 X-Gitlab-Token header
    """
    if not token:
        return True  # 未配置 token 时不校验
    return hmac.compare_digest(header_value or "", token)


def verify_github_webhook(
    payload_body: bytes,
    secret: str,
    signature_header: str,
) -> bool:
    """
    验证 GitHub Webhook HMAC-SHA256 签名
    GitHub 使用 X-Hub-Signature-256: sha256=...
    """
    if not secret:
        return True
    if not signature_header:
        return False
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def verify_jira_webhook(
    payload_body: bytes,
    secret: str,
    authorization_header: str,
) -> bool:
    """
    验证 Jira Webhook (简单 JWT 或共享密钥)
    Jira 通常使用 Authorization: Bearer <shared-secret>
    """
    if not secret:
        return True
    expected = f"Bearer {secret}"
    return hmac.compare_digest(authorization_header or "", expected)


def parse_webhook_event(
    provider: DevOpsProvider,
    event_header: str,
    payload: Dict[str, Any],
) -> WebhookEventType:
    """
    从 Webhook header 和 payload 解析事件类型

    GitLab: X-Gitlab-Event: Issue Hook / Merge Request Hook / Pipeline Hook
    GitHub: X-GitHub-Event: issues / pull_request / check_run / pipeline
    Jira:   webhookEvent: jira:issue_updated / jira:issue_created
    """
    if provider == DevOpsProvider.GITLAB:
        return _parse_gitlab_event(event_header, payload)
    if provider == DevOpsProvider.GITHUB:
        return _parse_github_event(event_header, payload)
    if provider == DevOpsProvider.JIRA:
        return _parse_jira_event(event_header, payload)
    return WebhookEventType.PIPELINE_STATUS


def _parse_gitlab_event(event_header: str, payload: Dict[str, Any]) -> WebhookEventType:
    """解析 GitLab webhook 事件类型"""
    header = (event_header or "").lower()
    obj_attr = payload.get("object_attributes", {})
    state = obj_attr.get("state", "")

    if "issue" in header:
        if state == "closed":
            return WebhookEventType.ISSUE_CLOSED
        elif state == "reopened":
            return WebhookEventType.ISSUE_REOPENED
        return WebhookEventType.PIPELINE_STATUS
    if "merge" in header:
        return WebhookEventType.MERGE_REQUEST
    if "pipeline" in header:
        return WebhookEventType.PIPELINE_STATUS
    return WebhookEventType.PIPELINE_STATUS


def _parse_github_event(event_header: str, payload: Dict[str, Any]) -> WebhookEventType:
    """解析 GitHub webhook 事件类型"""
    header = (event_header or "").lower()
    action = payload.get("action", "")

    if "issue" in header:
        if action == "closed":
            return WebhookEventType.ISSUE_CLOSED
        elif action == "reopened":
            return WebhookEventType.ISSUE_REOPENED
        return WebhookEventType.PIPELINE_STATUS
    if "pull_request" in header:
        return WebhookEventType.MERGE_REQUEST
    if "check_run" in header or "pipeline" in header:
        return WebhookEventType.PIPELINE_STATUS
    return WebhookEventType.PIPELINE_STATUS


def _parse_jira_event(event_header: str, payload: Dict[str, Any]) -> WebhookEventType:
    """解析 Jira webhook 事件类型"""
    webhook_event = payload.get("webhookEvent", "")
    changelog = payload.get("changelog", {})
    items = changelog.get("items", [])

    if "issue_updated" in webhook_event or "issue_created" in webhook_event:
        for item in items:
            if item.get("field") == "status":
                to_status = item.get("toString", "").lower()
                if "close" in to_status or "done" in to_status or "resolved" in to_status:
                    return WebhookEventType.ISSUE_CLOSED
                elif "reopen" in to_status or "open" in to_status:
                    return WebhookEventType.ISSUE_REOPENED
                elif "progress" in to_status:
                    return WebhookEventType.PIPELINE_STATUS
        return WebhookEventType.PIPELINE_STATUS
    return WebhookEventType.PIPELINE_STATUS


def build_ticket_status_change(
    provider: DevOpsProvider,
    payload: Dict[str, Any],
) -> Optional[TicketStatusChangeEvent]:
    """
    从 Webhook payload 构建 TicketStatusChangeEvent 对象
    适配三种平台的字段差异
    """
    if provider == DevOpsProvider.GITLAB:
        issue = payload.get("issue") or payload.get("object_attributes", {})
        if not issue:
            return None
        from_state = _gitlab_state_to_ticket(issue.get("state", ""))
        # GitLab webhook 的 state 通常是最终状态
        to_state = from_state
        return TicketStatusChangeEvent(
            provider=provider,
            ticket_id=str(issue.get("iid") or issue.get("id", "")),
            ticket_key=str(issue.get("iid", "")),
            from_status=TicketStatus.OPEN,
            to_status=to_state,
            project_id=str(issue.get("project_id", "")),
            closed_by=issue.get("closed_by", {}).get("username", "") if isinstance(issue.get("closed_by"), dict) else "",
            resolution=issue.get("state", ""),
            raw_payload=payload,
        )
    if provider == DevOpsProvider.JIRA:
        issue = payload.get("issue", {})
        changelog = payload.get("changelog", {})
        status_item = None
        for item in changelog.get("items", []):
            if item.get("field") == "status":
                status_item = item
                break
        if issue and status_item:
            return TicketStatusChangeEvent(
                provider=provider,
                ticket_id=str(issue.get("id", "")),
                ticket_key=issue.get("key", ""),
                from_status=_jira_status_to_ticket(status_item.get("fromString", "")),
                to_status=_jira_status_to_ticket(status_item.get("toString", "")),
                project_id=str(issue.get("fields", {}).get("project", {}).get("id", "")),
                closed_by=payload.get("user", {}).get("displayName", ""),
                resolution=status_item.get("toString", ""),
                raw_payload=payload,
            )
    if provider == DevOpsProvider.GITHUB:
        issue = payload.get("issue", {})
        action = payload.get("action", "")
        if issue:
            to_status = TicketStatus.CLOSED if action == "closed" else (
                TicketStatus.REOPENED if action == "reopened" else TicketStatus.OPEN
            )
            return TicketStatusChangeEvent(
                provider=provider,
                ticket_id=str(issue.get("number") or issue.get("id", "")),
                ticket_key=str(issue.get("number", "")),
                from_status=TicketStatus.OPEN,
                to_status=to_status,
                project_id="",
                closed_by=payload.get("sender", {}).get("login", ""),
                resolution=action,
                raw_payload=payload,
            )
    return None


def _gitlab_state_to_ticket(state: str) -> TicketStatus:
    """GitLab issue state -> TicketStatus"""
    return {
        "closed": TicketStatus.CLOSED,
        "reopened": TicketStatus.REOPENED,
        "opened": TicketStatus.OPEN,
    }.get(state.lower(), TicketStatus.OPEN)


def _jira_status_to_ticket(status: str) -> TicketStatus:
    """Jira status string -> TicketStatus"""
    s = status.lower()
    if any(k in s for k in ("close", "done", "resolved")):
        return TicketStatus.CLOSED
    if "reopen" in s:
        return TicketStatus.REOPENED
    if "progress" in s:
        return TicketStatus.IN_PROGRESS
    if "open" in s or "to do" in s or "todo" in s or "backlog" in s:
        return TicketStatus.OPEN
    return TicketStatus.OPEN
