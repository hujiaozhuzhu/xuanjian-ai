"""
DevSecOps Integration Module v3.0

Capabilities:
- GitLab/Jira/GitHub sync: auto-create issues from findings
- Pipeline gate: block merge on high/criteria vulns
- Ticket linkage: auto-close tickets on fix

Security: S1/S2/S3/S5/S7
"""

from .adapters import (
    DevOpsAdapter,
    GitLabAdapter,
    JiraAdapter,
    GitHubAdapter,
    HTTPClientProvider,
    create_adapter,
    fingerprint_finding,
)
from .models import (
    BatchSyncFindingsRequest,
    DevOpsConfig,
    DevOpsProvider,
    DevOpsStats,
    FindingRef,
    FindingTicketMapping,
    FindingViolation,
    PipelineGateRequest,
    PipelineGateResult,
    PipelineGateVerdict,
    SyncFindingsRequest,
    SyncRecord,
    SyncResult,
    SyncStatus,
    SyncDirection,
    TicketCloseRequest,
    TicketLinkRequest,
    TicketStatus,
    TicketStatusChangeEvent,
    WebhookEventType,
    WebhookPayload,
    severity_rank,
)
from .pipeline_gate import (
    evaluate_gate,
    format_gate_output,
    gate_exit_code,
)
from .repository import (
    FindingTicketMappingRepo,
    PipelineGateRecordRepo,
    SyncRecordRepo,
)
from .service import DevOpsService
from .ticket_manager import TicketManager
from .webhook_handler import (
    build_ticket_status_change,
    parse_webhook_event,
    verify_gitlab_webhook,
    verify_github_webhook,
    verify_jira_webhook,
)

__all__ = [
    "DevOpsAdapter", "GitLabAdapter", "JiraAdapter", "GitHubAdapter",
    "HTTPClientProvider", "create_adapter", "fingerprint_finding",
    "BatchSyncFindingsRequest", "DevOpsConfig", "DevOpsProvider",
    "DevOpsStats", "FindingRef", "FindingTicketMapping", "FindingViolation",
    "PipelineGateRequest", "PipelineGateResult", "PipelineGateVerdict",
    "SyncFindingsRequest", "SyncRecord", "SyncResult", "SyncStatus",
    "SyncDirection", "TicketCloseRequest", "TicketLinkRequest",
    "TicketStatus", "TicketStatusChangeEvent", "WebhookEventType",
    "WebhookPayload", "severity_rank",
    "evaluate_gate", "format_gate_output", "gate_exit_code",
    "FindingTicketMappingRepo", "PipelineGateRecordRepo", "SyncRecordRepo",
    "DevOpsService", "TicketManager",
    "build_ticket_status_change", "parse_webhook_event",
    "verify_gitlab_webhook", "verify_github_webhook", "verify_jira_webhook",
]

__version__ = "3.0.0"
