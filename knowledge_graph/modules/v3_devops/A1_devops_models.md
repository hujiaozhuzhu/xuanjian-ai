# A1 - DevOps Data Models

## Enums

- `DevOpsProvider`: gitlab / jira / github
- `TicketStatus`: open / closed / resolved / in_progress / reopened
- `SyncStatus`: pending / synced / failed / skipped
- `SyncDirection`: finding_to_ticket / ticket_to_local
- `PipelineGateVerdict`: pass / warn / block
- `WebhookEventType`: issue_closed / issue_reopened / merge_request / pipeline_status

## Key Models

### FindingRef
```python
FindingRef(id, severity, rule_id, file_path, line_start, message, cve, cwe)
```

### DevOpsConfig
```python
DevOpsConfig(
    provider: DevOpsProvider,
    base_url: str,
    api_token: str,
    project_id: str,
    jira_project_key: str = "",
    block_on_critical: bool = True,
    block_on_high: bool = True,
    warn_on_medium: bool = True,
    warn_on_low: bool = False,
    max_findings_threshold: int = 0,
    auto_close_on_resolve: bool = True,
    default_labels: List[str] = [],
    timeout_seconds: int = 30,
)
```

### FindingTicketMapping (SQLite Table: do_finding_ticket_mapping)
- Links external ticket to local finding
- Fields: id, finding_id, finding_fingerprint, provider, ticket_id, ticket_key, ticket_url, ticket_status, sync_status, severity, rule_id, metadata(json)

### SyncRecord (SQLite Table: do_sync_record)
- Records every sync attempt
- Fields: id, mapping_id, finding_id, provider, sync_direction, status, ticket_id, ticket_key, error_message, request_payload, response_summary, attempt_count

### PipelineGateResult
```python
PipelineGateResult(
    verdict: PipelineGateVerdict,
    total_findings: int,
    critical_count, high_count, medium_count, low_count, info_count,
    violations: List[FindingViolation],
    warnings: List[FindingViolation],
    summary: str,
    suggested_actions: List[str],
)
```
