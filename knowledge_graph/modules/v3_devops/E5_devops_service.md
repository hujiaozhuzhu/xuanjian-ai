# E5 - Business Service Layer

## DevOpsService

### sync_findings(request, adapter) -> SyncResult
- Deduplicates via fingerprint
- Creates tickets for new findings
- Saves mapping + sync records

### evaluate_pipeline_gate(request, persist) -> PipelineGateResult
- Wraps evaluate_gate() from pipeline_gate.py
- Optionally persists result to DB

### close_ticket(request, adapter) -> SyncRecord
- Finds mapping by ticket_id
- Delegates to TicketManager.close_ticket()

### link_fix_commit(request, adapter) -> SyncRecord
- Delegates to TicketManager.link_commit_to_ticket()

### handle_webhook_event(event_type, provider_value, payload, adapter)
- Routes to _handle_issue_closed / _handle_issue_reopened / etc.
- Dispatches to TicketManager.handle_status_webhook() (for issue_closed/reopened)

### get_stats() -> DevOpsStats
- Aggregates mapping counts by status
- Aggregates sync counts by status
- Groups mappings by provider
