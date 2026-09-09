# D4 - Ticket Manager

## TicketManager

### close_ticket(mapping, adapter, resolution, comment, commit_hash)
- Calls adapter.close_issue()
- Updates mapping status to CLOSED
- Creates SyncRecord

### auto_close_resolved_findings(findings, adapter, resolution, comment)
- Finds all open mappings
- Computes active fingerprints from findings
- Closes mappings whose fingerprints are no longer active

### link_commit_to_ticket(request, adapter)
- Adds comment with commit hash
- Optionally closes ticket after link
- Updates mapping with commit_hash

### handle_status_webhook(ticket_id, from_status, to_status, provider_value)
- Updates local mapping when external status changes
- Creates SyncRecord with TICKET_TO_LOCAL direction

### reopen_ticket_if_vulnerable(mapping, adapter)
- Reopens closed/resolved tickets when vuln reappears
- Calls adapter.update_issue_status(REOPENED)
