# F6 - Webhook Handler

## Event Parsing

### parse_webhook_event(provider, event_header, payload) -> WebhookEventType

**GitLab**: X-Gitlab-Event header (Issue Hook / Merge Request Hook / Pipeline Hook)
**GitHub**: X-GitHub-Event header (issues / pull_request / check_run)
**Jira**: webhookEvent field (jira:issue_updated)

### build_ticket_status_change(provider, payload) -> TicketStatusChangeEvent

Extracts ticket_id, from/to status from platform-specific payloads.

## Signature Verification

### verify_gitlab_webhook(body, token, header_value)
Simple token comparison against X-Gitlab-Token header.

### verify_github_webhook(body, secret, signature_header)
HMAC-SHA256 verification: sha256=... in X-Hub-Signature-256.

### verify_jira_webhook(body, secret, authorization_header)
Bearer token comparison.
