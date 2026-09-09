# N4: Notification Engine (notify/engine.py)

version: v2.5.0 | file: fp_sentinel/notify/engine.py | tests: 48 cases

## Core Logic

### Rule Matching (match_rule / match_rules)
Matching conditions (AND):
1. Rule enabled
2. Finding severity >= rule min_severity
3. Event type in rule events
4. Finding rule_id matches rule_id_patterns (if any)
5. Finding file_path matches path_patterns (if any)

### Frequency Control
- Duplicate suppression via count_recent_by_finding()
- Time window configured per rule (suppress_duplicates_minutes)

### Dispatch Flow
1. Load enabled rules from store
2. For each finding, determine event type (CRITICAL -> NEW_CRITICAL, HIGH -> NEW_HIGH)
3. Match against all enabled rules
4. For matched rules: check duplicate suppression -> send via webhook
5. Record result (sent/failed/suppressed) in store

## NotifyEngine Class
- Optional injected store (for testing)
- Or creates own store via open_store() (for production)

### Methods
- process_findings(findings, events?) -> List[NotifyRecord]
- notify_status_change(finding, old_status, new_status) -> List[NotifyRecord]

## Convenience Functions
- process_findings(findings, events?) -> List[NotifyRecord]
- notify_status_change(finding, old_status, new_status) -> List[NotifyRecord]

Both open their own NotifyEngine context.
