# N2: SQLite Storage Layer (notify/store.py)

version: v2.5.0 | file: fp_sentinel/notify/store.py | tests: 34 cases

## Schema

notify_channels(id, name, channel_type, webhook_url, secret, enabled, timeout_seconds, created_at, updated_at)
notify_rules(id, name, enabled, min_severity, events, channels, frequency, rule_id_patterns, path_patterns, suppress_duplicates_minutes, created_at, updated_at)
notify_records(id, channel_id, rule_id, event, finding_id, status, title, content, error_message, retry_count, created_at, sent_at)

## Class: NotifyStore

Connection management (aiosqlite + WAL, context manager pattern)

### Channel CRUD
- create_channel(channel: IMChannel) -> IMChannel
- update_channel(channel: IMChannel) -> IMChannel
- delete_channel(channel_id: str) -> bool
- get_channel(channel_id: str) -> Optional[IMChannel]
- list_channels(enabled_only: bool = False) -> List[IMChannel]

### Rule CRUD
- create_rule(rule: NotifyRule) -> NotifyRule
- update_rule(rule: NotifyRule) -> NotifyRule
- delete_rule(rule_id: str) -> bool
- get_rule(rule_id: str) -> Optional[NotifyRule]
- list_rules(enabled_only: bool = False) -> List[NotifyRule]

### Push Records
- create_record(record: NotifyRecord) -> NotifyRecord
- update_record_status(record_id, status, error_message?, retry_count?, sent_at?) -> None
- list_records(status_filter?, channel_id?, limit?) -> List[NotifyRecord]
- count_recent_by_finding(finding_id, window_minutes) -> int  (dedup check)
- purge_records(days) -> int  (S5 cleanup)
- stats() -> Dict  (summary stats)

## Helper Functions
- default_notify_db_path() -> str  (~/.xuanjian/notify.db)
- open_store(db_path?) -> NotifyStore
