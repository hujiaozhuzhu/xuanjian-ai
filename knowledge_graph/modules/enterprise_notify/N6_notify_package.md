# N6: Package Entry (notify/__init__.py)

version: v2.5.0 | file: fp_sentinel/notify/__init__.py

## Exports

### Models
- IMChannel, IMChannelType, NotifyEvent, NotifyFrequency, NotifyStatus, NotifyRule, NotifyRecord, NotificationPayload, ChannelTestResult
- severity_rank, event_to_display, status_to_display

### Store
- NotifyStore, open_store, default_notify_db_path

### Webhook
- WebhookAdapter, FeishuWebhookAdapter, DingTalkWebhookAdapter, WeChatWorkWebhookAdapter
- get_adapter, send_notification, check_channel

### Engine
- NotifyEngine, match_rule, match_rules, process_findings, notify_status_change

## Version
__version__ = "2.5.0"
