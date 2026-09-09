# N1: Notification Data Models (notify/models.py)

version: v2.5.0 | file: fp_sentinel/notify/models.py | tests: 23 cases

## Model Inventory

| Model | Type | Description |
|-------|------|-------------|
| IMChannelType | Enum | feishu / dingtalk / wechat_work |
| NotifyEvent | Enum | new_critical / new_high / status_changed / scan_completed / daily_digest |
| NotifyFrequency | Enum | realtime / hourly / daily / weekly |
| NotifyStatus | Enum | pending / sent / failed / suppressed |
| IMChannel | BaseModel | IM channel config (name, type, webhook URL, secret) |
| NotifyRule | BaseModel | Push rule (trigger conditions, recipients, frequency, filters) |
| NotifyRecord | BaseModel | Push record (finding ref, channel, status, content) |
| NotificationPayload | BaseModel | Full notification message body |
| ChannelTestResult | BaseModel | Channel connectivity test result |

## Security Validation (S1 Redline)

webhook_url validator blocks external IM domains:
- hooks.slack.com
- discord.com/api/webhooks
- api.telegram.org
- oapi.dingtalk.com
- qyapi.weixin.qq.com

Only http:// and https:// schemes are allowed.

## Utility Functions

| Function | Description |
|----------|-------------|
| severity_rank(severity) | Severity priority mapping (CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0) |
| event_to_display(event) | Chinese display for event types |
| status_to_display(status) | Chinese display for push status |
