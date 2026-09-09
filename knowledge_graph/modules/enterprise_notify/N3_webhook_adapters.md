# N3: IM Webhook Adapters (notify/webhook.py)

version: v2.5.0 | file: fp_sentinel/notify/webhook.py | tests: 33 cases

## Adapters

### FeishuWebhookAdapter
- Formats notifications using Feishu post message format
- Severity colors: red(CRITICAL), orange(HIGH), yellow(MEDIUM), blue(LOW), grey(INFO)
- Uses post.zh_cn.content rich text structure

### DingTalkWebhookAdapter
- Formats as markdown message
- Optional HMAC-SHA256 signing with timestamp
- sign() returns {timestamp, sign} for URL query params

### WeChatWorkWebhookAdapter
- Formats as markdown message (max 4096 bytes)
- Color tags: warning(CRITICAL/HIGH), comment(MEDIUM), info(LOW/INFO)
- Auto-truncates content that exceeds byte limit

## Functions
- get_adapter(channel_type) -> WebhookAdapter  (factory)
- send_notification(channel, payload, http_client?) -> ChannelTestResult
- check_channel(channel, http_client?) -> ChannelTestResult
- _ssl_verify() -> bool  (respects XUANJIAN_NOTIFY_VERIFY_SSL env)

## Security
- All requests go to URL from IMChannel config (validated at creation)
- SSL verification enabled by default
- No external URLs possible (blocked by IMChannel.validate_internal_url)
