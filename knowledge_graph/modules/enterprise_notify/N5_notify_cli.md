# N5: CLI Commands (notify/cli.py)

version: v2.5.0 | file: fp_sentinel/notify/cli.py

## Commands

### Channel Management
- `notify channel add --name NAME --type feishu|dingtalk|wechat_work --webhook URL [--secret SECRET] [--timeout 10]`
- `notify channel list [--all]`
- `notify channel test CHANNEL_ID`
- `notify channel delete CHANNEL_ID`

### Rule Management
- `notify rule add --name NAME [--min-severity HIGH] [--events new_critical,new_high] [--channels ch-1,ch-2]`
- `notify rule list [--all]`
- `notify rule delete RULE_ID`

### Push Operations
- `notify send --channel ch-1 --title TITLE --content CONTENT --severity HIGH`
- `notify history [--status sent|failed|pending|suppressed] [--limit 50]`
- `notify stats`
- `notify clean [--days 90]`

## Registration
The notify sub-app is registered in `fp_sentinel/cli/__init__.py` via:
```python
from ..notify.cli import notify_app
app.add_typer(notify_app, name="notify", help="...")
```
