# G7 - CLI Commands

## Typer Subcommands

| Command | Description |
|---------|-------------|
| `sync` | Sync findings to issues |
| `gate` | Evaluate pipeline security gate |
| `close` | Close external ticket |
| `link` | Link fix commit to ticket |
| `status` | List finding-ticket mappings |
| `stats` | DevOps module statistics |

## Usage Examples

```bash
fp-sentinel devops sync --provider gitlab -p 123 -f findings.json
fp-sentinel devops gate --provider gitlab -p 123 -f findings.json
fp-sentinel devops close --provider jira --ticket-id VULN-123
fp-sentinel devops link --provider github --ticket-id 42 --commit abc123
fp-sentinel devops status
fp-sentinel devops stats
```
