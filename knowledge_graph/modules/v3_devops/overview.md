# DevSecOps Module v3.0 - Knowledge Graph

## Overview

DevSecOps module for Xuanjian v3.0 integrates security scans with CI/CD platforms.

### Architecture

- `models.py` - Data models (Pydantic)
- `adapters.py` - API adapters (GitLab/Jira/GitHub)
- `pipeline_gate.py` - Pipeline security gate
- `ticket_manager.py` - Ticket lifecycle engine
- `service.py` - Business orchestration
- `webhook_handler.py` - Webhook event handling
- `repository.py` - SQLite persistence
- `cli.py` - CLI commands
- `routes.py` - REST API

### Security

- All HTTP calls injectable via mock (HTTPClientProvider)
- No file modifications (S2/S3)
- Data retention configurable (S5)
- No new attack surface (S7)
