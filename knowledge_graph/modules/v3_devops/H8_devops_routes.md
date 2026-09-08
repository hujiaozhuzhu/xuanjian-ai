# H8 - REST API Routes

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/devops/sync | Sync findings to external issues |
| POST | /api/devops/gate | Evaluate pipeline security gate |
| POST | /api/devops/close | Close external ticket |
| POST | /api/devops/link | Link fix commit to ticket |
| GET | /api/devops/mappings | List finding-ticket mappings |
| GET | /api/devops/stats | Module statistics |
| GET | /api/devops/mappings/{id} | Single mapping detail with sync records |
| POST | /api/devops/webhook/{provider} | Receive external webhook |

## Path Parameters
- `provider`: gitlab | jira | github

## Request/Response
All endpoints use DTOs defined in models.py. Responses are JSON-serialized Pydantic models.
