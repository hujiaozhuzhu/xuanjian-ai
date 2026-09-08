# B2 - API Adapters

## HTTPClientProvider
Injected mock HTTP client. All tests provide mock via constructor.

## GitLabAdapter
- test_connection(): GET /api/v4/version
- create_issue(): POST /api/v4/projects/{id}/issues
- close_issue(): PUT /api/v4/projects/{id}/issues/{iid} (state_event=close)
- add_comment(): POST /api/v4/projects/{id}/issues/{iid}/notes
- Auth: PRIVATE-TOKEN header

## JiraAdapter
- test_connection(): GET /rest/api/2/myself
- create_issue(): POST /rest/api/2/issue (Jira Document Format)
- close_issue(): POST /rest/api/2/issue/{id}/transitions (find close/done transition)
- Auth: Basic base64(username:token)

## GitHubAdapter
- test_connection(): GET /api/v3/user
- create_issue(): POST /api/v3/repos/{owner/repo}/issues
- close_issue(): PATCH /api/v3/repos/{owner/repo}/issues/{number} (state=closed)
- Auth: Bearer token

## Utility Functions
- create_adapter(provider, config, http_provider) -> DevOpsAdapter
- fingerprint_finding(finding) -> str (SHA256 for dedup)
- _close_comment(resolution, comment, commit_hash) -> str
