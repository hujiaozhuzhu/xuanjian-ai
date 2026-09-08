# C3. PR 管理器

## 模块路径

`fp_sentinel/auto_pr/pr_manager.py`

## 职责

管理修复PR的全生命周期：创建提交、查看状态、工单关联、历史记录。

## 核心组件

### GitProviderAdapter (抽象基类)
- `test_connection()` - 检测连通性
- `create_pull_request(title, desc, src_branch, tgt_branch, labels)` - 创建PR，返回(pr_id, pr_url)
- `get_pr_status(pr_id)` - 获取PR状态
- `add_pr_comment(pr_id, comment)` - 添加PR评论

### GitLabPRAdapter
- API: `https://xxx/api/v4`
- Auth: PRIVATE-TOKEN header
- 创建MR: POST `/projects/{id}/merge_requests`
- 获取状态: GET `/projects/{id}/merge_requests/{iid}`

### GitHubPRAdapter
- API: `https://api.github.com`
- Auth: Authorization: Bearer header
- 创建PR: POST `/repos/{owner/repo}/pulls`
- 获取状态: GET `/repos/{owner/repo}/pulls/{number}`，merged_at字段判断合并

### GitHTTPProvider
- 可注入 mock HTTP client 用于测试

### PRManager
- `submit_pull_request(config, patches, ...)` - 提交修复PR
- `check_pr_status(pr_id, adapter)` - 检查PR状态
- `link_ticket_to_pr(pr_id, ticket_id, adapter)` - 关联工单到PR
- `submit_pull_request` 支持 dry_run 模式

## 安全约束

- S1: 外部HTTP调用通过GitHTTPProvider注入
- S2: 不修改被扫描代码（仅操作PR）
- S3: 不删除文件

## 测试

- `tests/auto_pr/test_pr_manager.py` - 16 tests
- `tests/auto_pr/test_pr_adapters.py` - 30+ mock adapter tests, 95% coverage
