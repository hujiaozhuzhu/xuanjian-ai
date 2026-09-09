# B2 -- 自动修复PR模块 API (v3.1)

## 文件位置
fp_sentinel/auto_pr/routes.py

## 路由前缀
/api/auto-pr

## 端点详情

### 1. 修复预览
- POST /api/auto-pr/preview
- 请求体: PreviewRequest (findings[])
- 响应含: total_requested, total_generated, total_failed, previews[]
- 每个preview含: finding_id, rule_id, severity, file_path, vuln_type, unified_diff,
  title, effort_minutes, reference_cve, can_customize

### 2. 单修复验证
- POST /api/auto-pr/verify
- 请求体: VerifyRequest (patch_id, finding_id, original_code, fixed_code,
  rule_id, vuln_type)
- 响应含: 验证结果（原漏洞是否修复、新漏洞数、语法、安全检查）

### 3. 三重校验
- POST /api/auto-pr/verify/triple
- 请求体: VerifyTripleRequest (patch_id, finding_id, original_code, fixed_code,
  rule_id, vuln_type, file_path)
- 响应含: overall_status, checks{original_vuln_resolved, no_new_vulns,
  syntax_valid, security_check}

### 4. 创建PR (核心安全控制)
- POST /api/auto-pr/create
- 请求体: CreatePRRequest
  - dry_run: bool = True (默认干运行)
  - confirm: bool = False (二次确认)
  - 安全规则: dry_run=False + confirm=False → 403拒绝
- 响应含: status("dry_run"|"submitted"), preview, next_steps

### 5. 修复状态查询
- GET /api/auto-pr/status/{record_id}
- 返回修复记录详情

### 6. 修复历史
- GET /api/auto-pr/history
- 查询参数: status_filter(可选), limit(50), offset(0)

### 7. PR统计
- GET /api/auto-pr/stats
- 返回PRStats

### 8. 配置查询
- GET /api/auto-pr/config
- 返回当前配置（api_token等敏感字段自动掩码）

### 9. 配置更新
- PUT /api/auto-pr/config
- 请求体: UpdateConfigRequest（各字段可选）

## 安全红线 (v3.1增强)

### PR创建安全机制
1. **强制dry_run优先**: create接口默认dry_run=True，仅返回预览
2. **二次确认**: 真实提交需同时满足 dry_run=False AND confirm=True
3. **三重校验**: PR创建前建议先调用三重校验接口
4. **敏感字段掩码**: 配置接口中api_token显示为 ****abcd1234 格式

### 安全适配
- 所有Git操作通过适配器注入（S1）
- 不修改源文件（S2）
- 不删除文件（S3）
- 数据保留周期可配置（S5）
