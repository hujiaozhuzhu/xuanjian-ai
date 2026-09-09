# A1. 自动修复代码生成器

## 模块路径

`fp_sentinel/auto_pr/auto_fix_generator.py`

## 职责

基于漏洞类型自动生成可落地的修复代码，支持Diff预览和自定义修改。

## 核心组件

### VulnerabilityType 映射

`_match_vuln_type(rule_id: str) -> VulnerabilityType` 将 semgrep/bandit 等扫描器的 rule_id 映射到内部的 16 类 VulnerabilityType：

- 优先级匹配：os.system > injection.sql > xss > command.injection > ... > generic
- 支持 `.` 和 `-` 两种分隔符

### _FixTemplate 模板

每个 VulnerabilityType 对应一个模板，包含：
- `bad_patterns`: 用于从代码片段中识别危险行
- `good_example`: 安全代码示例
- `effort_minutes`: 预计修复工时
- `reference_cve`: 参考CVE
- `incident_note`: 事故说明

### AutoFixGenerator 类

核心方法：
- `generate_fix_preview(request)` - 生成修复预览（Diff格式）
- `generate_patch(request, custom_fix_code)` - 生成修复补丁
- `customize_patch(patch_id, custom_code)` - 自定义修改补丁
- `batch_generate_previews(requests)` - 批量生成预览
- `batch_generate_patches(requests)` - 批量生成补丁

### 便捷函数

`generate_fix_preview(...)` - 快速生成修复预览的一站式函数。

## 安全约束

- S2: 绝不修改用户源文件，仅生成修复建议字符串
- 零网络、零写入

## 覆盖的漏洞类型 (16类)

1. SQL_INJECTION - SQL 注入
2. XSS - 跨站脚本
3. COMMAND_INJECTION - 命令注入
4. PATH_TRAVERSAL - 路径遍历
5. HARDCODED_SECRET - 硬编码密钥
6. JWT_WEAK - JWT 弱密钥/弱算法
7. YAML_UNSAFE - YAML 不安全加载
8. PICKLE_DESERIALIZE - Pickle 反序列化
9. EVAL_INJECTION - eval 代码注入
10. SSRF - 服务端请求伪造
11. WEAK_HASH - 弱哈希（MD5/SHA1）
12. ECB_MODE - ECB 模式加密
13. DEBUG_EXPOSURE - 调试模式暴露
14. OPEN_REDIRECT - 开放重定向
15. OS_COMMAND - os.system 命令执行
16. GENERIC - 通用修复建议

## 测试

- `tests/auto_pr/test_auto_fix_generator.py` - 32 tests, 99% coverage
- 覆盖规则匹配、Diff生成、自定义修改、批量生成、所有VulnerabilityType
