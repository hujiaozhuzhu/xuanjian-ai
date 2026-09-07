# A1. PoC 模板库

> 版本：v2.2.0 | 文件：`fp_sentinel/attack/poc_templates.py`
> 覆盖：20 种漏洞类型 + 1 种新型 LLM 提示词注入

## 设计要点

### 数据结构
- `PocTemplate`（dataclass）：单条模板（vuln_type, cwe, payload_template, safety_level 等）
- `PocInstance`（dataclass）：生成后的 PoC 实例（含 rendered 文本）
- `POC_TEMPLATES: Dict[str, PocTemplate]`：全局模板字典，按 vuln_type 索引

### 模板清单（21 种）
1. `sqli-union` - SQL UNION 注入
2. `sqli-time` - SQL 时间盲注
3. `xss-reflected` - 反射型 XSS
4. `xss-dom` - DOM 型 XSS
5. `cmd-injection` - 命令注入
6. `ssrf` - SSRF（目标锁定 127.0.0.1）
7. `path-traversal` - 路径遍历
8. `jwt-weak` - JWT 弱密钥（模式 B 本地 HMAC）
9. `deser-pickle` - Pickle 反序列化
10. `deser-yaml` - YAML 不安全加载
11. `xxe` - XML 外部实体注入
12. `prototype-pollution` - JS 原型链污染
13. `open-redirect` - 开放重定向
14. `idor` - 越权访问
15. `nosql-injection` - MongoDB 操作符注入
16. `ssti` - 服务端模板注入
17. `weak-hash` - 弱哈希算法
18. `hardcoded-secret` - 硬编码密钥
19. `debug-mode` - 调试模式暴露
20. `csrf-missing` - CSRF 防护缺失
21. `sql-format-string` - SQL 格式化字符串注入
22. `llm-prompt-injection` - LLM 提示词注入（OWASP-LLM01）

### 安全红线实现

**S1 - 本地目标守卫**：
- `_assert_local(target)` 解析 URL，校验 hostname ∈ {127.0.0.1, localhost, ::1}
- 非法目标抛 `UnsafeTargetError`（含明确提示信息）
- `generate_poc()` 与 `generate_all_pocs()` 均强制调用 `_assert_local()`

**S2 + S4 - 仅生成字符串，零网络**：
- 模式 A（默认）：模板字符串填充 {target_url}/{param}/{payload}
- 模式 B（jwt-weak）：本地 HMAC + base66 离线伪造 JWT（仅用 stdlib hmac/hashlib/base64）
- 不 import requests/httpx/socket，无任何真实基础设施地址

### 防御性说明
每个模板携带 `safe_explanation`（修复方法说明）+ `reference_cve`（真实 CVE 编号字典，静态），直接写入攻防报告的参考案例。

## 测试结果

```
tests/unit/test_attack_poc.py — 用例 24
- TestTemplateCompleteness（5）: 模板齐全度、字段完整、CVE 格式、教科书 payload
- TestUnsafeTargetGuard（8）: 外部目标拦截（6 参数化）、本地目标放行、错误信息
- TestPocGeneration（6）: 变量填充、默认 payload、JWT 本地加密、确定性、异常、列表
结果：24 PASSED
```

## 变更说明

| 文件 | 变更 |
|------|------|
| `fp_sentinel/attack/poc_templates.py` | 新建，实现 22 种模板 + UnsafeTargetError + assert_local |
| `fp_sentinel/attack/__init__.py` | 导出 generate_poc, UnsafeTargetError, forge_jwt_token 等 |
