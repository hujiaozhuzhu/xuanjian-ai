# B2. 修复验证引擎

## 模块路径

`fp_sentinel/auto_pr/fix_validator.py`

## 职责

提交PR前自动验证修复代码的有效性，确保：
1. 原漏洞已被修复
2. 没有引入新的漏洞
3. 代码语法有效
4. 修复逻辑基本正确

## 核心逻辑

### FixValidator 类

`verify_fix(request: VerifyFixRequest) -> FixVerificationResult`

三重校验：
1. **语法检查** - Python代码AST解析，非Python代码括号匹配
2. **原漏洞修复确认** - 特殊处理SQL注入和路径遍历：
   - SQLi: 检查是否还有字符串拼接（f-string/+/format），验证是否使用参数化查询
   - Path Traversal: 检查是否使用 realpath/abspath
   - 通用: 检查危险模式是否仍在修复代码中
3. **新漏洞引入检测** - 检查eval/exec/os.system/shell=True/pickle.loads/yaml.load等

### FixVerificationResult

- `status`: PASS / WARN / FAIL
- `original_vuln_resolved`: 原漏洞是否已修复
- `new_vulns_introduced`: 引入的新漏洞数
- `syntax_valid`: 语法是否有效
- `security_check_passed`: 安全检查是否通过

### 分支判定

```
if not syntax_valid or not original_resolved or new_vulns > 0:
    FAIL
elif warnings:
    WARN (or FAIL in strict_mode)
else:
    PASS
```

## 安全约束

- S2: 不修改用户源文件
- 零网络依赖

## 测试

- `tests/auto_pr/test_fix_validator.py` - 24 tests, 91% coverage
- 覆盖所有16类漏洞的验证
