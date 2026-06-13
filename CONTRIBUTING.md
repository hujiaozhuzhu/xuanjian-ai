# 贡献指南

感谢你对玄鉴 (XuanJian AI) 的关注！我们欢迎各种形式的贡献。

## 当前重点方向

1. ☕ **Java 代码审计误报排查** — 最高优先级
2. 🔍 **Semgrep / SpotBugs / FindSecBugs 结果标准化**
3. 📚 **Java 安全规则误报样例沉淀**
4. 🔌 **MCP Skill 体验优化**
5. 🖥️ **Web 仪表板功能增强**

## 开发环境搭建

### 1. Fork & Clone

```bash
# Fork 仓库后
git clone https://github.com/<your-username>/xuanjian-ai.git
cd xuanjian-ai
git remote add upstream https://github.com/hujiaozhuzhu/xuanjian-ai.git
```

### 2. 创建虚拟环境

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. 安装开发依赖

```bash
pip install -e ".[all]"
```

### 4. 运行测试

```bash
# 运行所有测试
pytest -q

# 运行特定测试
pytest tests/test_fp_sentinel.py -v

# 运行测试并查看覆盖率
pytest --cov=fp_sentinel --cov-report=term-missing
```

### 5. 验证环境

```bash
# CLI
fp-sentinel version
fp-sentinel scan --help

# MCP Server
fp-sentinel mcp --transport stdio

# Web 仪表板
fp-sentinel web --port 8080
```

## 代码规范

### Python 代码风格

- **Python 3.10+**，使用类型注解
- **PEP 8** 为基础，行宽 100 字符
- 使用 **Pydantic v2** 定义数据模型
- 异步函数使用 `async def`
- 字符串统一使用双引号

### 命名规范

| 类型 | 规范 | 示例 |
|------|------|------|
| 模块名 | snake_case | `rule_filter.py` |
| 类名 | PascalCase | `RuleFilter` |
| 函数名 | snake_case | `filter_false_positives` |
| 常量 | UPPER_SNAKE_CASE | `JAVA_FALSE_POSITIVE_RULES` |
| 私有方法 | `_` 前缀 | `_check_path_whitelist` |

### 文档字符串

```python
async def filter(self, scan_result: ScanResult) -> FilterResult:
    """
    过滤单条扫描结果

    Args:
        scan_result: 扫描结果

    Returns:
        FilterResult: 过滤结果，包含判定、置信度和原因
    """
```

### 类型注解

```python
from typing import List, Optional, Dict, Any

def process(
    items: List[ScanResult],
    threshold: float = 0.7,
    config: Optional[Dict[str, Any]] = None,
) -> List[FilterResult]:
    ...
```

## 提交规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 格式：

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Type 类型

| Type | 说明 |
|------|------|
| `feat` | 新功能 |
| `fix` | Bug 修复 |
| `docs` | 文档更新 |
| `style` | 代码格式调整（不影响逻辑） |
| `refactor` | 重构 |
| `test` | 测试相关 |
| `chore` | 构建/工具/配置变更 |

### 示例

```
feat(java): add MyBatis ${} detection in context filter
fix(rule): handle null code in pattern matching
docs(readme): update MCP tools list
test(filter): add edge cases for SQL injection rules
```

### Scope 范围

| Scope | 说明 |
|-------|------|
| `java` | Java 相关 |
| `filter` | 过滤器相关 |
| `scanner` | 扫描器相关 |
| `mcp` | MCP Server 相关 |
| `web` | Web 仪表板相关 |
| `cli` | CLI 相关 |
| `config` | 配置相关 |
| `db` | 数据库相关 |

## PR 流程

### 1. 创建分支

```bash
git checkout -b feat/my-feature
# 或
git checkout -b fix/my-bugfix
```

### 2. 开发 & 测试

```bash
# 编写代码
# ...

# 运行测试
pytest -q

# 确保无 lint 错误
python -m py_compile fp_sentinel/my_module.py
```

### 3. 提交

```bash
git add .
git commit -m "feat(scope): description"
```

### 4. 推送 & 创建 PR

```bash
git push origin feat/my-feature
```

在 GitHub 上创建 Pull Request，填写：

- **标题**：简洁描述变更
- **描述**：说明做了什么、为什么做、如何测试
- **关联 Issue**：如果有相关 Issue

### 5. Code Review

- 等待维护者 review
- 根据反馈修改代码
- 所有 CI 检查通过后合并

## 如何添加新的扫描器

### 1. 创建扫描器适配器

```python
# fp_sentinel/scanners/my_scanner.py

from typing import List, Dict, Any, Optional
from .base import BaseScanner
from ..models import ScanResult, ScanTool, Severity


class MyScanner(BaseScanner):
    """MyScanner 适配器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.timeout = self.config.get("timeout", 300)

    async def scan(self, target_path: str, **kwargs) -> List[ScanResult]:
        """扫描目标路径"""
        import asyncio
        import json

        # 1. 调用外部工具
        cmd = ["my-scanner", "--json", target_path]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=self.timeout
        )

        # 2. 解析输出
        raw_output = json.loads(stdout.decode())

        # 3. 转换为 ScanResult
        results = []
        for item in raw_output.get("findings", []):
            results.append(ScanResult(
                tool=self.get_tool_type(),
                rule_id=item["rule_id"],
                file=item["file"],
                line=item["line"],
                code=item.get("code", ""),
                severity=Severity(item.get("severity", "MEDIUM")),
                message=item.get("message", ""),
                cwe=item.get("cwe"),
            ))

        return results

    def get_tool_type(self) -> ScanTool:
        return ScanTool.MY_TOOL  # 需要先在枚举中添加
```

### 2. 注册扫描器

在 `fp_sentinel/models.py` 的 `ScanTool` 枚举中添加：

```python
class ScanTool(str, Enum):
    # ... 已有
    MY_TOOL = "my_tool"
```

在 `fp_sentinel/scanners/manager.py` 中注册：

```python
from .my_scanner import MyScanner

def _init_scanners(self):
    # ... 已有扫描器
    my_config = scanner_configs.get("my_tool", {"enabled": True})
    if my_config.get("enabled", True):
        self.scanners[ScanTool.MY_TOOL] = MyScanner(my_config)
```

### 3. 添加测试

```python
# tests/test_my_scanner.py

import pytest
from fp_sentinel.scanners.my_scanner import MyScanner


@pytest.mark.asyncio
async def test_my_scanner_basic():
    scanner = MyScanner()
    results = await scanner.scan("/path/to/test/project")
    assert isinstance(results, list)
```

### 4. 更新配置

在 `fp_sentinel/config.py` 的 `DEFAULT_CONFIG` 中添加：

```python
DEFAULT_CONFIG = {
    "scanners": {
        # ... 已有
        "my_tool": {
            "enabled": True,
            "timeout": 300,
        },
    },
}
```

## 如何添加新的过滤规则

### 1. Java 规则

在 `fp_sentinel/rules/java/rules.py` 中添加：

```python
JAVA_FALSE_POSITIVE_RULES.append({
    "name": "java_my_new_rule",
    "rule_id_pattern": "my.vulnerability.pattern",
    "code_pattern": r"mySafeFunction|MySecurityGuard",
    "reason": "使用了安全防护函数",
    "confidence": 0.8,
})
```

### 2. 安全守卫模式

在 `JAVA_SECURITY_GUARD_PATTERNS` 中添加：

```python
JAVA_SECURITY_GUARD_PATTERNS["my_vuln_type"] = [
    "myGuardFunction", "MySecurityCheck",
]
```

### 3. 通用规则（配置文件方式）

用户可以在 `xuanjian.yaml` 中添加自定义规则，无需修改代码。详见 [Java 误报规则文档](docs/java-rules.md)。

### 4. 添加测试

```python
# tests/test_my_rule.py

import pytest
from fp_sentinel.filters import RuleFilter
from fp_sentinel.models import ScanResult, ScanTool, Severity


@pytest.mark.asyncio
async def test_my_rule_matches():
    filter = RuleFilter({"enabled": True})
    result = ScanResult(
        tool=ScanTool.SEMGREP,
        rule_id="my.vulnerability.pattern",
        file="src/main/java/MyService.java",
        line=42,
        code="mySafeFunction(userInput)",
        severity=Severity.HIGH,
        message="Potential vulnerability",
    )
    fr = await filter.filter(result)
    assert fr.verdict.value == "false_positive"
    assert fr.confidence >= 0.8
```

## 提交误报样例

我们特别欢迎真实的误报样例！请确保：

- ✅ 不包含真实业务代码
- ✅ 不包含真实密钥/凭证
- ✅ 不包含客户扫描结果
- ✅ 给出误报原因说明
- ✅ 包含扫描器原始输出和误报判断

示例格式：

```json
{
  "tool": "semgrep",
  "rule_id": "java.lang.security.audit.sql-injection",
  "file": "src/UserDao.java",
  "line": 42,
  "code": "jdbcTemplate.query(sql, args)",
  "severity": "HIGH",
  "message": "Potential SQL injection",
  "is_false_positive": true,
  "reason": "使用 JdbcTemplate 参数化查询，sql 参数不含用户输入"
}
```

## 社区

- **GitHub Issues** — 报告 Bug、提出功能请求
- **Pull Requests** — 贡献代码
- **Discussions** — 技术讨论、使用问答

## 行为准则

- 尊重每一位参与者
- 建设性地提出批评和建议
- 专注于对社区最有利的事情
- 对他人表示同理心
