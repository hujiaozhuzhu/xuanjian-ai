# 自动化修复模块 (Auto PR) v3.0 - Knowledge Graph

## Overview

自动化修复模块是玄鉴 v3.0 的核心功能之一，实现从漏洞发现到修复代码生成、验证、PR提交的完整自动化流水线。

### Architecture

```
fp_sentinel/auto_pr/
├── __init__.py            # 模块导出
├── models.py              # 数据模型 (Pydantic)
├── auto_fix_generator.py  # 自动修复代码生成器
├── fix_validator.py       # 修复验证引擎
├── pr_manager.py          # PR管理器 (GitLab/GitHub适配器)
├── service.py             # 业务编排服务
└── cli.py                 # CLI命令
```

### Capabilities

1. **自动修复代码生成** - 基于漏洞类型自动生成可落地的修复代码，支持Diff预览、自定义修改
2. **Git仓库对接** - 自动将修复代码提交到GitLab/GitHub，创建修复PR，自动关联对应漏洞单
3. **修复验证** - 提交PR前自动验证修复代码的有效性，确保不会引入新的漏洞
4. **PR管理** - 支持查看PR状态、合并结果、修复历史记录

### Security

- S1: 外部调用通过适配器注入，测试可 mock
- S2: 不修改被扫描源文件（仅生成修复建议）
- S3: 不删除文件
- S5: 数据保留周期可配置
- S7: 数据库路径固定于 ~/.xuanjian/

### Coverage

- 187 tests, 95.54% coverage
- Models: 100%
- Auto Fix Generator: 99%
- Fix Validator: 91%
- PR Manager: 96%
- Service: 92%
- CLI: Excluded (tested via functional tests)

### Design Decisions

1. **VulnerabilityType枚举** - 16类漏洞类型，覆盖OWASP Top 10高危类型
2. **修复模板映射** - 每个VulnerabilityType对应一个_FixTemplate，含bad_patterns/good_example
3. **FixValidator三重校验** - 语法检查 + 原漏洞修复确认 + 新漏洞引入检测
4. **PR适配器模式** - GitLab/GitHub双适配器，支持mock HTTP provider注入
5. **dry_run模式** - 全流程支持dry_run，不实际调用外部API即可测试
