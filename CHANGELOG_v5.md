# fp_sentinel v5.0 — 审计 Agent 升级版

发布日期：2026-09-23

## 规则层（rules/）
- rules/rule_registry.py — 暴露 check_scope / require_write_opt_in / fail_closed
- rules/__init__.py — 对外提供 get_registry() 单例
- 加载 skills/fp_sentinel/rules/ 下 15 份规则文件
- CLI scan / setup 命令已接入红线闸门

## 模块层（modules/）
- 5 个核心模块追加 available() / self_check() / module_version()
  - attack/dom_verify, api_knowledge/store, api_knowledge/associator
  - web_api/api_discovery, attack/harmless_verifier
- 对外暴露走各模块 __init__.py

## 规则-模块仲裁
- rules/ 文件冲突时，rules/ 优先级高于 modules/ 文件
- 模块未声明的能力视为禁止（默认拒绝）
- Agent 文档与模块文档不一致时，以 rules/ 为准

## 测试覆盖
- tests/test_rule_registry.py — rule_registry 三接口单测
- tests/test_module_contracts.py — 5 模块 available/self_check/version 单测

## 规则文件位置
- 全部规则置于 ~/.meituan-catpaw/4275287949/skills/fp_sentinel/
- 规则与代码分离：换规则不改代码，改代码不动规则
