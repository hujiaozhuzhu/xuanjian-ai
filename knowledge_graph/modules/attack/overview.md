# 玄鉴 v2.2.1 攻防模块（Agent-Attack）总览

> 版本：v2.2.1 | 更新日期：2026-09-08
> 模块路径：`fp_sentinel/attack/`、`fp_sentinel/reporting/`、`fp_sentinel/cli/`
> 安全红线：S1/S2/S4/S5/S7 全面覆盖

## 领地文件清单

| # | 子功能 | 文件 | 依赖可复用模块 |
|---|--------|------|---------------|
| A1 | PoC 模板库 | `fp_sentinel/attack/poc_templates.py` | 无（独立） |
| A2 | 可利用性评分 | `fp_sentinel/attack/exploitability.py` | 参照 `analysis/chain_scorer.py` |
| A3 | 攻击链编排 | `fp_sentinel/attack/chain_orchestrator.py` | `analysis/chain_discovery.py` |
| A4 | 靶场验证器 | `fp_sentinel/attack/target_validator.py` | shutil（docker 探测） |
| A5 | 攻防报告生成 | `fp_sentinel/reporting/attack_report.py` | A1~A4 聚合 |
| A6 | 合规增强 | `fp_sentinel/reporting/fix_advisor.py` + `compliance_report.py` | database/repositories |
| A7 | CLI 集成 | `fp_sentinel/cli/attack_commands.py` + `cli/__init__.py` | typer |

## 安全红线落地

| 红线 | 实现位置 | 验证 |
|------|---------|------|
| S1 仅 localhost 目标 | `poc_templates._assert_local()` | 6 参数化测试（external → UnsafeTargetError） |
| S2 禁止修改代码 | `fix_advisor` 仅输出 diff 字符串；`compliance_report` 只读 | test_diff_is_string_not_file |
| S4 禁止真实攻击 | `target_validator` 无 Docker → simulated，诚实标注 | test_no_docker_no_verified_local |
| S5 30 天清理 | `cli/attack_commands.purge_attack_records()` | test_attack_purge_runs |
| S7 路径白名单 | `reporting/attack_report.resolve_output_path()` | test_traversal_rejected / test_absolute_escape_rejected |

## 测试覆盖

- `tests/unit/test_attack_poc.py`：24 用例
- `tests/unit/test_attack_exploitability.py`：9 用例
- `tests/unit/test_attack_chain.py`：6 用例
- `tests/unit/test_attack_validator.py`：7 用例
- `tests/unit/test_attack_report.py`：35 用例（v2.2.1 从 14 扩充至 35）
- `tests/unit/test_attack_cli.py`：10 用例
- `tests/unit/test_fix_advisor.py`：16 用例
- `tests/unit/test_compliance_report.py`：9 用例
- **合计：119 用例，全绿**（v2.2.1 从 90 提升至 119）

## 变更记录

### v2.2.1（2026-09-08）

- `fp_sentinel/reporting/attack_report.py`：报告从 6 章节增强至 10 章节，新增：
  - ② 攻防思路：每漏洞类型独立分析利用场景、前置条件、攻击路径、影响范围
  - ⑤ 本地验证PoC和EXP：每个 PoC 标注目标为 localhost、仅用于防御验证、包含防御说明
  - ⑥ 可能的问题：每个漏洞列出利用限制、现有防御绕过可能性、修复建议
  - ⑦ 攻击链串联思路：展示攻击链路径、逐步影响范围、最终风险与断链建议
  - ⑩ 安全声明：强化为 5 条（防御验证 / 本地环境 / 无真实载荷 / 30天清理 / 法律合规）
- `tests/unit/test_attack_report.py`：从 14 用例扩充至 35 用例，新增攻防思路/本地验证/可能问题/攻击链串联/安全红线/边缘分支覆盖等断言
- `knowledge_graph/modules/attack/A5_attack_report.md`：更新文档，新增知识库说明与测试结果

### v2.2.0（初始版本）

- 完整建设 A1~A7 全部子功能模块，90 用例全绿
