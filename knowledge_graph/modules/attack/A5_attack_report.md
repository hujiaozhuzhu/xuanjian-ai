# A5. 攻防报告生成器

> 版本：v2.2.1 | 文件：`fp_sentinel/reporting/attack_report.py`
> 聚合：A1~A4 全部子功能输出

## 设计要点

### 报告章节固定（10 章节）

```
① 攻击面总览          ASCII 路径图（路径/步骤/难度/概率）
② 攻防思路            利用场景、前置条件、攻击路径、影响范围（每类型独立分析）
③ 已验证漏洞表        漏洞/位置/难度/概率/验证状态/验证方式
④ 攻击路径详情        每步 PoC 代码块 + reference_cve
⑤ 本地验证PoC和EXP    仅 localhost 环境，标注仅用于防御验证，无真实攻击载荷、禁外网
⑥ 可能的问题          漏洞利用限制、现有防御绕过可能性、修复建议
⑦ 攻击链串联思路      漏洞组合形成完整攻击链路径、逐步影响范围、最终风险
⑧ 需人工确认          manual_required 列表
⑨ 修复优先级         按概率排序 + 预计工时（分钟转 XhYm）
⑩ 安全声明           PoC 仅用于防御验证 + 本地环境限制 + 30天清理提示 + 法律合规声明
```

### 关键函数

- `_ascii_path_diagram(chain_report)`：ASCII 路径图
- `_attack_thinking_section(findings, exploit_results, chain_report)`：攻防思路（v2.2.1 新增）
- `_verified_table(findings, verify_results, exploit_results)`：Markdown 表格
- `_path_details(chain_report, poc_map)`：每步 PoC 代码块
- `_poc_and_exp_section(poc_map, chain_report)`：本地验证 PoC/EXP（v2.2.1 新增）
- `_potential_issues_section(findings, verify_results, exploit_results)`：可能的问题（v2.2.1 新增）
- `_attack_chain_thinking_section(chain_report)`：攻击链串联思路（v2.2.1 新增）
- `_manual_section(verify_results, findings)`：筛选项
- `_fix_priority(exploit_results, findings)`：按概率降序 + 工时估计
- `_security_statement_section(now)`：增强版安全声明（v2.2.1 扩展）

### 攻防思路知识库

`_ATTACK_THINKING_DB`：12 种漏洞类型的内置知识库（sqli/xss/cmd/command/eval/path/traversal/ssrf/deser/jwt/xxe），
每条记录包含 4 个维度：利用场景、前置条件、攻击路径、影响范围。

### 利用限制知识库

`_LIMITATION_DB`：12 种漏洞类型的利用限制分析库，每条记录包含 3 个维度：
利用限制、现有防御绕过可能性、修复建议。

### S7 白名单校验

`resolve_output_path(output_dir, filename)`：
- 拒绝绝对路径文件名（`candidate.is_absolute() or candidate.anchor`）
- `resolve()` 后必须在 output_dir（或 cwd）之内
- 拒绝 `../` 路径穿越
- 越界抛 `ReportPathError`

`write_report(content, output_dir, filename) -> Path`：
- 白名单校验后写入，自动创建父目录

### 公开 API
- `generate_attack_report(project, findings, chain_report, ...) -> str`（Markdown 字符串）
- `write_report(content, output_dir, filename) -> Path`
- `resolve_output_path(output_dir, filename, allowed_roots) -> Path`

### 安全红线
- **S2**：报告为字符串/文件输出，不修改源文件
- **S7**：所有写盘走白名单校验
- **S1**：PoC 内所有目标固定为 127.0.0.1/localhost，不含任何外部地址
- **S4**：PoC 仅含教科书级 payload，无真实攻击载荷

## 测试结果

```
tests/unit/test_attack_report.py — 用例 24
- TestReportContent（12）: 全章节存在、含概率、含PoC代码块、安全声明强化、诚实验证状态、
  ASCII路径图、无外部地址、空findings兜底、攻防思路节、本地验证节、可能的问题节、攻击链串联节
- TestOutputWhitelist（4）: 合法路径放行、路径穿越拒绝、绝对路径逃逸拒绝、报告内含reference_cve
- TestSafetyRedLines（8）: 仅localhost目标、无外网请求、仅防御验证标注、无外部IP、30天清理声明、
  本地环境标注、无真实攻击载荷声明、法律合规声明
结果：24 PASSED
```

## 变更说明

| 文件 | 变更 |
|------|------|
| `fp_sentinel/reporting/attack_report.py` | 增强至 586 行，新增 10 章节报告结构（含攻防思路 / 本地验证PoC / 可能的问题 / 攻击链串联思路 / 增强安全声明），新增 _ATTACK_THINKING_DB 与 _LIMITATION_DB 知识库 |
