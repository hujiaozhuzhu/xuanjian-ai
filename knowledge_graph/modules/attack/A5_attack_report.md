# A5. 攻防报告生成器

> 版本：v2.2.0 | 文件：`fp_sentinel/reporting/attack_report.py`
> 聚合：A1~A4 全部子功能输出

## 设计要点

### 报告章节固定

```
① 攻击面总览          ASCII 路径图（路径/步骤/难度/概率）
② 已验证漏洞表        漏洞/位置/难度/概率/验证状态/验证方式
③ 攻击路径详情        每步 PoC 代码块 + reference_cve
④ 需人工确认          manual_required 列表
⑤ 修复优先级         按概率排序 + 预计工时（分钟转 XhYm）
⑥ 安全声明           PoC 仅用于防御验证 + 30 天清理提示
```

### 关键函数

- `_ascii_path_diagram(chain_report)`：ASCII 路径图（connector: 同文件↓ / 跨模块↓）
- `_verified_table(findings, verify_results, exploit_results)`：Markdown 表格
- `_path_details(chain_report, poc_map)`：每步 PoC 代码块
- `_manual_section(verify_results, findings)`：筛选项
- `_fix_priority(exploit_results, findings)`：按概率降序 + 工时估计

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

## 测试结果

```
tests/unit/test_attack_report.py — 用例 14
- TestReportContent（8）: 全章节存在、含概率、含 PoC 代码块、安全声明、诚实验证状态、ASCII 路径图、无外部地址、空 findings 兜底
- TestOutputWhitelist（4）: 合法路径放行、路径穿越拒绝、绝对路径逃逸拒绝、报告内含 reference_cve
结果：14 PASSED
```

## 变更说明

| 文件 | 变更 |
|------|------|
| `fp_sentinel/reporting/attack_report.py` | 新建，324 行，Markdown 报告 + S7 白名单 |
