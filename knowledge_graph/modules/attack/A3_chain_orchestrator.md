# A3. 攻击链编排器

> 版本：v2.2.0 | 文件：`fp_sentinel/attack/chain_orchestrator.py`
> 复用：`analysis/chain_discovery.VulnerabilityGraph`

## 设计要点

### 编排逻辑

**入口识别（Entry）**：
- 规则 ID 含：xss, ssrf, open-redirect, ssti, prompt-injection, idor, csrf, xxe, nosql
- 或文件路径含：routes/, controllers/, handlers/, api/, views/, pages/

**汇聚点识别（Sink）**：
- 规则 ID 含：sql-injection, command-injection, eval, path-traversal, deserialization, pickle, yaml, os.system

**图构建**：
1. 每个 finding → `GraphNode(id, VULNERABILITY, ...)`
2. 同文件数据流边：按行序相邻（窗口 4），入口 → 汇 方向
3. 同目录弱依赖边：跨文件，权重 0.3

**路径发现**：
- BFS `find_all_paths(entry.id, sink.id, max_depth=5)`
- 路径乘积：各步概率连乘 + 下限 5%（不取绝对 0）
- 去重：同起终点保留概率最高的一条，最多输出 20 条路径

### 输出模型（pydantic，兼容 models.py）

```python
class ChainStep(BaseModel):
    step_number: int
    vuln_type: str
    file_path: str
    line: int
    difficulty: str        # EASY/MEDIUM/HARD/VERY_HARD
    probability: float     # 该步 0-100

class ChainPath(BaseModel):
    id: str                # PATH-{uuid8}
    name: str              # vuln@file:line → vuln@file:line
    steps: List[ChainStep]
    severity: str          # 由平均概率推断
    probability: float     # 整链 0-100
    remediation: List[str]

class SinglePoint(BaseModel):  # 单点漏洞直接评分
    rule_id, file_path, line, severity, probability, reachability, difficulty

class AttackChainReport(BaseModel):
    project, generated_at, paths, single_points, total_findings, entry_count, sink_count
```

### 公开 API
- `orchestrate(findings, project, exploit_results) -> AttackChainReport`
- `node_id(finding) -> str`（公开，与 exploit_results 键值对齐）
- `to_legacy_chains(report) -> List[Dict]`（向后兼容）

### 安全红线
- **零网络**：纯图算法（BFS + 连乘），无 I/O
- **零修改**：输入 findings 只读

## 测试结果

```
tests/unit/test_attack_chain.py — 用例 6
- 多点发现生成路径、入口/汇聚分类、单点评分、空 findings 处理、路径按概率排序、步骤包含位置信息
结果：6 PASSED
```

## 变更说明

| 文件 | 变更 |
|------|------|
| `fp_sentinel/attack/chain_orchestrator.py` | 新建，372 行，图构建 + 路径编排 + 报告模型 |
