# A4. 靶场验证器

> 版本：v2.2.0 | 文件：`fp_sentinel/attack/target_validator.py`
> 约束：Docker 不可用 → 一律 simulated 诚实标注

## 设计要点

### 三态诚实标注

| 状态 | 含义 | 触发条件 |
|------|------|---------|
| `verified_local` | Docker 靶场实际验证 | allow_docker=True + docker 可用 + 镜像存在 |
| `simulated` | 特征匹配模拟验证（默认） | 源码可读取 + sink 特征 + 输入特征同时命中 |
| `manual_required` | 需人工确认 | 源码不可读 或 特征匹配未命中 |

### 模拟验证（默认路径，本环境主用）

**特征匹配算法**：
1. `_rule_key(rule_id)`：把规则 ID 映射为特征键（14 种内置特征：sqli / cmd-injection / eval / path-traversal / ssrf / deser-pickle / deser-yaml / jwt / xss / ssti / xxe / weak-hash / secret）
2. 源码中查找 sink 特征子串（如 `query(`、`innerHTML`、`pickle.loads(`）
3. 同文件中查找输入特征子串（如 `request.args`、`window.location`、`URLSearchParams`）
4. 输入特征命中 → `simulated`；仅 sink 命中但无输入 → `simulated`（置信度说明较低）

**Docker 路径（可选，S4 模式 C）**：
- `allow_docker=True` + `shutil.which("docker")` 检测 daemon
- 未配置靶场镜像 → 返回 None 降级 simulated（诚实标注）
- 所有容器端口仅绑定 127.0.0.1

### 公开 API
- `verify(finding, project_root, allow_docker) -> VerifyResult`
- `verify_many(findings, ...) -> List[VerifyResult]`
- `docker_available() -> bool`

### 数据结构
```python
class VerifyStatus(str, Enum):
    VERIFIED_LOCAL = "verified_local"
    SIMULATED = "simulated"
    MANUAL_REQUIRED = "manual_required"

@dataclass
class VerifyResult:
    status: VerifyStatus
    method: str          # docker / signature-match / fallback
    evidence: str        # 判定依据
    detail: str          # 补充说明
```

### 安全红线
- **S1**：网络探测（若有）仅发往 127.0.0.1
- **S4**：无 Docker 绝不伪造成 verified_local
- **S7**：只读源文件，零写入

## 测试结果

```
tests/unit/test_attack_validator.py — 用例 7
- TestSimulatedVerification（2）: SQL 与 YAML 特征均命中 simulated
- TestManualRequired（2）: 源码不可读、无 sink 特征 → manual_required
- TestHonestStatus（3）: 无 Docker 时无 verified_local、allow_docker 无 Docker 降级、批量对齐
结果：7 PASSED
```

## 变更说明

| 文件 | 变更 |
|------|------|
| `fp_sentinel/attack/target_validator.py` | 新建，217 行，特征匹配 + 诚实三态标注 |
