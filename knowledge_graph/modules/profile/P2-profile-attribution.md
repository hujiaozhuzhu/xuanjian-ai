# P2 作者归因采集 — v2.2.0

> 版本：v2.2.0 | 子功能：作者归因采集（git blame 只读 + 降级）
> 代码位置：`fp_sentinel/profile/attribution.py`
> 测试文件：`tests/unit/test_profile_attribution.py`

---

## 一、概述

基于只读 git blame 的作者归因子系统。将 Finding 行号匹配到 git blame 最近行，
提取作者 email 后立即 SHA256 别名化，落盘时仅保存 16 位别名摘要，不存明文 email。

---

## 二、安全红线落地

| 红线 | 技术落实 |
|------|---------|
| S2 禁止修改用户代码 | git 命令白名单硬校验（log/blame/show），禁止一切写操作 |
| S6 隐私保护 | SHA256 别名化，email 不落盘 |
| S3 禁止删除文件 | 只读操作，不提供任何文件删除 API |

---

## 三、核心数据结构

### GitCommandViolation
尝试执行白名单外 git 命令时抛出的红线异常。

### LineBlame（内存态）
单行 blame 结果，含 email/name/commit_time。仅存在于内存中，不落盘。

### AttributionResult
归因结果汇总：
- records: List[AttributionRecord] 归因记录
- display_names: Dict[str, str] alias_hash -> 明文姓名（**仅内存态，落盘前加密**）
- total: 总 findings 数
- attributed: 成功归因数
- truncated: 是否达到上限被截断
- is_git: 是否为 git 仓库
- coverage: 覆盖率

---

## 四、核心函数签名

```python
def _run_git(args: List[str], cwd: str) -> subprocess.CompletedProcess
    """白名单硬校验 + --no-pager + 60s 超时"""

def is_git_repo(path: str) -> bool
    """只读探测（git log -1）"""

def blame_file(repo_path: str, rel_file: str) -> Dict[int, LineBlame]
    """git blame --porcelain 解析"""

def attribute_findings(project_path, findings, max_records=5000) -> AttributionResult
    """主归因入口：行号最近匹配 + SHA256 别名化 + 截断"""

async def attribute_and_store(db, project_path, findings, max_records=5000) -> AttributionResult
    """归因入库（developer_alias + scan_attribution）"""
```

---

## 五、归因策略

1. finding 行号向 blame 结果最近行匹配（二分 bisect）
2. 作者 email -> SHA256 alias_hash（确定性、不可逆）
3. 非 git 目录/行号无法归因 -> alias_hash="unknown"
4. 归因覆盖率 = attributed / total，报告中展示
5. 上限截断：达到 max_records 后设置 truncated=True，超出部分不归因也不生成记录

---

## 六、降级路径

| 场景 | 降级行为 |
|------|---------|
| 非 git 目录 | is_git=False，全部 alias=unknown，覆盖率 0% |
| blame 解析失败 | 返回空 dict，该文件 findings 归为 unknown |
| 达到上限 | truncated=True，超出部分跳过 |
| git 命令超时 60s | OSError 捕获，降级为 unknown |
| 文件不在 git 追踪 | blame 返回非零，降级为 unknown |

---

## 七、git 命令只读白名单

```python
GIT_READONLY_SUBCOMMANDS = {"log", "blame", "show"}
```

所有 git 调用经 `_run_git` 守卫，非白名单命令直接抛 `GitCommandViolation`。
`--no-pager` 强制注入。60 秒超时。 `check=False`（不因非零退出码抛异常，由调用方判断）。

---

## 八、性能缓存

同一项目内，按文件缓存 blame 结果（dict + sorted lines），避免同一文件反复调用 git blame。
每个项目最多缓存 N 条归因记录（默认 5000，可配置）。

---

## 九、测试结果

```
test_git_command_guard_rejects_write_operations PASSED
test_git_command_guard_allows_readonly PASSED
test_non_git_dir_degrades_to_unknown PASSED
test_blame_file_on_real_repo PASSED
test_attribute_findings_on_real_repo_no_plaintext PASSED
test_alias_consistency_for_same_author PASSED
test_max_records_cap PASSED
```

7/7 通过 (2026-09-07，其中最后一条在真实 git 仓库上验证)

## 十、验证要点

- 真实仓库（xuanjian-ai 项目自身）：blame 准确解析出行级归因，覆盖率 100%
- 记录落盘结构（model_dump）：不含 email、name、display_name 字段
- 序列化 blob 中不出现任何原始姓名（内存态姓名仅存于 display_names 字典，入库时加密）
