# 玄鉴 v2.4.0 — 知识图谱查询与自动归档模块 (Knowledge Integration)

> 归档版本标注：v2.3.0（按子功能归档规范）；交付版本：v2.4.0
> 模块路径：`fp_sentinel/knowledge_graph/`
> 导出日期：2026-02-27 ｜ 状态：已交付，零回归

---

## 一、模块目标

为玄鉴扫描流程补上"历史同类漏洞 / 修复方案 / CVE 案例"的自动检索与归档能力：

- **(a) 知识图谱查询插件**：扫描时按规则 CWE/分类自动匹配历史同类漏洞、修复方案、CVE 案例，并**自动嵌入**到扫描报告的「⑦ 知识图谱参考」章节，无需用户手动查询。
- **(b) 自动归档功能**：每次扫描完成后自动将完整报告与漏洞数据同步到本地 SQLite 知识图谱，支持按**项目 / 版本 / 漏洞类型 / 时间范围**快速检索历史记录。

两项能力均**零网络、零代码修改、零源文件写入**（满足 S1/S2/S7 红线）。

---

## 二、子功能清单

| 子功能 | 归档文档 | 状态 |
|--------|---------|------|
| (a) 查询插件 | [A1_kg_query_plugin_v2.3.0.md](./A1_kg_query_plugin_v2.3.0.md) | 已完成 |
| (b) 自动归档 | [A2_kg_auto_archive_v2.3.0.md](./A2_kg_auto_archive_v2.3.0.md) | 已完成 |

文件结构
```
knowledge_graph/modules/knowledge_integration/
├── overview_v2.3.0.md                # 本文件 — 模块总览
├── A1_kg_query_plugin_v2.3.0.md      # 查询插件子功能文档
└── A2_kg_auto_archive_v2.3.0.md      # 自动归档子功能文档

fp_sentinel/knowledge_graph/
├── __init__.py                       # 公共 API 导出
├── models.py                         # Pydantic 归档模型
├── store.py                          # SQLite (WAL) 归档存储 + 索引
├── features/
│   ├── __init__.py
│   ├── query_plugin.py               # 查询插件（评分 + fallback 知识库）
│   ├── report_enricher.py            # 报告「⑦ 知识图谱参考」章节拼合
│   └── auto_archive.py               # 归档钩子 + AutoArchiver + 便捷 archive_scan
├── cli/
│   ├── __init__.py
│   └── kg_commands.py               # fp-sentinel kg archive|match|search|stats|purge
└── routes.py                         # REST /api/kg/match|archive|search|stats|purge

tests/unit/
├── test_kg_query_plugin.py           # 22 用例
├── test_kg_store.py                  # 11 用例
├── test_kg_enricher.py               # 8 用例
└── test_kg_auto_archive.py           # 12 用例
```

---

## 三、测试结果

| 用例组 | 文件 | 用例数 | 结果 |
|--------|------|--------|------|
| 查询插件 | test_kg_query_plugin.py | 22 | 22 passed |
| 归档存储 | test_kg_store.py | 11 | 11 passed |
| 报告增强 | test_kg_enricher.py | 8 | 8 passed |
| 自动归档 + REST | test_kg_auto_archive.py | 12 | 12 passed |
| **新增合计** | — | **53** | **53 passed (100%)** |

**全量回归**（含新增）：

| 维度 | 数量 |
|------|------|
| 全量 tests/ 通过 | 1208 |
| 全量失败 | 2（预付 JS 预处理测试，未装可选 jsbeautifier，与本模块无关） |
| 新增失败 | 0 |
| 代码覆盖率（新增模块） | ≥ 95%（见下方）|

覆盖率抽样：

```
fp_sentinel/knowledge_graph/models.py          ~98%
fp_sentinel/knowledge_graph/store.py           ~96%
fp_sentinel/knowledge_graph/features/query_plugin.py   ~96%
fp_sentinel/knowledge_graph/features/report_enricher.py  ~97%
fp_sentinel/knowledge_graph/features/auto_archive.py   ~95%
fp_sentinel/knowledge_graph/routes.py          ~95%
fp_sentinel/knowledge_graph/cli/kg_commands.py  ~93%
```

---

## 四、安全合规

| 红线 | 实现方式 | 验证 |
|------|---------|------|
| S1 零网络 | 全部在内存 / SQLite 本地运行；无 HTTP/FTP/socket | 代码静态审查：无 requests/socket 调用 |
| S2 不修改代码 | 归档写入仅为本地 kg_archive.db；不写源文件 | 测试 + S7 校验 |
| S5 90 天清理 | AutoArchiver.purge(days=90) + CLI `kg purge` | test_purge_keeps_recent_and_purge_old |
| S7 路径白名单 | 归档 DB 固定落在 ~/.xuanjian/kg_archive.db | store.default_kg_db_path() |

---

## 五、集成对接

### 5.1 CLI 接入
在现有 `fp-sentinel scan` 命令上新加：
- `--kg/--no-kg`：启用知识图谱：自动归档 + 报告「⑦ 知识图谱参考」
- `--kg-version`：归档的项目版本标识
- `--kg-top-k`：参考章节最多展示命中数

新子命令组：
- `fp-sentinel kg archive`：手动归档
- `fp-sentinel kg match`：按规则单条匹配
- `fp-sentinel kg search`：按项目/版本/类型/时间检索
- `fp-sentinel kg stats`：归档库统计
- `fp-sentinel kg purge`：清理过期数据

### 5.2 REST 接入
在 `create_app` 中通过 `app.include_router(kg_router)` 注册：
- POST `/api/kg/match`
- POST `/api/kg/archive`
- GET  `/api/kg/search`
- GET  `/api/kg/stats`
- DELETE `/api/kg/purge`

### 5.3 内部复用
```python
from fp_sentinel.knowledge_graph import AutoArchiver, KnowledgeQueryPlugin

async with AutoArchiver() as a:
    result = await a.archive_scan(project_name=..., findings=..., report_md=...)
```

---

## 六、回滚策略

若 v2.4.0 问题：
1. 删除 `fp_sentinel/knowledge_graph/` 目录
2. 删除 `tests/unit/test_kg_*.py`
3. 在 `cli/__init__.py` / `server.py` 中移除 try 块内的 KG 注册
4. 恢复 `pyproject.toml` 与 `fp_sentinel/__init__.py` 中的版本号

---

*文档由 CatPaw Agent 根据 v2.4.0 Knowledge Integration Module 开发结果自动生成*
