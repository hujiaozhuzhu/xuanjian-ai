# A2. 自动归档功能 (KG Auto Archive)

> 版本：v2.3.0 ｜ 文件：
>   `fp_sentinel/knowledge_graph/features/auto_archive.py`
>   `fp_sentinel/knowledge_graph/store.py`
>   `fp_sentinel/knowledge_graph/models.py`
>   `fp_sentinel/knowledge_graph/cli/kg_commands.py`
>   `fp_sentinel/knowledge_graph/routes.py`
> 状态：完成 ｜ 依赖：features.query_plugin + store

---

## 一、设计要点

### 1.1 数据模型

- FixSnapshot：一次扫描对应的归档快照；按「项目 / 版本 / 漏洞类型 / 时间范围」建立索引。
- FixRecord：单条 finding 归档记录，包含其匹配的 KnowledgeMatch 列表。
- ArchiveQuery：检索条件模型（支持 snapshot_id / project / version / category / cwe / language / 时间范围）。

### 1.2 SQLite 存储 (store.py - KnowledgeStore)

- 独立数据库 ~/.xuanjian/kg_archive.db，不干扰主 data.db。
- WAL 模式 + 无外键依赖；对 :memory: 友好（测试用）。
- Schema: kg_snapshots + kg_fix_records + 12 个复合索引（project / version / rule_id / cwe / category / severity / archived_at）。

### 1.3 自动归档钩子 (auto_archive.py)

AutoArchiver.archive_scan(...) / archive_scan(...) 便捷函数：
1. KnowledgeQueryPlugin 批量匹配每条 finding；
2. fix_advisor 兜底修复建议；
3. 聚合 severity/category 分布；
4. 写入 kg_snapshots + kg_fix_records。

### 1.4 CLI 与 REST 检索

CLI (cli/kg_commands.py):
- fp-sentinel kg archive | match | search | stats | purge

REST (routes.py):
- POST /api/kg/match
- POST /api/kg/archive
- GET  /api/kg/search
- GET  /api/kg/stats
- DELETE /api/kg/purge

---

## 二、关键 API

AutoArchiver(db_path=None, top_k=5, fallback_knowledge=True, min_score=0.05)
    async with AutoArchiver() as a:
        result = await a.archive_scan(project_name=, project_path=, findings=, report_md=, ...)

archive_scan(...)  # 便捷函数

CLI: fp-sentinel kg {archive|match|search|stats|purge}

REST: /api/kg/{match|archive|search|stats|purge}

scan 命令追加：--kg/--no-kg (启用归档 + 报告「⑦ 知识图谱参考」)
                --kg-version / --kg-top-k

---

## 三、测试结果

test_kg_store.py (11 用例):
  写入 / 检索 (project/version/rule-prefix/severity/cwe) / 计数 / 统计 / 分页 / purge
test_kg_enricher.py (8 用例):
  章节生成 / 去重 / metadata 注入 / 空输入兜底 / 统计摘要
test_kg_auto_archive.py (12 用例):
  archive_scan 快照+记录 / 保留外部 store / 空 findings / attach_kg_metadata / REST 路由冒烟
结果：31 PASSED (store + enricher + auto_archive)

---

## 四、变更

fp_sentinel/knowledge_graph/{__init__.py,models.py,store.py}
fp_sentinel/knowledge_graph/features/query_plugin.py
fp_sentinel/knowledge_graph/features/report_enricher.py
fp_sentinel/knowledge_graph/features/auto_archive.py
fp_sentinel/knowledge_graph/cli/__init__.py
fp_sentinel/knowledge_graph/cli/kg_commands.py
fp_sentinel/knowledge_graph/routes.py
fp_sentinel/cli/__init__.py            注册 kg 子命令 + scan --kg
fp_sentinel/server.py                   注册 /api/kg/*
fp_sentinel/__init__.py                __version__ → 2.5.1
pyproject.toml                         version → 2.5.1
tests/unit/test_kg_*.py               4 文件 53 用例
tests/unit/test_attack_cli.py         版本断言同步至 2.5.1
