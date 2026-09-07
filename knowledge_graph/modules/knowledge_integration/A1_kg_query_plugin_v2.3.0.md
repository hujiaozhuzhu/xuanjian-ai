# A1. 知识图谱查询插件 (KG Query Plugin)

> 版本：v2.3.0 ｜ 文件：`fp_sentinel/knowledge_graph/features/query_plugin.py`
> 状态：完成 ｜ 依赖：store.KnowledgeStore

---

## 一、设计要点

### 1.1 匹配逻辑（三层）

扫描期间，每个 finding 按以下优先级召回历史知识：

1. **归档库召回**：从 `kg_fix_records` 拉取候选，按 category / cwe / severity / language / rule_id / 时间衰减加权评分，取 top-K。
2. **内置知识 fallback**：若归档库为空或读取失败（SQLite Down / 首次部署），退回到 _CATEGORY_KNOWLEDGE（静态字典，10 类高频漏洞 + 真实 CVE），保证零历史也能产出参考。
3. **去重 + 截断**：按 reference_cve + rule_id 去重保留相似度最高；最多返回 top-K（默认 5）。

### 1.2 评分函数 score_match

权重上限 1.0，下限 0.05：

+ 分类一致 ........ 0.50
+ CWE 一致 ......... 0.30
+ 严重度一致 ........ 0.10
+ 语言一致 .......... 0.05
+ 同 rule_id ........ 0.05
+ 时间衰减 .......... exp(-age_days/365) * 0.10

### 1.3 分类推理 _infer_category

从 rule_id 解析归一化分类键，覆盖：sqli / xss / cmd / path / secret / jwt / yaml / pickle / eval / ssrf。

---

## 二、关键 API

KnowledgeQueryPlugin(archive_fn, top_k=5, fallback=True, min_score=0.05)
  await match(rule_id, category, cwe, severity, language) -> List[KnowledgeMatch]
  await batch_match(findings) -> Dict[fid, List[KnowledgeMatch]]

KnowledgeMatch(match_id, rule_id, category, cwe, language, severity, file_path, line_start,
               fix_title, fix_diff, reference_cve, incident_note, archived_at, similarity)

工具：fallback(category) / all_fallback_categories()

---

## 三、测试结果

test_kg_query_plugin.py — 22 用例
TestInferCategory (6) / TestScoreMatch (6) / match() 主路径 (7) /
batch_match (3, 含 Pydantic Finding / 空列表 / 异常 fallback) / Fallback helper (3)
结果：22 PASSED

---

## 四、变更

query_plugin.py       新建（评分 + fallback 知识库）
test_kg_query_plugin.py  新建（22 用例）
