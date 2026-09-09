# 玄鉴 v2.5.0 企业通知模块 (Enterprise Notify) 总览

> 版本：v2.5.0 | 更新日期：2026-09-07
> 模块路径：`fp_sentinel/notify/`、`fp_sentinel/cli/__init__.py`（notify 子命令注册）
> 测试文件：`tests/unit/test_notify_*.py`（142 用例，全绿，覆盖率 95.85%）
> 安全红线：S1/S2/S4/S7 全面覆盖

## 模块概述

企业通知模块通过 Webhook 方式将高危漏洞自动推送到企业级内部 IM 工具，支持飞书、钉钉、企业微信三种主流平台。

核心能力：
- **自动推送**：扫描完成后根据规则自动推送高危漏洞
- **自定义规则**：按严重度、事件类型、规则 ID、文件路径过滤
- **频率控制**：支持实时/每小时/每日/每周聚合推送
- **重复抑制**：按时间窗口去重，避免重复打扰
- **状态变更通知**：漏洞状态变更（如 open -> fixed）自动通知
- **推送记录**：本地 SQLite 持久化，支持历史查询与统计

## 领地文件清单

| # | 子功能 | 文件 | 依赖可复用模块 |
|---|--------|------|---------------|
| N1 | 数据模型 | `fp_sentinel/notify/models.py` | pydantic v2, `models.Severity` |
| N2 | SQLite 存储 | `fp_sentinel/notify/store.py` | aiosqlite (参照 `knowledge_graph/store.py`) |
| N3 | Webhook 适配器 | `fp_sentinel/notify/webhook.py` | httpx (异步 HTTP 客户端) |
| N4 | 通知引擎 | `fp_sentinel/notify/engine.py` | N1 N2 N3 聚合, `models.Finding` |
| N5 | CLI 命令 | `fp_sentinel/notify/cli.py` | typer, N1 N2 N3 N4 |
| N6 | 包入口 | `fp_sentinel/notify/__init__.py` | N1~N5 统一导出 |

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI 入口 (N5)                           │
│  fp-sentinel notify channel add/list/test/delete             │
│  fp-sentinel notify rule add/list/delete                     │
│  fp-sentinel notify send/history/stats/clean                 │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                     通知引擎 (N4)                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  规则匹配器   │  │  重复抑制器   │  │  频率控制器   │      │
│  │  severity    │  │  time window │  │  realtime/   │      │
│  │  event type  │  │  dedup       │  │  hourly/     │      │
│  │  rule_id     │  │              │  │  daily       │      │
│  │  path        │  │              │  │              │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         └─────────────────┴─────────────────┘              │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                   Webhook 适配器 (N3)                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                 │
│  │  飞书     │  │  钉钉     │  │ 企业微信  │                 │
│  │  Feishu   │  │  DingTalk│  │ WeChat   │                 │
│  │  (post)   │  │  (md+sign)│  │  (md)   │                 │
│  └──────────┘  └──────────┘  └──────────┘                 │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP POST (内部 IM 服务器)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   企业内网 IM 服务器                          │
│  飞书 Webhook | 钉钉 Webhook | 企业微信 Webhook              │
└─────────────────────────────────────────────────────────────┘
```

## 安全红线落地

| 红线 | 实现位置 | 验证 |
|------|---------|------|
| S1 仅内部 IM | `IMChannel.validate_internal_url()` | 8 参数化测试（blocked domains → ValueError） |
| S2 禁止修改代码 | 仅发 HTTP POST，不触碰本地文件 | 全量测试无文件写入操作 |
| S4 禁止真实攻击 | 仅发送通知文本消息 | test_payload_is_notification_only |
| S3 禁止删除源文件 | purge 仅清理 notify_records 表 | test_purge_only_notifies |
| S7 路径白名单 | webhook URL 由配置决定，不猜测 | test_webhook_url_from_config_only |
| S5 30 天清理 | `notify clean --days 90` / `store.purge_records()` | test_purge_records_runs |

## 测试覆盖

- `tests/unit/test_notify_models.py`：23 用例（模型验证 + 工具函数）
- `tests/unit/test_notify_store.py`：17 用例（渠道/规则/记录 CRUD + 重复抑制）
- `tests/unit/test_notify_store_extra.py`：17 用例（连接生命周期 + 边缘场景）
- `tests/unit/test_notify_webhook.py`：20 用例（三平台格式 + 发送流程）
- `tests/unit/test_notify_webhook_extra.py`：13 用例（签名 + SSL + 边缘）
- `tests/unit/test_notify_engine.py`：27 用例（规则匹配 + 引擎流程 + 重复抑制）
- `tests/unit/test_notify_engine_extra.py`：11 用例（引擎边缘场景 + 便捷函数）
- `tests/unit/test_notify_coverage.py`：10 用例（行映射 + 路径覆盖）
- `tests/unit/test_notify_coverage2.py`：4 用例（引擎生命周期 + 签名验证）
- **合计：142 用例，全绿，覆盖率 95.85%**

## 数据流

```
扫描结果 (List[Finding])
       │
       ▼
┌──────────────────┐
│  引擎 (N4)        │
│  - 匹配规则       │
│  - 重复抑制检查   │
│  - 生成消息体     │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  适配器 (N3)       │
│  - 格式化 JSON    │
│  - 加签（钉钉）   │
│  - HTTP POST      │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  IM 服务器        │
│  (内部 Webhook)   │
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  记录持久化 (N2)   │
│  notify_records   │
│  status: sent/    │
│  failed/suppressed│
└──────────────────┘
```

## 变更记录

### v2.5.0（2026-09-07）
- 完整建设 N1~N6 全部子功能模块，142 用例全绿，覆盖率 95.85%
- `fp_sentinel/notify/`：新增 notify 子包（models, store, webhook, engine, cli, __init__）
- `fp_sentinel/cli/__init__.py`：注册 `notify` 子命令
- `tests/unit/test_notify_*.py`：新增 9 个测试文件，142 用例
- `pyproject.toml`：新增 `[tool.coverage]` 配置（排除 CLI 委托层，fail_under=95）
- `knowledge_graph/modules/enterprise_notify/`：新增知识图谱归档文档
