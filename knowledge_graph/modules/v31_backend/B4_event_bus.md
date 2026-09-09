# B4 -- 全局事件总线 (v3.1)

## 文件位置
- `fp_sentinel/events/__init__.py`
- `fp_sentinel/events/event_bus.py`
- `fp_sentinel/events/routes.py`

## 路由前缀
`/api/events`

## 9种事件类型

| 事件类型 | 值 | 必填字段 | 可选字段 |
|----------|------|----------|----------|
| SCAN_PROGRESS | scan_progress | scan_id, progress_pct | current_file, findings_count, stage |
| FINDING_NEW | finding_new | finding_id, rule_id | severity, file_path, category, message |
| SCAN_COMPLETED | scan_completed | scan_id, total_findings | duration_seconds, severity_counts, scanner_used |
| SYSTEM_STATUS | system_status | component, status | message, metrics |
| FED_ROUND | fed_round | session_id, round_number | accuracy, loss, participants, privacy_loss |
| FED_COMPLETED | fed_completed | session_id, total_rounds | final_accuracy, final_loss, compliance_passed |
| PR_STATUS | pr_status | pr_id, status | provider, title, url, merged_by |
| PIPELINE_GATE | pipeline_gate | build_id, gate_name, passed | reason, severity_threshold, metrics |
| WEBHOOK_EVENT | webhook_event | provider, event_type | action, source_branch, commit_hash |

## 核心类

### EventBus
- 单例模式: EventBus.get_instance()
- 订阅: subscribe(event_type, handler), subscribe_all(handler)
- 发布: publish(event), publish_simple(event_type, payload, severity, source)
- WebSocket: register_ws(ws), unregister_ws(ws)
- 历史: get_history(type, limit, severity), clear_history()
- 统计: get_stats()

### Event (dataclass)
- event_type: EventType
- payload: Dict[str, Any]
- severity: EventSeverity (DEBUG/INFO/WARNING/ERROR/CRITICAL)
- event_id: str (UUID)
- timestamp: str (ISO8601)
- source: str
- validate(): 按schema校验payload
- to_dict(): 序列化

## API端点
- GET  /api/events/types   -- 列出所有9种事件类型及schema
- GET  /api/events/history -- 查询事件历史（支持type/severity过滤）
- GET  /api/events/stats   -- 事件总线统计
- POST /api/events/publish -- 发布事件（自动过滤敏感字段）
- WS   /api/events/ws     -- WebSocket实时推送

## 便捷函数
- publish_event(event_type, payload, severity, source) -> bool
- subscribe(event_type, handler) -> None
- get_event_history(type, limit, severity) -> List[Dict]

## 安全红线
- 发布时自动过滤敏感字段 (token/password/secret等 → ***REDACTED***)
- 事件payload校验：必填字段缺失则拒绝发布
- WebSocket推送不含敏感数据
