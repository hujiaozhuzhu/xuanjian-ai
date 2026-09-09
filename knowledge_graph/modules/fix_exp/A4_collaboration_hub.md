# A4. 协同整改中心模块

## 模块路径
`fp_sentinel/devops/collaboration_hub.py`

## 功能概述

支持漏洞工单自动分配、整改进度跟踪、复测自动触发的协同整改平台。

整合 4 个子引擎，覆盖漏洞从发现到关闭的完整生命周期。

## 子引擎

### 1. TicketAllocator (智能分配引擎)

#### 分配策略
- **ROUND_ROBIN**: 轮询，公平分配
- **LOAD_BALANCED**: 优先选负载最低的修复人员
- **EXPERTISE_MATCH**: 专长匹配 + 模块匹配 + 负载加权
- **MODULE_OWNER**: 优先对应模块负责人（回退到负载均衡）

#### 数据结构
- `AssigneeInfo`: user_id, name, specialties, module_scope, current_load, max_load
- `VulnTicket`: ticket_id, finding_id, severity, status, assignee_id, sla_deadline

### 2. ProgressTracker (进度跟踪器)

#### 状态机 (7 态)

```
PENDING -> ASSIGNED -> IN_PROGRESS -> FIXED -> VERIFIED (终态)
  |            |           |
  v            v           v
WONT_FIX    WONT_FIX    WONT_FIX  (终态)
                    v
                REOPENED -> ASSIGNED/IN_PROGRESS
```

- PENDING 允许: ASSIGNED, IN_PROGRESS, WONT_FIX
- ASSIGNED 允许: IN_PROGRESS, WONT_FIX
- IN_PROGRESS 允许: FIXED, WONT_FIX
- FIXED 允许: VERIFIED, REOPENED
- REOPENED 允许: ASSIGNED, IN_PROGRESS

#### SLA 策略 (SLAPolicy)
- CRITICAL: 4 小时响应
- HIGH: 24 小时
- MEDIUM: 72 小时
- LOW: 168 小时 (7 天)
- 升级阈值: 80% 时间消耗时预警

### 3. RetestTrigger (复测触发器)

#### 触发模式
- **manual**: 手动触发
- **scheduled**: 定时轮询（默认 30 分钟间隔）
- **event**: Git Push Hook / 修复提交事件驱动

#### 自动复测流程
1. 扫描所有 FIXED 状态的工单
2. 为每个没有待复测任务的工单创建复测任务
3. 执行扫描 -> 验证漏洞是否已消除

### 4. SLAMonitor (SLA 监控器)

#### 功能
- 检查所有活跃工单的 SLA 状态
- 生成预警事件（80% 时间消耗）
- 生成超时事件（超过 deadline）
- 格式化剩余时间显示

## CollaborationHub (一站式入口)

整合 4 个子工程的便捷 API:

- `create_and_assign_ticket(finding, strategy)` -> 从 finding 创建工单并分配
- `process_fix_and_retest(ticket_id, commit_hash)` -> 标记修复并触发复测
- `run_sla_check()` -> 运行 SLA 检查
- `get_dashboard()` -> 获取管理仪表板数据

## 安全红线

- S3: 工单操作通过 DevopsAdapter 隔离外部 API
- S6: 核心逻辑零网络依赖（复测触发为模拟）
- S2: 不修改用户源文件

## 测试覆盖

- 测试文件: tests/exp_fix/test_collaboration_hub.py
- 测试数量: ~85
- 覆盖率: 94%
- 覆盖要点: 四种分配策略/完整状态机转换/SLA预警超时/复测生命周期/一站式API
