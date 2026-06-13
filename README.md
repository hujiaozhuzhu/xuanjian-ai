# 玄鉴 XuanJian AI

**玄鉴** 是一个面向安全研究团队的开源代码审计误报排查工具。当前仓库的首个 MCP Skill 为 **fp-sentinel**，专注于对静态分析结果进行误报识别、上下文解释和审计辅助。

> 鉴伪存真，洞察代码风险。

## 项目定位

`xuanjian-ai` 不重新造一个完整扫描器，而是站在 Semgrep、SpotBugs、FindSecBugs、Bandit 等工具之后，帮助审计人员解决一个更痛的问题：

- 扫描结果太多
- 误报太多
- 缺少上下文解释
- 缺少可复用的误报经验
- AI Agent/MCP 无法直接消费结构化审计判断

## 当前重点

- **优先支持 Java 代码审计误报排查**
- Python 结果作为次优先级兼容
- MCP Skill 名称：`fp-sentinel`
- 开源、免费、本地部署优先

## 当前能力

### fp-sentinel MCP 工具

当前已实现：

1. `filter_false_positives`  
   对静态分析工具输出进行误报过滤。

2. `analyze_code_context`  
   分析代码上下文，识别测试代码、不可达代码、安全防护、输入校验等因素。

3. `train_false_positive_model`  
   使用历史标注数据训练轻量误报识别模型。

4. `get_filter_status`  
   查看过滤器状态与配置。

### 三层过滤架构

```text
L1 规则过滤       ->  路径、规则ID、代码模式、严重等级
L2 上下文分析     ->  测试代码、dead code、安全守卫、输入校验
L3 轻量模型评分   ->  基于历史标注的误报概率评估
```

## Java 优先路线

后续 Java 审计重点包括：

- SQL 注入：PreparedStatement、MyBatis `#{}` / `${}`、ORM 封装识别
- XSS：HTML escape、模板自动转义、JSON 响应场景识别
- SSRF：URL 来源、host allowlist、内网地址拦截识别
- 命令执行：常量命令、用户输入拼接、allowlist 判断
- 反序列化：ObjectInputFilter、可信数据源、测试工具代码识别
- 路径穿越：canonical path、normalize、base dir 限制识别

推荐 Java 扫描器组合：

```text
Semgrep + SpotBugs + FindSecBugs
```

当前代码已具备通用误报过滤 MCP 能力；Java 扫描器适配器和规则库会作为下一阶段重点补齐。

## 安装

```bash
git clone https://github.com/hujiaozhuzhu/xuanjian-ai.git
cd xuanjian-ai

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 启动 MCP Server

```bash
python main.py --transport stdio
```

## MCP 客户端配置示例

```json
{
  "mcpServers": {
    "fp-sentinel": {
      "command": "python",
      "args": ["/path/to/xuanjian-ai/main.py", "--transport", "stdio"],
      "env": {
        "CONFIG_PATH": "/path/to/xuanjian-ai/config.json"
      }
    }
  }
}
```

## 调用示例

```python
result = await mcp_client.call_tool(
    "filter_false_positives",
    scan_results=[
        {
            "tool": "semgrep",
            "rule_id": "java.lang.security.audit.sql-injection",
            "file": "src/main/java/com/example/UserDao.java",
            "line": 42,
            "code": "jdbcTemplate.query(sql, args)",
            "severity": "WARNING",
            "message": "Potential SQL injection"
        }
    ],
    source_code_dir="/path/to/project",
    filter_level="all",
    confidence_threshold=0.7
)
```

## 运行测试

```bash
pytest -q
```

当前基础测试已覆盖：

- L1 规则过滤
- L2 上下文分析
- L3 模型过滤
- 完整过滤流水线
- 统计信息计算
- 配置加载

## 仓库结构

```text
xuanjian-ai/
├── code_audit_fp/          # fp-sentinel 当前核心实现
│   ├── server.py           # MCP Server
│   ├── models.py           # 数据模型
│   └── filters/            # 误报过滤器
├── main.py                 # MCP 入口
├── config.json             # 默认配置
├── demo.py                 # 演示脚本
├── example.py              # 使用示例
├── test_example.py         # 测试
├── requirements.txt
└── README.md
```

## 路线图

### Phase 1：fp-sentinel 核心稳定化

- [x] MCP Server
- [x] 三层过滤器原型
- [x] 测试样例
- [x] 基础文档
- [ ] 包名重构为 `fp_sentinel`
- [ ] CLI 命令封装

### Phase 2：Java 审计优先支持

- [ ] Semgrep Java 输出标准化
- [ ] SpotBugs 输出解析
- [ ] FindSecBugs 输出解析
- [ ] Java 误报规则库
- [ ] Java 上下文识别器

### Phase 3：审计体验增强

- [ ] 历史误报基线
- [ ] Finding 指纹
- [ ] Markdown/HTML 报告导出
- [ ] 基础 Web 仪表盘

## License

MIT License
