# 使用指南

## 快速开始

### 1. 安装依赖

```bash
cd code-audit-false-positive-filter
pip install -r requirements.txt
```

### 2. 运行示例

```bash
# 运行基本示例
python example.py

# 运行Hermes Agent集成示例
python hermes_integration.py
```

### 3. 运行测试

```bash
python -m pytest test_example.py -v
```

## 在Hermes Agent中使用

### 方法1：直接调用MCP工具

在Hermes Agent中，可以直接调用MCP工具：

```python
# 过滤误报
result = await mcp_client.call_tool(
    "filter_false_positives",
    scan_results=your_scan_results,
    source_code_dir="/path/to/project",
    filter_level="all",
    confidence_threshold=0.7
)

# 分析代码上下文
context = await mcp_client.call_tool(
    "analyze_code_context",
    file_path="app/database.py",
    line_number=42,
    context_lines=10,
    check_types=["dead_code", "security_guards", "input_validation"]
)

# 训练模型
training_result = await mcp_client.call_tool(
    "train_false_positive_model",
    training_data=your_training_data,
    model_type="random_forest",
    validation_split=0.2
)
```

### 方法2：使用集成类

```python
from hermes_integration import HermesCodeAuditIntegration

# 创建集成实例
integration = HermesCodeAuditIntegration()
await integration.initialize()

# 扫描并过滤
result = await integration.scan_and_filter(
    target_path="/path/to/project",
    scan_tools=["semgrep", "bandit"],
    filter_level="all"
)

# 分析特定问题
analysis = await integration.analyze_specific_issue(
    file_path="app/database.py",
    line_number=42
)
```

## 配置说明

### 配置文件位置

默认配置文件：`config.json`

### 环境变量

- `CONFIG_PATH`: 配置文件路径
- `MODEL_PATH`: ML模型路径
- `LOG_LEVEL`: 日志级别

### 配置示例

```json
{
  "rule_filter": {
    "enabled": true,
    "global_whitelist": [
      {
        "file_pattern": "*/test/*",
        "reason": "测试代码",
        "confidence": 0.9
      }
    ]
  },
  "context_filter": {
    "enabled": true,
    "false_positive_threshold": 0.5
  },
  "ml_filter": {
    "enabled": true,
    "confidence_threshold": 0.7
  }
}
```

## 扫描工具集成

### Semgrep集成

```python
import subprocess
import json

def run_semgrep(target_path, rules=None):
    """运行Semgrep扫描"""
    cmd = ["semgrep", "--json", "--config", "auto", target_path]
    if rules:
        cmd = ["semgrep", "--json"] + [f"--config={r}" for r in rules] + [target_path]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout)
```

### Bandit集成

```python
def run_bandit(target_path):
    """运行Bandit扫描"""
    cmd = ["bandit", "-r", "-f", "json", target_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout)
```

### Gosec集成

```python
def run_gosec(target_path):
    """运行Gosec扫描"""
    cmd = ["gosec", "-fmt=json", target_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout)
```

## 训练自定义模型

### 1. 准备训练数据

```python
training_data = [
    {
        "features": {
            "rule_confidence": 0.9,
            "severity_score": 1.0,
            "code_complexity": 0.6,
            "data_flow_length": 5,
            "has_security_guards": 0.0,
            "has_input_validation": 0.0,
            "is_test_code": 0.0,
            "file_depth": 3,
            "line_count": 1
        },
        "is_false_positive": False
    },
    # 更多训练数据...
]
```

### 2. 训练模型

```python
from code_audit_fp.filters import MLFilter

ml_filter = MLFilter(config)
result = await ml_filter.train_model(
    training_data=training_data,
    model_type="random_forest",
    validation_split=0.2
)

print(f"模型准确率: {result['accuracy']:.2f}")
print(f"模型路径: {result['model_path']}")
```

### 3. 使用训练好的模型

```json
{
  "ml_filter": {
    "enabled": true,
    "model_path": "models/false_positive_model_random_forest.pkl",
    "confidence_threshold": 0.7
  }
}
```

## 性能优化

### 1. 并发处理

```python
import asyncio

async def process_batch(scan_results, batch_size=10):
    """批量处理扫描结果"""
    results = []
    for i in range(0, len(scan_results), batch_size):
        batch = scan_results[i:i+batch_size]
        batch_results = await asyncio.gather(
            *[server._apply_filters(r, "all", 0.7) for r in batch]
        )
        results.extend(batch_results)
    return results
```

### 2. 缓存优化

```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def get_rule_confidence(rule_id):
    """缓存规则置信度"""
    # 实现规则置信度查询
    return 0.5
```

### 3. 内存管理

```python
import gc

def optimize_memory():
    """优化内存使用"""
    gc.collect()
    
    # 清理文件缓存
    server.context_filter._file_cache.clear()
    
    # 清理AST缓存
    server.context_filter._ast_cache.clear()
```

## 故障排除

### 常见问题

1. **模型加载失败**
   ```bash
   # 检查ONNX Runtime版本
   pip show onnxruntime
   
   # 重新安装
   pip install --force-reinstall onnxruntime
   ```

2. **内存不足**
   ```python
   # 减少并发数量
   import asyncio
   semaphore = asyncio.Semaphore(5)  # 限制并发数为5
   ```

3. **规则不生效**
   ```python
   # 检查规则配置
   import json
   with open("config.json") as f:
       config = json.load(f)
   print(json.dumps(config["rule_filter"], indent=2))
   ```

4. **文件读取失败**
   ```python
   # 检查文件权限
   import os
   print(os.access("path/to/file", os.R_OK))
   ```

### 调试模式

```python
import logging

# 启用详细日志
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("code_audit_fp").setLevel(logging.DEBUG)
```

## 最佳实践

### 1. 规则配置

- 从宽松的规则开始，逐步收紧
- 定期审查和更新规则
- 为不同项目维护不同的配置

### 2. 模型训练

- 收集足够多的训练数据（至少1000条）
- 定期重新训练模型
- 使用交叉验证评估模型性能

### 3. 性能优化

- 使用批量处理
- 启用缓存
- 监控内存使用

### 4. 集成建议

- 在CI/CD流水线中集成
- 定期运行扫描
- 建立误报反馈机制

## 扩展开发

### 添加新的扫描工具

1. 创建新的扫描器类
2. 实现扫描逻辑
3. 集成到服务器中

### 添加新的过滤规则

1. 在配置文件中定义规则
2. 实现规则匹配逻辑
3. 添加测试用例

### 添加新的上下文分析

1. 在上下文过滤器中添加新的检测方法
2. 实现检测逻辑
3. 更新特征提取

## 社区与支持

- **GitHub Issues**: 报告问题和功能请求
- **Pull Requests**: 贡献代码
- **文档**: 完善文档
- **测试**: 添加测试用例

## 许可证

MIT License