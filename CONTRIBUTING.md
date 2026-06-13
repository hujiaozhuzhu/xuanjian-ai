# Contributing to XuanJian AI

欢迎参与玄鉴 `xuanjian-ai`。

当前重点方向：

1. Java 代码审计误报排查
2. Semgrep / SpotBugs / FindSecBugs 结果标准化
3. Java 安全规则误报样例沉淀
4. MCP Skill 体验优化

## 本地开发

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

## 贡献规则

- 新增规则请附带误报/真报样例
- 新增过滤逻辑请补测试
- 不提交真实业务代码、真实密钥、客户扫描结果
- 误报判断必须尽量给出可解释原因

## Commit 风格

推荐：

```text
feat: add spotbugs parser
fix: handle java preparedstatement false positive
docs: update mcp usage
```
