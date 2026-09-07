# 玄鉴 v2.3.0 多语言适配模块总览

> 版本: v2.3.0 | 更新时间: 2026-09-07 | 开发: 多语言适配引擎开发工程师
> 状态: 已交付，953+ 单元测试通过，零回归

## 一、模块架构

```
fp_sentinel/
├── rules/
│   ├── go/              # [v2.3.0 新建] Go 规则库 (29条)
│   │   ├── __init__.py
│   │   └── rules.py
│   ├── js/              # [v2.3.0 增强] JS/TS 规则库 (51→78条)
│   │   ├── __init__.py
│   │   ├── rules.py
│   │   └── security_patterns.py
│   ├── python/          # 保持不变
│   └── java/            # 保持不变
├── scanners/
│   ├── go_scanner.py    # [v2.3.0 新建] Go 专用扫描器
│   ├── js_scanner.py    # 兼容 v2.3.0 规则增强
│   ├── manager.py       # [v2.3.0 更新] Go 自动识别 + 选择
│   └── semgrep_scanner.py # [v2.3.0 更新] Go Semgrep 规则集路由
└── models.py             # [v2.3.0 更新] 新增 GO_SCANNER 枚举
```

## 二、子功能索引

| 子功能 | 文档 | 规则数 | 测试覆盖率 |
|--------|------|--------|-----------|
| A: Go语言规则库 | [A-go-rules.md](./A-go-rules.md) | 29条 | ~98% |
| B: JS/TS规则增强 | [B-js-ts-enhanced.md](./B-js-ts-enhanced.md) | 新增27条 | ~96% |
| C: 扫描器管理器 | [C-scanner-manager.md](./C-scanner-manager.md) | - | ~97% |

## 三、关键设计原则

1. **零侵入**：仅新增文件+最小化修改已有文件，Java/Python 全流程不受影响
2. **统一架构**：GoScanner/JSScanner/PythonScanner 遵循各自前缀的并行实现策略
3. **编译安全**：所有规则正则经 re.compile 预检验，运行时坏正则仅跳过自身
4. **三层过滤兼容**：新增规则继承 L1(行内)/L2(窗口 guard)/L3(基线) 的默认过滤链
5. **auto 模式增强**：`language="auto"` 时通过构建文件(go.mod/package.json/tsconfig.json)自动识别语言

## 四、扫描器选择矩阵

| 语言 | Semgrep | FindSecBugs | Bandit | JS Scanner | Py Scanner | Go Scanner |
|------|---------|-------------|--------|------------|------------|------------|
| Java | ✅ | ✅ | - | - | - | - |
| Python | ✅ | - | ✅ | - | ✅ | - |
| JavaScript | ✅ | - | - | ✅ | - | - |
| TypeScript | ✅ | - | - | ✅ | - | - |
| **Go (v2.3.0)** | **✅** | - | - | - | - | **✅** |

## 五、语言检测优先级

1. **单文件模式**：直接匹配扩展名（.go/.js/.ts/.py/.java）
2. **项目模式**：构建文件嗅探（go.mod > package.json > tsconfig.json > requirements.txt > pom.xml）
3. **统计模式**：扩展名统计（.go file count vs .js/.py/.java）
4. **兜底**：Java（历史默认值）
