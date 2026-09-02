#!/bin/bash
# 玄鉴本地质量门禁
# 用法: ./scripts/quality-gate.sh

set -e

echo "=========================================="
echo "🔒 玄鉴 v2.0.1 质量门禁"
echo "=========================================="

FAILED=0

# 1. 代码风格检查
echo ""
echo "📝 [1/5] 代码风格检查 (ruff)..."
if command -v ruff &> /dev/null; then
    ruff check fp_sentinel/ --select E,F,W --ignore E501 || FAILED=1
    echo "  ✅ ruff 检查完成"
else
    echo "  ⚠️ ruff 未安装，跳过"
fi

# 2. 类型检查
echo ""
echo "🔍 [2/5] 类型检查 (mypy)..."
if command -v mypy &> /dev/null; then
    mypy fp_sentinel/ --ignore-missing-imports --no-strict-optional || FAILED=1
    echo "  ✅ mypy 检查完成"
else
    echo "  ⚠️ mypy 未安装，跳过"
fi

# 3. 单元测试
echo ""
echo "🧪 [3/5] 单元测试 (pytest)..."
if command -v pytest &> /dev/null; then
    pytest tests/unit/ -v --tb=short -q || FAILED=1
    echo "  ✅ 单元测试完成"
else
    echo "  ❌ pytest 未安装!"
    FAILED=1
fi

# 4. 安全扫描
echo ""
echo "🛡️ [4/5] 安全扫描 (bandit)..."
if command -v bandit &> /dev/null; then
    bandit -r fp_sentinel/ -ll -ii || FAILED=1
    echo "  ✅ bandit 扫描完成"
else
    echo "  ⚠️ bandit 未安装，跳过"
fi

# 5. 测试覆盖率
echo ""
echo "📊 [5/5] 测试覆盖率..."
if command -v pytest &> /dev/null; then
    pytest tests/unit/ --cov=fp_sentinel --cov-report=term-missing -q || FAILED=1
    echo "  ✅ 覆盖率报告完成"
else
    echo "  ⚠️ 跳过"
fi

echo ""
echo "=========================================="
if [ $FAILED -eq 0 ]; then
    echo "✅ 质量门禁: 全部通过!"
    exit 0
else
    echo "❌ 质量门禁: 存在失败项!"
    exit 1
fi
