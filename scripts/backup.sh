#!/bin/bash
# ============================================================
# 玄鉴 迭代备份脚本
# 用法: ./scripts/backup.sh "本次迭代说明"
# 示例: ./scripts/backup.sh "v2.1: 修复JS靶场检出率"
#
# 做什么:
#   1. 将整个工作区(含未跟踪文件, 排除 .git/缓存)打包到 .backups/
#   2. 为当前 git HEAD 打 annotated tag: backup/<日期>-<序号>
#   3. 自动保留最近 20 份快照, 更早的清理
#
# 回滚方法:
#   - 文件级回滚: 解压 .backups/backup-*.tar.gz 覆盖即可
#   - 代码级回滚: git reset --hard backup/<tag>   (或 git checkout backup/<tag>)
# ============================================================

set -euo pipefail

cd "$(dirname "$0")/.."

BACKUP_DIR=".backups"
KEEP_N=20
TS=$(date +%Y%m%d-%H%M%S)
LABEL="${1:-iteration}"
SLUG=$(echo "$LABEL" | tr -cd 'a-zA-Z0-9_-' | head -c 40)

mkdir -p "$BACKUP_DIR"

# ---------- 1. 文件快照 (含未跟踪文件) ----------
SNAPSHOT="$BACKUP_DIR/backup-$TS-$SLUG.tar.gz"
echo "📦 [1/2] 创建文件快照: $SNAPSHOT"

tar czf "$SNAPSHOT" \
    --exclude='.git' \
    --exclude="$BACKUP_DIR" \
    --exclude='__pycache__' \
    --exclude='.pytest_cache' \
    --exclude='.coverage' \
    --exclude='*.egg-info' \
    --exclude='.venv' \
    --exclude='.fp_sentinel' \
    .

echo "   ✅ 快照完成 ($(du -h "$SNAPSHOT" | cut -f1))"

# ---------- 2. git tag (代码回滚点) ----------
TAG="backup/$TS"
if git rev-parse --git-dir > /dev/null 2>&1; then
    echo "🏷️  [2/2] 打 git tag: $TAG"
    git tag -a "$TAG" -m "backup: $LABEL"
    echo "   ✅ tag 完成"
else
    echo "   ⚠️ 非 git 仓库, 跳过 tag"
fi

# ---------- 3. 清理旧快照 ----------
echo "🧹 清理 $BACKUP_DIR 中超过 $KEEP_N 份的旧快照..."
ls -1t "$BACKUP_DIR"/backup-*.tar.gz 2>/dev/null | tail -n +$((KEEP_N + 1)) | while read -r old; do
    rm -f "$old"
    echo "   🗑️ 删除 $old"
done

echo ""
echo "=========================================="
echo "✅ 备份完成"
echo "   快照: $SNAPSHOT"
echo "   tag : $TAG"
echo ""
echo "   回滚: tar xzf $SNAPSHOT   # 文件级"
echo "         git reset --hard $TAG   # 代码级"
echo "=========================================="
