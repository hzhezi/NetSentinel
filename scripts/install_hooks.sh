#!/usr/bin/env bash
#
# 安装本地 git hooks。
#
# 为什么不放在仓库里的 .git/hooks：
#     .git/ 不纳入版本控制，hook 无法随之分发。
#     因此脚本放在 scripts/，由本脚本符号链接到 .git/hooks/。
#
# 用法：./scripts/install_hooks.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

HOOK_DIR=.git/hooks
mkdir -p "$HOOK_DIR"

# 用符号链接而非拷贝：脚本更新后 hook 自动生效，不必重新安装
ln -sf ../../scripts/check_secrets.sh "$HOOK_DIR/pre-commit"
chmod +x scripts/check_secrets.sh

echo "✅ 已安装 pre-commit hook: $HOOK_DIR/pre-commit"
echo "   提交时会自动扫描疑似密钥（见 scripts/check_secrets.sh）"
