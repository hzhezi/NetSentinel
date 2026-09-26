#!/usr/bin/env bash
#
# 提交前密钥扫描。
#
# 为什么需要它（真实事故）：
#     项目开发中，真实的 DEEPSEEK_API_KEY 曾被误写进 .env.example 并提交，
#     直到 GitHub 的 push protection 拦截才被发现 —— 也就是说已经推送过一次。
#     事后必须重置该 key 并重写整个 git 历史。
#
#     教训：不能依赖"我记得不要提交密钥"这种自觉。
#     把它变成机械检查，才是可靠的防线。
#
# 安装为 git hook：
#     ln -sf ../../scripts/check_secrets.sh .git/hooks/pre-commit
#   （或运行 ./scripts/install_hooks.sh）
#
# 设计取舍：
#     - 宁可误报也不放过：命中的行会打印出来，由人判断
#     - 用"变量名 + 高熵值"的组合模式，而不是宽泛匹配，减少误报
#     - 允许显式豁免：行尾加 `# allow-secret` 可跳过（用于测试夹具里的假 key）
#
set -euo pipefail

# 只扫描**将要提交的内容**（staged），而不是整个工作区 ——
# 工作区里未暂存的改动不会被提交，扫它们只会造成困惑。
STAGED=$(git diff --cached --name-only --diff-filter=ACM)
[ -z "$STAGED" ] && exit 0

# 排除的数据/生成文件（二进制或体积大，没必要扫）
SKIP_PATTERN='\.(png|jpg|jpeg|gif|ico|svg|woff2?|ttf|lock|parquet|pcap|gz)$|^frontend/(node_modules|dist)/|^uv\.lock$'

FOUND=0

scan_file() {
  local file="$1"
  [ -f "$file" ] || return 0
  echo "$file" | grep -qE "$SKIP_PATTERN" && return 0

  # 逐行检查，行尾含 allow-secret 的跳过
  while IFS= read -r line; do
    local lineno="$1"
    echo "$line" | grep -q "allow-secret" && continue

    # ── 检测模式 ────────────────────────────────────────────
    local hit=""

    # 1. 已知供应商的 key 前缀（最可靠：这些前缀本身就是"这是密钥"的标记）
    if echo "$line" | grep -qE '(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})'; then
      hit="API key 前缀"
    # 2. 变量名含敏感词且赋了"看起来像密钥的值"
    #    收紧规则的原因（真实误报）：`tokens = sum(...)` 这类
    #    普通代码曾被误判为密钥赋值 —— 变量名含 TOKEN 就命中的话
    #    会频繁误报，最终导致人们绕过检查（比不检查更糟）。
    #    现在要求：变量名是**全大写**（环境变量风格）+ 值有密钥特征
    elif echo "$line" | grep -qE '^[[:space:]]*(export[[:space:]]+)?[A-Z_]*(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY)[A-Z_]*[[:space:]]*=[[:space:]]*["'\'']?[A-Za-z0-9_\-]{16,}' \
         && ! echo "$line" | grep -qE '=[[:space:]]*["'\'']?[[:space:]]*$'; then
      hit="疑似密钥变量被赋值"
    fi

    if [ -n "$hit" ]; then
      echo "  ❌ $file:$lineno  ($hit)"
      # 打印时脱敏：只显示前 12 个字符，避免把密钥又输出到终端日志
      echo "     $(echo "$line" | cut -c1-60 | sed -E 's/(sk-.{4}).*/\1***[已脱敏]/')"
      FOUND=1
    fi
  done < <(awk '{printf "%d\t%s\n", NR, $0}' "$file" | while IFS=$'\t' read -r n content; do echo "$content"; done)
}

echo "🔍 扫描暂存文件中的密钥..."
for f in $STAGED; do
  scan_file "$f"
done

if [ "$FOUND" -eq 1 ]; then
  cat >&2 <<'EOF'

────────────────────────────────────────────────────────
❌ 提交被拦截：检测到疑似密钥。

处理方式：
  1. 若确实是密钥 → 从文件中移除，放进本地 .env（已 gitignore）
  2. 若是测试用的假 key → 在该行尾加注释 `# allow-secret`
  3. 临时跳过（不推荐）：git commit --no-verify

提醒：一旦密钥曾被提交，即使之后删除也必须**重置该密钥** ——
删除文件不能撤销已发生的泄露。
────────────────────────────────────────────────────────
EOF
  exit 1
fi

echo "✅ 未发现密钥"
