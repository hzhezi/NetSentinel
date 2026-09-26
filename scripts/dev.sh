#!/usr/bin/env bash
#
# 一键开发环境启动脚本。
#
# 做四件事：
#   1. 起 PostgreSQL + Redis（Docker，幂等）
#   2. 应用数据库迁移
#   3. 若 data/logs 下没有 eve.json，生成演示数据
#   4. 起后端 API（前台），并提示如何在另一个终端起前端
#
# 为什么不让脚本同时起前后端：
#     两个前台进程混在一个脚本里，日志交织且 Ctrl-C 的行为难以预期。
#     分开终端更清晰，也便于单独重启其中一个。
#
# 用法：./scripts/dev.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> 1/4 启动 PostgreSQL 与 Redis"
docker compose up -d db redis
# 等健康检查通过 —— 直接执行迁移会撞上"数据库还没就绪"
printf "    等待服务健康"
for _ in $(seq 1 30); do
  if docker compose ps --format '{{.Health}}' | grep -q "healthy"; then
    echo " 就绪"
    break
  fi
  printf "."
  sleep 2
done

echo "==> 2/4 应用数据库迁移"
uv run alembic upgrade head

echo "==> 3/4 检查演示数据"
if ! ls data/logs/*.json >/dev/null 2>&1; then
  echo "    未发现 eve.json，生成演示数据"
  uv run python scripts/generate_demo_eve.py --out data/logs/demo-eve.json
else
  echo "    已存在 eve.json，跳过生成"
fi

echo "==> 4/4 启动后端 API（http://localhost:8000/docs）"
cat <<'TIP'

  另开一个终端启动前端：
      cd frontend && npm run dev        # http://localhost:5173

  演示路径：
      打开前端 → 数据重放 → 选择 data/logs/demo-eve.json → 开始重放
      然后回到「实时告警」页观察告警流式出现。

  若要用真实 pcap：
      docker compose --profile suricata run --rm suricata \
          suricata -r /data/raw/your.pcap -l /data/logs
      然后把 data/logs/eve.json 作为重放数据。

  提示：未配置 DEEPSEEK_API_KEY 时，检测与推送正常，但不会产生 AI 研判。

TIP
exec uv run uvicorn backend.main:app --reload --port 8000
