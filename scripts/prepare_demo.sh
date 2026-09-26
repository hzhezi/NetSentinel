#!/usr/bin/env bash
#
# 一键准备演示环境（不启动服务，只把数据准备好）。
#
# 做四件事：
#   1. 确认依赖服务在跑（不在则拉起）
#   2. 应用数据库迁移
#   3. 生成真实 pcap 并用 Suricata 处理（若 Docker 可用）
#   4. 清空旧数据，让演示从零开始
#
# 与 dev.sh 的区别：
#   dev.sh   起服务（日常开发用）
#   demo.sh  准备演示数据（答辩前用），不占终端
#
# 用法：./scripts/prepare_demo.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

echo "═══════════════════════════════════════════════"
echo "  准备演示环境"
echo "═══════════════════════════════════════════════"

echo
echo "==> 1/4 确认依赖服务"
docker compose up -d db redis
printf "    等待服务健康"
for _ in $(seq 1 30); do
  if [ "$(docker compose ps --format '{{.Health}}' | grep -c healthy)" -ge 2 ]; then
    echo " 就绪"
    break
  fi
  printf "."
  sleep 2
done

echo
echo "==> 2/4 应用数据库迁移"
uv run alembic upgrade head

echo
echo "==> 3/4 准备演示数据"
if [ ! -f data/logs/demo-eve.json ]; then
  echo "    生成合成演示数据（eve.json）"
  uv run python scripts/generate_demo_eve.py --count 40 --out data/logs/demo-eve.json

  # 若 Docker 可用，额外生成一份"真实 pcap 过 Suricata"的数据
  if docker info >/dev/null 2>&1; then
    echo "    生成真实 pcap 并用 Suricata 处理（更能体现'真在检测'）"
    uv run python scripts/generate_demo_pcap.py >/dev/null
    docker compose --profile suricata run --rm --entrypoint sh suricata \
      -c "mkdir -p /data/logs && suricata -r /data/raw/demo-traffic.pcap -l /data/logs" \
      >/dev/null 2>&1 \
      && cp data/logs/eve.json data/logs/pcap-eve.json \
      && echo "    真实 pcap 数据: data/logs/pcap-eve.json"
  else
    echo "    (Docker 未运行，跳过真实 pcap 处理)"
  fi
else
  echo "    演示数据已存在，跳过生成"
fi

echo
echo "==> 4/4 清空旧数据（让演示从零开始）"
docker compose exec -T db psql -U netsentinel -d netsentinel \
  -c "TRUNCATE alerts CASCADE; TRUNCATE triage_results CASCADE;" >/dev/null
echo "    已清空"

echo
echo "═══════════════════════════════════════════════"
echo "  ✅ 准备完成"
echo "═══════════════════════════════════════════════"
cat <<'TIP'

接下来（两个终端）：

  终端 A:  ./scripts/dev.sh
  终端 B:  cd frontend && npm run dev

然后打开前端，按 docs/demo-script.md 的流程演示。

可用的演示数据：
  data/logs/demo-eve.json     合成数据（40 条，含重复用于演示去重）
  data/logs/pcap-eve.json     真实 pcap 过 Suricata 的产出（若已生成）
TIP
