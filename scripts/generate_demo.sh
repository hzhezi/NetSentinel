#!/usr/bin/env bash
#
# 生成演示用的 eve.json（无需 pcap 即可跑通全流程）。
#
# 为什么需要它：
#     完整走通流程需要"用 Suricata 跑 pcap"，但 pcap 下载可能受阻、
#     Suricata 容器构建也要时间。生成的样例数据**格式与真实 eve.json 一致**，
#     因此全链路无需任何特殊处理即可演示与调试。
#
# 用法：
#   ./scripts/generate_demo.sh
#   ./scripts/generate_demo.sh --count 80 --out data/logs/demo.json
#
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run python scripts/generate_demo_eve.py "$@"
