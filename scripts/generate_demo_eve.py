"""生成演示用的 eve.json。

用途：在没有 pcap 的情况下跑通全流程、做演示与开发调试。
输出格式与 Suricata 真实 eve.json 一致，因此解析器与下游无需任何特殊处理。

设计要点：
    - **时间戳刻意分散**：模拟真实攻击在不同时刻发生，
      便于观察"按时间戳节奏重放"的效果（而不是一瞬间全部涌出）。
    - **严重度有梯度**：覆盖 critical/high/medium/low，
      让仪表盘的分布图有内容。
    - **包含重复告警**：同源同签名的多次触发，用于演示去重效果。
    - 用固定随机种子：演示可复现，不因每次生成不同而难以讲解。

用法：
    uv run python scripts/generate_demo_eve.py
    uv run python scripts/generate_demo_eve.py --count 80 --out data/logs/demo.json
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

# 攻击模板：(签名, 分类, Suricata priority, 目标端口, 协议)
# priority 越小越严重（Suricata 语义，见 parsers/eve_parser.py 的映射说明）
_ATTACK_TEMPLATES = [
    ("Possible SQL Injection (UNION SELECT)", "Web Application Attack", 1, 80, "TCP"),
    ("Possible SQL Injection (OR 1=1)", "Web Application Attack", 1, 80, "TCP"),
    ("Directory Traversal Attempt (/etc/passwd)", "Attempted Recon", 2, 80, "TCP"),
    ("Log4Shell JNDI Injection Attempt (CVE-2021-44228)", "Attempted Admin", 1, 8080, "TCP"),
    ("Possible XSS Attempt (script tag in URI)", "Web Application Attack", 2, 80, "TCP"),
    ("SSH Brute Force Attempt", "Attempted Login", 2, 22, "TCP"),
    ("Nmap OS Detection Probe", "Network Scan", 2, 0, "TCP"),
    ("TCP Port Scan Detected", "Network Scan", 3, 0, "TCP"),
    ("ICMP Ping Sweep Detected", "Network Scan", 3, 0, "ICMP"),
    ("Possible Reverse Shell (/bin/bash interactive)", "Suspicious Login", 1, 4444, "TCP"),
    ("Suspicious Large DNS TXT Query (possible tunneling)", "Bad Unknown", 3, 53, "UDP"),
]

# 模拟的攻击源（多为公网地址，HOME_NET 为内网）
_EXTERNAL_IPS = [
    "45.33.32.156",
    "198.51.100.23",
    "203.0.113.77",
    "192.0.2.44",
    "104.28.16.9",
    "185.220.101.5",
]
_INTERNAL_IPS = ["192.168.10.5", "192.168.10.12", "192.168.10.19"]


def build_events(count: int, seed: int = 42) -> list[dict]:
    """构造 count 条 eve alert 事件。

    时间上从"当前时间往前 count*3 秒"开始，逐条向后推进，
    使重放时能看到连续的时间线。
    """
    rng = random.Random(seed)
    base_time = datetime.now(UTC) - timedelta(seconds=count * 3)
    events: list[dict] = []

    for i in range(count):
        sig, category, priority, dst_port, proto = rng.choice(_ATTACK_TEMPLATES)
        src = rng.choice(_EXTERNAL_IPS)
        dst = rng.choice(_INTERNAL_IPS)

        # 每 5 条插入一次"同源同签名"的重复，用于演示去重。
        # 去重键是 (src_ip, signature)，因此必须两者都相同才会被合并。
        if i % 5 == 0 and events:
            previous = events[-1]
            clone = json.loads(json.dumps(previous))
            clone["timestamp"] = (base_time + timedelta(seconds=i * 3)).strftime(
                "%Y-%m-%dT%H:%M:%S.%f+0000"
            )
            clone["flow_id"] = rng.randint(1, 999999)
            events.append(clone)
            continue

        detected_at = base_time + timedelta(seconds=i * 3)
        events.append(
            {
                "timestamp": detected_at.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
                "flow_id": rng.randint(1, 999999),
                "in_iface": "eth0",
                "event_type": "alert",
                "src_ip": src,
                # 高位端口模拟攻击源（真实扫描/攻击通常来自随机源端口）
                "src_port": rng.randint(32768, 60999),
                "dest_ip": dst,
                "dest_port": dst_port,
                "proto": proto,
                "alert": {
                    "action": "allowed",
                    "gid": 1,
                    "signature_id": 1000000
                    + _ATTACK_TEMPLATES.index((sig, category, priority, dst_port, proto))
                    + 1,
                    "rev": 1,
                    "signature": sig,
                    "category": category,
                    "severity": priority,
                },
            }
        )

    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="生成演示用 eve.json")
    parser.add_argument("--count", type=int, default=40, help="生成多少条告警")
    parser.add_argument(
        "--out", type=Path, default=Path("data/logs/demo-eve.json"), help="输出路径"
    )
    args = parser.parse_args()

    events = build_events(args.count)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    # 简要统计，便于确认生成内容符合预期
    sigs: dict[str, int] = {}
    for e in events:
        sigs[e["alert"]["signature"]] = sigs.get(e["alert"]["signature"], 0) + 1

    print(f"已生成 {len(events)} 条告警 → {args.out}")
    print("签名分布：")
    for sig, n in sorted(sigs.items(), key=lambda kv: -kv[1]):
        print(f"  {n:>3}  {sig}")


if __name__ == "__main__":
    main()
