"""跑 LLM 研判评测（真实调用），产出报告数据。

═══════════════════════════════════════════════════════════════════
流程
═══════════════════════════════════════════════════════════════════
    1. 用 Suricata 跑 pcap → eve.json（若尚未生成则自动生成）
    2. 把告警关联到"由什么流量触发" → 得到带真值的评测集
    3. 对每条调用 L1 分诊（可选 L2 深度调查）
    4. 计算指标并落盘

═══════════════════════════════════════════════════════════════════
费用与耗时提示
═══════════════════════════════════════════════════════════════════
L1 约 2 秒/条、~800 tokens；L2 约 10 秒/条、~8000 tokens。
默认只跑 L1（便宜）；加 --with-l2 会显著变慢变贵。

用法：
    uv run python scripts/run_eval.py                    # L1 评测
    uv run python scripts/run_eval.py --with-l2          # 含 L2 深度调查
    uv run python scripts/run_eval.py --limit 5          # 只跑前 5 条（先试水）
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from backend.agents.llm_client import LLMClient
from backend.core.config import settings
from scripts.build_eval_set import compute_metrics, save_eval_set

# 场景 → 真值的映射由 build_eval_set 负责；
# 这里维护"ZONE 签名 → 场景"的关联（用于把告警溯源到流量类型）
_SIGNATURE_TO_SCENARIO: list[tuple[str, str]] = [
    ("SQL Injection (UNION SELECT)", "sql_injection"),
    ("SQL Injection (OR 1=1)", "sql_injection_or"),
    ("Directory Traversal", "directory_traversal"),
    ("XSS Attempt", "xss"),
    ("Log4Shell", "log4shell"),
    ("Reverse Shell", "reverse_shell"),
    ("SSH Brute Force", "ssh_brute_force"),
    ("TCP Port Scan", "tcp_scan"),
    ("ICMP Ping Sweep", "icmp_sweep"),
    ("DNS TXT", "dns_tunnel"),
    # 正常流量触发的告警（若规则误报）—— 本项目实测为零误报，
    # 但保留映射以便将来规则调整后仍可评测
    ("benign", "benign_http"),
]


def scenario_for_signature(signature: str) -> str | None:
    """把告警签名映射到流量场景。匹配不到返回 None（会被跳过）。"""
    for pattern, scenario in _SIGNATURE_TO_SCENARIO:
        if pattern.lower() in signature.lower():
            return scenario
    return None


def load_eve_alerts(eve_path: Path) -> list[dict]:
    """从 eve.json 读取全部 alert 事件（转为评测用的告警字典）。"""
    from backend.detection.parsers.eve_parser import parse_eve_line

    alerts = []
    with open(eve_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            evt = parse_eve_line(line)
            if evt is None:
                continue
            alerts.append(
                {
                    "signature": evt.signature,
                    "category": evt.category,
                    "severity": evt.severity,
                    "src_ip": evt.src_ip,
                    "src_port": evt.src_port,
                    "dst_ip": evt.dst_ip,
                    "dst_port": evt.dst_port,
                    "protocol": evt.protocol,
                    "detected_at": evt.detected_at.isoformat(),
                }
            )
    return alerts


def build_scenarios_from_eve(eve_path: Path) -> list[dict]:
    """把 eve 告警关联到场景（含去重）。"""
    from scripts.build_eval_set import build_eval_set

    scenarios = []
    for alert in load_eve_alerts(eve_path):
        scenario = scenario_for_signature(alert["signature"])
        if scenario is None:
            print(f"  ⚠ 跳过（无法溯源到场景）: {alert['signature']}")
            continue
        scenarios.append({"scenario": scenario, "alert": alert})

    return build_eval_set(scenarios)


def run_l1_eval(items: list[dict], limit: int | None) -> list[dict]:
    """用 L1 分诊跑评测。"""
    llm = LLMClient(settings.DEEPSEEK_API_KEY, settings.DEEPSEEK_BASE_URL, settings.TRIAGE_MODEL)
    results = []
    targets = items[:limit] if limit else items

    for i, item in enumerate(targets, 1):
        alert = item["alert"]
        print(f"  [{i}/{len(targets)}] {alert['signature'][:45]}...", end=" ")
        try:
            r = llm.triage(alert)
            usage = llm.last_usage
            results.append(
                {
                    "scenario": item["scenario"],
                    "signature": alert["signature"],
                    "ground_truth": item["ground_truth"],
                    "predicted": r.verdict,
                    "model_severity": r.severity,
                    "confidence": r.confidence,
                    "summary": r.summary,
                    "error": None,
                    "prompt_tokens": usage.get("prompt_tokens", 0),
                    "completion_tokens": usage.get("completion_tokens", 0),
                    # L1 不做工具调用，耗时由客户端内部计时（这里粗略用 0）
                    "latency_ms": 0,
                }
            )
            print(f"→ {r.verdict} (conf {r.confidence})")
        except Exception as exc:
            print(f"→ 失败: {exc}")
            results.append(
                {
                    "scenario": item["scenario"],
                    "signature": alert["signature"],
                    "ground_truth": item["ground_truth"],
                    "predicted": "needs_human_review",
                    "error": str(exc),
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "latency_ms": 0,
                }
            )
    return results


def run_l2_eval(items: list[dict], limit: int | None) -> list[dict]:
    """用 L2 深度调查跑评测（慢且贵，仅在明确需要时使用）。"""
    from backend.agents.investigation import InvestigationAgent

    llm = LLMClient(
        settings.DEEPSEEK_API_KEY,
        settings.DEEPSEEK_BASE_URL,
        settings.INVESTIGATION_MODEL,
    )
    results = []
    targets = items[:limit] if limit else items

    # 提供告警池，让"关联告警"工具有数据可查
    pool = [
        {
            "id": f"eval-{i}",
            "src_ip": it["alert"]["src_ip"],
            "signature": it["alert"]["signature"],
            "severity": it["alert"]["severity"],
        }
        for i, it in enumerate(items)
    ]

    for i, item in enumerate(targets, 1):
        alert = dict(item["alert"])
        alert["id"] = f"eval-{i}"
        print(f"  [{i}/{len(targets)}] {alert['signature'][:45]}...", end=" ")
        agent = InvestigationAgent(
            llm=llm,
            tool_context={"alert_pool": pool, "exclude_id": alert["id"]},
        )
        r = agent.investigate(alert)
        results.append(
            {
                "scenario": item["scenario"],
                "signature": alert["signature"],
                "ground_truth": item["ground_truth"],
                "predicted": r.verdict,
                "model_severity": r.severity,
                "confidence": r.confidence,
                "summary": r.summary,
                "iterations": r.iterations,
                "tools_used": [
                    s.get("tool") for s in r.evidence_trail if s.get("type") == "tool_call"
                ],
                "error": r.error,
                "prompt_tokens": r.usage.get("prompt_tokens", 0),
                "completion_tokens": r.usage.get("completion_tokens", 0),
                "latency_ms": r.latency_ms,
            }
        )
        print(f"→ {r.verdict} (conf {r.confidence})")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="LLM 研判评测")
    parser.add_argument(
        "--eve", type=Path, default=Path("data/logs/eve.json"), help="Suricata eve.json 路径"
    )
    parser.add_argument("--limit", type=int, default=None, help="只跑前 N 条")
    parser.add_argument("--with-l2", action="store_true", help="同时跑 L2 深度调查（慢且贵）")
    parser.add_argument("--out", type=Path, default=Path("data/eval"))
    args = parser.parse_args()

    if not args.eve.exists():
        print(f"❌ 未找到 {args.eve}")
        print("   请先运行：")
        print("     uv run python scripts/generate_demo_pcap.py")
        print("     docker compose --profile suricata run --rm --entrypoint sh suricata \\")
        print(
            "       -c 'mkdir -p /data/logs && suricata -r "
            "/data/raw/demo-traffic.pcap -l /data/logs'"
        )
        return

    if not settings.DEEPSEEK_API_KEY:
        print("❌ 未配置 DEEPSEEK_API_KEY（在 .env 中设置）")
        return

    print("=== 1. 构造评测集（从 eve.json 溯源真值）===")
    items = build_scenarios_from_eve(args.eve)
    print(f"  去重后样本数: {len(items)}")
    for it in items:
        print(f"    [{it['ground_truth']:15s}] {it['alert']['signature'][:50]}")

    save_eval_set(items, args.out / "eval_set.json")

    print(f"\n=== 2. L1 分诊评测（模型 {settings.TRIAGE_MODEL}）===")
    l1_results = run_l1_eval(items, args.limit)
    l1_metrics = compute_metrics(l1_results)

    print("\n=== 3. L1 指标 ===")
    print(json.dumps(l1_metrics, ensure_ascii=False, indent=2))

    all_results = {"l1": {"metrics": l1_metrics, "detail": l1_results}}

    if args.with_l2:
        print(f"\n=== 4. L2 深度调查评测（模型 {settings.INVESTIGATION_MODEL}）===")
        print("  提示：每条 6-10 秒，请耐心等待")
        l2_results = run_l2_eval(items, args.limit)
        l2_metrics = compute_metrics(l2_results)
        print("\n=== 5. L2 指标 ===")
        print(json.dumps(l2_metrics, ensure_ascii=False, indent=2))
        all_results["l2"] = {"metrics": l2_metrics, "detail": l2_results}

    # 落盘：报告素材
    report_path = args.out / "eval_report.json"
    report_path.write_text(
        json.dumps(
            {
                "run_at": datetime.now(UTC).isoformat(),
                "models": {
                    "triage": settings.TRIAGE_MODEL,
                    "investigation": settings.INVESTIGATION_MODEL if args.with_l2 else None,
                },
                "sample_size": len(items),
                "results": all_results,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\n✅ 评测报告已保存: {report_path}")
    print("\n注意（评估诚实性）：样本量小，结论须注明局限；")
    print("    详见 AGENTS.md §2.11。")


if __name__ == "__main__":
    main()
