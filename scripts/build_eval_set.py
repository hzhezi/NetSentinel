"""构造 LLM 研判评测集。

═══════════════════════════════════════════════════════════════════
答案从哪来（这是评测能成立的前提）
═══════════════════════════════════════════════════════════════════
不能用主观判断当标准答案 —— 那评的是"模型是否同意我们"。

本项目的答案来自**数据构造过程**：
    generate_demo_pcap.py 知道每个包是攻击还是正常；
    Suricata 从这些包产出告警；
    因此每条告警的真值是可以从"它由什么包触发"推出来的：

        攻击包触发的告警   → true_positive
        正常包触发的告警   → false_positive

这样答案有客观依据、可复现（固定种子），也是"用真实数据评测"的体现。

═══════════════════════════════════════════════════════════════════
两个刻意的取舍
═══════════════════════════════════════════════════════════════════
① **按 (signature, src_ip) 去重**
   一次 SSH 爆破产生 5 条相同告警。若全保留，SSH 会主导指标，
   掩盖其他类型上的表现。

② **只统计"能对上真值"的三态**
   needs_human_review 不计入一致率（它不是"答对/答错"），
   但**单独统计其占比** —— 这个数字反映"模型承认不确定的频率"：
       过高 → 告警信息不足，或提示词需要改进
       过低 → 可能模型过度自信（安全场景下危险）
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# 场景 → 标准答案。
# 场景名对应 generate_demo_pcap.py 里构造的流量类型。
_ATTACK_SCENARIOS = {
    "sql_injection",
    "sql_injection_or",
    "directory_traversal",
    "xss",
    "log4shell",
    "reverse_shell",
    "ssh_brute_force",
    "tcp_scan",
    "icmp_sweep",
    "dns_tunnel",
}

_BENIGN_SCENARIOS = {
    "benign_http",
}


def label_from_scenario(scenario: str) -> str:
    """把场景名映射为标准答案。

    未知场景**显式报错**而非默认某个值 ——
    默认值会让评测偏向某一方，污染指标且不易察觉。
    """
    if scenario in _ATTACK_SCENARIOS:
        return "true_positive"
    if scenario in _BENIGN_SCENARIOS:
        return "false_positive"
    raise ValueError(
        f"未知场景: {scenario!r}。请在 _ATTACK_SCENARIOS 或 _BENIGN_SCENARIOS 中登记。"
    )


def build_eval_set(scenarios: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """构造评测集。

    Args:
        scenarios: 形如 [{"scenario": "sql_injection", "alert": {...}}]。
                   通常由解析 Suricata eve.json 并关联到流量的构造过程得到。

    Returns:
        去重后的评测样本列表，每项含：
            scenario      —— 流量场景（溯源用）
            alert         —— 喂给 LLM 的告警内容
            ground_truth  —— 标准答案
    """
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for s in scenarios:
        alert = s.get("alert") or {}
        # 去重键：同一签名 + 同一源的重复告警只留一条
        key = (str(alert.get("signature", "")), str(alert.get("src_ip", "")))
        if key in seen:
            continue
        seen.add(key)

        items.append(
            {
                "scenario": s["scenario"],
                "alert": alert,
                "ground_truth": label_from_scenario(s["scenario"]),
            }
        )

    return items


def compute_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    """计算评测指标。

    输入每项需含：ground_truth（标准答案）、predicted（模型结论）。

    指标说明：
        agreement                  —— 结论一致率（仅计 true/false_positive 两类）
        needs_human_review_rate    —— 模型承认不确定的比例（单独看，不计入一致率）
        confusion                  —— 混淆矩阵，**漏报（假阴性）可单独看到**
        total_tokens / avg_latency_ms —— 成本与性能
    """
    total = len(results)
    if total == 0:
        return {
            "total": 0,
            "agreement": 0.0,
            "needs_human_review_count": 0,
            "needs_human_review_rate": 0.0,
            "confusion": {},
            "total_tokens": 0,
            "avg_latency_ms": 0,
        }

    # 混淆矩阵：只统计"能判定对错"的样本（排除 needs_human_review）
    confusion: dict[str, dict[str, int]] = {}
    decisive = 0
    correct = 0

    for r in results:
        gt = r.get("ground_truth")
        pred = r.get("predicted")
        if gt in ("true_positive", "false_positive") and pred in (
            "true_positive",
            "false_positive",
        ):
            decisive += 1
            confusion.setdefault(gt, {})
            confusion[gt][pred] = confusion[gt].get(pred, 0) + 1
            if gt == pred:
                correct += 1

    nhr = sum(1 for r in results if r.get("predicted") == "needs_human_review")
    tokens = sum(
        int(r.get("prompt_tokens") or 0) + int(r.get("completion_tokens") or 0) for r in results
    )
    latencies = [int(r.get("latency_ms") or 0) for r in results if r.get("latency_ms")]

    return {
        "total": total,
        # 一致率只在"模型给出了明确判断"的样本上计算 ——
        # 把 needs_human_review 当作"答错"会低估模型（它其实是审慎）
        "agreement": round(correct / decisive, 4) if decisive else 0.0,
        "decisive_count": decisive,
        "correct_count": correct,
        "needs_human_review_count": nhr,
        "needs_human_review_rate": round(nhr / total, 4),
        "confusion": confusion,
        "total_tokens": tokens,
        "avg_latency_ms": int(sum(latencies) / len(latencies)) if latencies else 0,
    }


def load_eval_set(path: str | Path) -> list[dict[str, Any]]:
    """从 JSON 加载评测集。"""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save_eval_set(items: list[dict[str, Any]], path: str | Path) -> None:
    """保存评测集（供人工复核与复现）。"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
