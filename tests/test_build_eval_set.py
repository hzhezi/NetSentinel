"""评测集构造的测试。

═══════════════════════════════════════════════════════════════════
为什么评测集必须是"带 ground truth 的真实告警"
═══════════════════════════════════════════════════════════════════
评测 LLM 研判质量的前提是**知道正确答案**。而答案不能凭主观编造 ——
否则评的是"模型是否同意我们的看法"，而非"模型判断是否正确"。

本项目的做法：**答案来自数据构造过程**。
    generate_demo_pcap.py 知道每个包是什么（攻击 / 正常），
    Suricata 从这些包产出告警，因此：
        攻击包触发的告警   → ground truth = true_positive
        正常包触发的告警   → ground truth = false_positive

这样答案有**客观依据**，且可复现（固定随机种子）。

═══════════════════════════════════════════════════════════════════
评测的诚实性（AGENTS.md §2.11）
═══════════════════════════════════════════════════════════════════
    - 样本量小（个位数到几十条），结论必须注明局限
    - 不把"模型看起来合理"当作"准确"
    - 指标不好看也要如实报告
═══════════════════════════════════════════════════════════════════
"""

import json

import pytest

from scripts.build_eval_set import (
    build_eval_set,
    compute_metrics,
    label_from_scenario,
)

# ── 标注逻辑 ───────────────────────────────────────────────────


def test_attack_scenario_labeled_positive():
    """攻击场景触发的告警 → 真阳性。"""
    assert label_from_scenario("sql_injection") == "true_positive"
    assert label_from_scenario("log4shell") == "true_positive"
    assert label_from_scenario("ssh_brute_force") == "true_positive"


def test_benign_scenario_labeled_false_positive():
    """正常流量若触发告警 → 假阳性（误报）。"""
    assert label_from_scenario("benign_http") == "false_positive"


def test_unknown_scenario_raises():
    """未知场景必须显式报错，不能默认成某个答案。

    默认成 true_positive 会让评测偏向"模型说攻击就算对"，
    默认成 false_positive 则相反 —— 两者都会污染指标。
    """
    with pytest.raises(ValueError):
        label_from_scenario("totally_unknown_scenario")


# ── 评测集构造 ─────────────────────────────────────────────────


def test_build_eval_set_returns_items_with_labels():
    """构造的每条评测样本都要带：告警内容 + 标准答案 + 场景说明。"""
    scenarios = [
        {"scenario": "sql_injection", "alert": {"signature": "SQL Injection", "src_ip": "1.1.1.1"}},
        {"scenario": "benign_http", "alert": {"signature": "Some Scan", "src_ip": "2.2.2.2"}},
    ]
    items = build_eval_set(scenarios)

    assert len(items) == 2
    assert items[0]["ground_truth"] == "true_positive"
    assert items[1]["ground_truth"] == "false_positive"
    assert items[0]["scenario"] == "sql_injection"


def test_build_eval_set_includes_alert_payload():
    """评测样本必须含告警内容 —— 这是喂给 LLM 的输入。"""
    scenarios = [{"scenario": "log4shell", "alert": {"signature": "Log4Shell", "dst_port": 8080}}]
    items = build_eval_set(scenarios)
    assert items[0]["alert"]["signature"] == "Log4Shell"


def test_build_eval_set_skips_duplicate_signatures():
    """同一签名+同源的重复告警只保留一条。

    评测不该被重复样本主导（10 条 SSH 爆破告警会让 SSH 主导指标），
    因此按 (signature, src_ip) 去重。
    """
    scenarios = [
        {"scenario": "ssh_brute_force", "alert": {"signature": "SSH", "src_ip": "1.1.1.1"}},
        {"scenario": "ssh_brute_force", "alert": {"signature": "SSH", "src_ip": "1.1.1.1"}},
        {"scenario": "ssh_brute_force", "alert": {"signature": "SSH", "src_ip": "2.2.2.2"}},
    ]
    items = build_eval_set(scenarios)
    assert len(items) == 2


# ── 指标计算 ───────────────────────────────────────────────────


def test_compute_metrics_perfect_agreement():
    results = [
        {"ground_truth": "true_positive", "predicted": "true_positive"},
        {"ground_truth": "false_positive", "predicted": "false_positive"},
    ]
    m = compute_metrics(results)
    assert m["agreement"] == 1.0
    assert m["total"] == 2


def test_compute_metrics_partial_agreement():
    """一致率只在"模型给出明确判断"的样本上计算。

    设计取舍：needs_human_review 不计入分母 ——
    把它当"答错"会低估模型（它是审慎而非错误）。
    其占比单独由 needs_human_review_rate 反映。
    """
    results = [
        # 3 条明确判断：2 对 1 错
        {"ground_truth": "true_positive", "predicted": "true_positive"},
        {"ground_truth": "true_positive", "predicted": "needs_human_review"},  # 不计入
        {"ground_truth": "false_positive", "predicted": "false_positive"},
        {"ground_truth": "false_positive", "predicted": "true_positive"},  # 错
    ]
    m = compute_metrics(results)
    assert m["decisive_count"] == 3
    assert m["correct_count"] == 2
    assert m["agreement"] == round(2 / 3, 4)
    assert m["needs_human_review_rate"] == 0.25


def test_compute_metrics_counts_needs_human_review():
    """needs_human_review 的量要单独统计 —— 它是"模型承认不确定"的比例。

    这个数字有意义：太高的说明告警信息不足（或提示词需改进），
    太低则可能模型在"过度自信"。
    """
    results = [
        {"ground_truth": "true_positive", "predicted": "needs_human_review"},
        {"ground_truth": "true_positive", "predicted": "true_positive"},
    ]
    m = compute_metrics(results)
    assert m["needs_human_review_count"] == 1
    assert m["needs_human_review_rate"] == 0.5


def test_compute_metrics_confusion_matrix():
    """真阳性/假阳性/假阴性/真阴性的混淆矩阵。

    把"攻击判成攻击"等四种情况分别计数 ——
    安全场景最关心的是**假阴性（漏报）**，必须能单独看到。
    """
    results = [
        {"ground_truth": "true_positive", "predicted": "true_positive"},  # TP
        {"ground_truth": "true_positive", "predicted": "false_positive"},  # FN ← 漏报
        {"ground_truth": "false_positive", "predicted": "false_positive"},  # TN
        {"ground_truth": "false_positive", "predicted": "true_positive"},  # FP
    ]
    m = compute_metrics(results)
    assert m["confusion"]["true_positive"]["true_positive"] == 1
    assert m["confusion"]["true_positive"]["false_positive"] == 1
    assert m["confusion"]["false_positive"]["false_positive"] == 1
    assert m["confusion"]["false_positive"]["true_positive"] == 1


def test_compute_metrics_handles_empty():
    """空结果不能崩（除零保护）。"""
    m = compute_metrics([])
    assert m["total"] == 0
    assert m["agreement"] == 0.0


def test_compute_metrics_tracks_cost_and_latency():
    """成本与耗时也要统计 —— 报告需要。"""
    results = [
        {
            "ground_truth": "true_positive",
            "predicted": "true_positive",
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "latency_ms": 2000,
        },
        {
            "ground_truth": "true_positive",
            "predicted": "true_positive",
            "prompt_tokens": 200,
            "completion_tokens": 80,
            "latency_ms": 3000,
        },
    ]
    m = compute_metrics(results)
    assert m["total_tokens"] == 430
    assert m["avg_latency_ms"] == 2500


# ── 落盘格式 ───────────────────────────────────────────────────


def test_eval_set_serializable(tmp_path):
    """评测集要能存成 JSON（供复现与人工复核）。"""
    items = build_eval_set(
        [
            {"scenario": "sql_injection", "alert": {"signature": "SQL"}},
        ]
    )
    path = tmp_path / "eval_set.json"
    path.write_text(json.dumps(items, ensure_ascii=False), encoding="utf-8")

    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded[0]["ground_truth"] == "true_positive"
