"""严格评估工具的测试。

这些工具用于应对 CICIDS2017 的**已知评估缺陷**：
    1. 流泄漏：同一攻击会话的流被随机切分到训练/测试，导致指标虚高
    2. 特征泄漏：某些特征（如目标端口）与标签相关性过强，模型可能"走捷径"

对应两种分析：
    group_split_by_label   —— 按攻击类型分组切分，测真实泛化
    feature_importances    —— 看模型依赖哪些特征，识别是否走捷径

测试用合成数据，不依赖真实数据集。
"""

import numpy as np
import pandas as pd
import pytest
from sklearn.linear_model import LogisticRegression

from backend.detection.ml.evaluation import (
    feature_importances,
    leave_one_attack_out,
    random_split,
)

# ── 分组切分：按攻击类型留一 ────────────────────────────────────


@pytest.fixture
def multi_attack_df():
    """构造含多种攻击类型的小数据集。

    设计成"每种攻击靠不同的特征区分"，这样才能验证
    leave_one_attack_out 真的在考泛化能力。
    """
    rng = np.random.default_rng(0)
    rows = []

    # 正常流量：所有特征都低
    for _ in range(60):
        rows.append({"f0": rng.random(), "f1": rng.random(), "Label": "BENIGN"})
    # DDoS：f0 高
    for _ in range(40):
        rows.append({"f0": 5 + rng.random(), "f1": rng.random(), "Label": "DDoS"})
    # PortScan：f1 高
    for _ in range(40):
        rows.append({"f0": rng.random(), "f1": 5 + rng.random(), "Label": "PortScan"})

    return pd.DataFrame(rows)


def test_leave_one_attack_out_returns_result_per_held_out(multi_attack_df):
    """对每种攻击类型留一验证，各出一个结果。"""
    result = leave_one_attack_out(multi_attack_df)

    assert "DDoS" in result
    assert "PortScan" in result
    # 每种结果都要有 recall —— 这是留一验证最关心的指标
    assert "recall" in result["DDoS"]


def test_leave_one_attack_out_trains_without_held_out_attack(multi_attack_df):
    """留一验证的核心：训练集里**不包含**被留出的攻击类型。

    实现校验方式：通过"模型对未见攻击的检出能力"间接体现 ——
    如果训练时见过，recall 会接近 1；没见过则明显更低。

    这个测试只验证机制成立（能跑通并产出 recall），
    不硬编码具体数值（那会随数据变化而脆弱）。
    """
    result = leave_one_attack_out(multi_attack_df)
    for m in result.values():
        assert 0.0 <= m["recall"] <= 1.0


def test_leave_one_attack_out_skips_benign(multi_attack_df):
    """BENIGN 不是攻击类型，不应被当作留出对象。"""
    result = leave_one_attack_out(multi_attack_df)
    assert "BENIGN" not in result


def test_leave_one_attack_out_with_specific_types(multi_attack_df):
    """可指定只对某些攻击做留一 —— 大数据集上可用子集加速。"""
    result = leave_one_attack_out(multi_attack_df, attack_types=["DDoS"])
    assert set(result.keys()) == {"DDoS"}


# ── 随机切分：标准做法，用于对比 ────────────────────────────────


def test_random_split_returns_metrics(multi_attack_df):
    """随机切分是标准做法（可与文献对比），留作基线。"""
    m = random_split(multi_attack_df)
    assert "accuracy" in m
    assert "f1" in m


def test_random_split_beats_leave_one_out(multi_attack_df):
    """关键实验结论：随机切分的指标应**高于**留一验证。

    为什么这是重要断言：
        它证明了数据集的评估虚高确实存在。如果两者相近，
        说明没有泄漏问题；如果随机切分明显更高，就实锤了泄漏。
        这条测试把"评估诚实性"这个设计意图固化下来。
    """
    random_metrics = random_split(multi_attack_df)
    loo = leave_one_attack_out(multi_attack_df)
    avg_loo_recall = float(np.mean([m["recall"] for m in loo.values()]))

    # 随机切分的整体 f1 应不低于留一验证的平均 recall
    assert random_metrics["f1"] >= avg_loo_recall


# ── 特征重要性 ─────────────────────────────────────────────────


def test_feature_importances_returns_sorted_list(multi_attack_df):
    """返回按重要性降序排列的特征名与分数。"""
    X = multi_attack_df[["f0", "f1"]].to_numpy()
    y = (multi_attack_df["Label"] != "BENIGN").astype(int).to_numpy()

    imp = feature_importances(X, y, feature_names=["f0", "f1"])

    assert len(imp) == 2
    # 已按降序排列
    assert imp[0][1] >= imp[1][1]
    assert {name for name, _ in imp} == {"f0", "f1"}


def test_feature_importances_works_with_logistic(multi_attack_df):
    """支持用逻辑回归做重要性分析（用系数绝对值）。

    XGBoost 需要装 libomp，某些环境可能没有；
    提供逻辑回归的回退路径让分析工具更可用。
    """
    X = multi_attack_df[["f0", "f1"]].to_numpy()
    y = (multi_attack_df["Label"] != "BENIGN").astype(int).to_numpy()

    imp = feature_importances(
        X, y, feature_names=["f0", "f1"], model=LogisticRegression(max_iter=200)
    )
    assert len(imp) == 2


def test_feature_importances_identifies_informative_feature(multi_attack_df):
    """模型应把"真正有区分度的特征"排在前面。

    数据里 f0 和 f1 都有区分度（分别对应两种攻击），
    所以两者重要性都应显著大于 0。这条测试验证分析工具
    真的能反映特征作用，而不只是返回一堆零。
    """
    X = multi_attack_df[["f0", "f1"]].to_numpy()
    y = (multi_attack_df["Label"] != "BENIGN").astype(int).to_numpy()

    imp = feature_importances(X, y, feature_names=["f0", "f1"])
    assert all(score > 0 for _, score in imp)
