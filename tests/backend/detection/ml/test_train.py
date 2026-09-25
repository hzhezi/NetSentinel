"""ML 训练模块的测试。

设计说明：训练函数接受**已切分的数组**（numpy），不负责读文件、不负责
归一化。这样它可独立测试，且调用方（脚本/CLI）能自由组织数据来源。

测试用合成数据（几百行、几个特征），秒级完成，不依赖 data/ 下的真实数据。
"""

import numpy as np
import pytest
from sklearn.linear_model import LogisticRegression

from backend.detection.ml.train import (
    estimate_scale_pos_weight,
    evaluate,
    train_binary,
    train_models,
)


@pytest.fixture
def synthetic():
    """构造一个**线性可分**的小数据集，保证模型能学到东西。

    用固定种子保证可复现 —— 否则测试会随机失败（flaky）。
    """
    rng = np.random.default_rng(42)
    n = 400
    X = rng.random((n, 5))
    # 让第 0 个特征决定标签，制造一个明确可学的规律
    y = (X[:, 0] > 0.5).astype(int)
    return X, y


# ── 指标计算 ───────────────────────────────────────────────────


def test_evaluate_returns_all_metrics():
    """评估必须给出完整指标集，报告要用。"""
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 0, 1, 1])
    m = evaluate(y_true, y_pred)

    assert m["accuracy"] == 1.0
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1"] == 1.0


def test_evaluate_handles_perfectly_wrong_predictions():
    """全错的情况不能崩（分母为 0 的处理）。

    真实场景：某类攻击完全没检出时，recall 的分母是正样本数，
    但 precision 的分母（预测为正的数量）可能是 0 —— 必须安全处理。
    """
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 0, 0, 0])  # 一条都没报
    m = evaluate(y_true, y_pred)

    assert m["recall"] == 0.0
    assert m["precision"] == 0.0  # 不能是 nan 或抛异常
    assert m["accuracy"] == 0.5


def test_evaluate_returns_confusion_matrix():
    """混淆矩阵要能拿到 —— 报告里要画。"""
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 1, 1, 0])
    m = evaluate(y_true, y_pred)

    tn, fp, fn, tp = m["confusion_matrix"]
    assert (tn, fp, fn, tp) == (1, 1, 1, 1)


# ── 训练 ───────────────────────────────────────────────────────


def test_train_binary_returns_model_and_metrics(synthetic):
    X, y = synthetic
    model, metrics = train_binary(X, y)

    assert hasattr(model, "predict")
    assert "accuracy" in metrics
    assert "f1" in metrics
    # 线性可分的数据，应该学得不错（不要求完美，避免过拟合测试脆弱）
    assert metrics["accuracy"] > 0.8


def test_train_binary_is_reproducible(synthetic):
    """固定 random_state 后，两次训练应得到相同结果。

    可复现性对实验很重要：报告里的数字必须能被重新跑出来。
    """
    X, y = synthetic
    _, m1 = train_binary(X, y)
    _, m2 = train_binary(X, y)
    assert m1["f1"] == m2["f1"]


def test_train_binary_accepts_custom_model(synthetic):
    """允许传入自定义模型 —— 用于多模型对比实验。

    用依赖注入而不是在函数里硬编码 XGBoost：
    这样加新模型不用改训练函数（符合开闭原则），也让测试能用
    训练极快的 LogisticRegression 而不是每次都跑 XGBoost。
    """
    X, y = synthetic
    model, metrics = train_binary(X, y, model=LogisticRegression(max_iter=200))
    assert isinstance(model, LogisticRegression)
    assert metrics["accuracy"] > 0.8


# ── 类别不平衡处理 ─────────────────────────────────────────────


def test_estimate_scale_pos_weight():
    """不平衡数据要算正负样本比，供 XGBoost 加权使用。

    本项目数据里正常流量占多数（约 72%），
    不加权的话模型会倾向"都判正常"以刷高准确率。
    """
    y = np.array([0] * 8 + [1] * 2)
    assert estimate_scale_pos_weight(y) == pytest.approx(4.0)


def test_estimate_scale_pos_weight_handles_no_negatives():
    """没有负样本时不能除零。"""
    y = np.array([1, 1, 1])
    assert estimate_scale_pos_weight(y) >= 1.0


# ── 多模型对比 ─────────────────────────────────────────────────


def test_train_models_returns_metrics_per_model(synthetic):
    """多模型对比：返回 {模型名: 指标} 的字典。"""
    X, y = synthetic
    results = train_models(X, y, model_names=["logistic"])

    assert "logistic" in results
    assert "accuracy" in results["logistic"]


def test_train_models_supports_multiple(synthetic):
    """至少支持 logistic 与 xgboost 两个可选项。"""
    X, y = synthetic
    results = train_models(X, y, model_names=["logistic", "xgboost"])

    assert set(results.keys()) == {"logistic", "xgboost"}
