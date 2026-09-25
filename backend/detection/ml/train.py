"""ML 检测引擎的训练与评估。

职责边界（刻意的设计）：
    本模块只做"给定特征矩阵和标签 → 训练模型 → 算指标"。
    **不负责**读文件、不负责归一化、不负责切分 —— 那些由脚本层组织。

    这样划分让本模块可用几百行的合成数据独立测试（秒级），
    而不必每次跑完整的 100 万行数据。

为什么选 XGBoost 作主模型（报告里要能解释）：
    - 本任务是**表格数据**（78 维流特征），树模型是这类数据的最强梯队
    - 不需要特征标准化（按阈值切分，对尺度不敏感）
    - 内建正则化，抗过拟合
    - 能输出**特征重要性**，可分析模型是否依赖了泄漏特征
    - 训练极快（本项目实测 104 万行 7.5 秒，纯 CPU）
    深度神经网络在同等表格数据上通常不占优，且需要 GPU 与大量调参。
"""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split


def evaluate(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, Any]:
    """计算分类指标。

    用 zero_division=0 而非默认行为：
        当某类完全没有预测出来时（precision 分母为 0），
        sklearn 默认会警告并返回 0 或 nan。显式设 0 让结果稳定可预期 ——
        这种情况下 precision 定义为 0 是合理的（没报就没错报可言）。
    """
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        # 混淆矩阵以 tuple 返回，便于报告画图与计算派生指标
        # （如误报率 FPR = fp / (fp + tn)）
        "confusion_matrix": (int(tn), int(fp), int(fn), int(tp)),
    }


def estimate_scale_pos_weight(y: np.ndarray) -> float:
    """计算 XGBoost 的 scale_pos_weight = 负样本数 / 正样本数。

    为什么需要：本项目数据里正常流量占多数（约 72%）。
    不加权时模型倾向于"多判正常"来刷高 accuracy，
    但安全场景最不能接受的是漏报（攻击被判成正常）。
    该权重让正样本的误差被放大，模型更重视检出攻击。

    没有负样本时返回 1.0（避免除零）。
    """
    n_pos = int((y == 1).sum())
    n_neg = int((y == 0).sum())
    if n_pos == 0 or n_neg == 0:
        return 1.0
    return n_neg / n_pos


def _build_model(name: str, y: np.ndarray):
    """按名字构造模型。

    模型在函数内部构造而不是模块级常量：
        因为 scale_pos_weight 依赖具体的 y，必须每次训练时重新算。
    """
    if name == "xgboost":
        from xgboost import XGBClassifier

        return XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.9,
            # 应对类别不平衡（见 estimate_scale_pos_weight 说明）
            scale_pos_weight=estimate_scale_pos_weight(y),
            eval_metric="logloss",
            n_jobs=-1,  # 用满 CPU 核心；XGBoost 是 CPU 算法，无需 GPU
            random_state=42,  # 固定种子保证实验可复现
        )

    if name == "lightgbm":
        from lightgbm import LGBMClassifier

        return LGBMClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
            verbose=-1,
        )

    if name == "random_forest":
        from sklearn.ensemble import RandomForestClassifier

        return RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        )

    if name == "logistic":
        from sklearn.linear_model import LogisticRegression

        return LogisticRegression(max_iter=1000, class_weight="balanced")

    raise ValueError(f"未知模型: {name}")


def train_binary(
    X: np.ndarray,
    y: np.ndarray,
    model: Any | None = None,
    model_name: str = "xgboost",
    test_size: float = 0.3,
) -> tuple[Any, dict[str, Any]]:
    """训练二分类模型并返回 (模型, 指标)。

    接受已准备就绪的 X/y（不做归一化）——
    XGBoost 对特征尺度不敏感，无需 StandardScaler。
    若将来换成对尺度敏感的模型（如 SVM、逻辑回归），
    归一化需在**本函数之外**完成，且只能用训练集拟合（避免 data leakage）。

    Args:
        model: 传入自定义模型则用之（便于测试与扩展）；否则按 model_name 构造。
        test_size: 测试集比例。
    """
    # stratify=y 保证切分后各类比例一致 ——
    # 否则可能切出一个几乎没有攻击样本的测试集，指标完全失真。
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )

    clf = model if model is not None else _build_model(model_name, y_tr)
    clf.fit(X_tr, y_tr)
    metrics = evaluate(y_te, clf.predict(X_te))
    return clf, metrics


def train_models(
    X: np.ndarray,
    y: np.ndarray,
    model_names: list[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """对比训练多个模型，返回 {模型名: 指标}。

    这是报告 §11.1「多模型对比」的实现。
    主模型（xgboost）会进系统；其余模型只用于报告里的对比表。
    """
    if model_names is None:
        model_names = ["xgboost", "random_forest", "lightgbm", "logistic"]

    results: dict[str, dict[str, Any]] = {}
    for name in model_names:
        _, metrics = train_binary(X, y, model_name=name)
        results[name] = metrics
    return results
