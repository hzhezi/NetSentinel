"""严格评估工具：应对 CICIDS2017 的已知评估缺陷。

═══════════════════════════════════════════════════════════════════
为什么需要这个模块（报告里的"评估诚实性"一节就靠它）
═══════════════════════════════════════════════════════════════════
CICIDS2017 在**随机切分**下可轻松达到 99.9%+ F1，但这个数字不可信：

问题一 · 流泄漏（session leakage）
    一次 DDoS 攻击持续 30 分钟，被 CICFlowMeter 切成十余万条高度相似的流。
    随机切分时，同一攻击的"相邻流"被分到训练集和测试集两边 ——
    模型在测试集上遇到的是"训练时见过的东西的近亲"，于是准确率虚高。
    → 本模块用 **leave_one_attack_out**（按攻击类型留一）应对：
      训练时完全不含某类攻击，测试时只考它，测的是**真实泛化能力**。

问题二 · 特征泄漏（feature leakage）
    某些特征（如 Destination Port）与标签相关性过强，
    模型可能只靠"记住端口号"就达到高准确率，而没学到攻击行为模式。
    → 本模块用 **feature_importances** 应对：
      看模型依赖哪些特征。若少数可疑特征占据主导，就说明在走捷径。

本模块只做**分析**，不参与系统运行时。结果用于报告的评测章节。
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from backend.detection.ml.train import evaluate

BENIGN_ALIASES = {"BENIGN", "NORMAL"}


def _is_benign(label: str) -> bool:
    return str(label).strip().upper() in BENIGN_ALIASES


def _build_analysis_model(y: np.ndarray, model: Any | None):
    """构造分析用模型。

    默认用 XGBoost（与生产一致）；若未提供则给逻辑回归回退 ——
    因为某些环境可能缺 OpenMP 导致 XGBoost 不可用，
    而特征重要性分析换个模型同样能做。
    """
    if model is not None:
        return model
    try:
        from xgboost import XGBClassifier

        return XGBClassifier(
            n_estimators=200,
            max_depth=6,
            eval_metric="logloss",
            n_jobs=-1,
            random_state=42,
        )
    except Exception:
        from sklearn.linear_model import LogisticRegression

        return LogisticRegression(max_iter=1000, class_weight="balanced")


def random_split(
    df: pd.DataFrame,
    label_column: str = "Label",
    model: Any | None = None,
    test_size: float = 0.3,
) -> dict[str, Any]:
    """标准随机切分评估（基线，可与文献对比）。

    这是"教科书做法"，普遍用于论文中，因此保留它作为**对比基线** ——
    它的高分不是造假，而是**数据集的固有特性**导致。报告里会与
    leave_one_attack_out 的结果并列呈现，说明差异来源。
    """
    from sklearn.model_selection import train_test_split

    feature_cols = [c for c in df.columns if c != label_column]
    X = df[feature_cols].to_numpy(dtype=float)
    y = (~df[label_column].map(_is_benign)).astype(int).to_numpy()

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )
    clf = _build_analysis_model(y_tr, model)
    clf.fit(X_tr, y_tr)
    return evaluate(y_te, clf.predict(X_te))


def leave_one_attack_out(
    df: pd.DataFrame,
    label_column: str = "Label",
    model: Any | None = None,
    attack_types: list[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """按攻击类型留一交叉验证。

    流程（对每一种攻击类型 A）：
        训练集 = 全部正常流量 + **除 A 外的所有攻击**
        测试集 = 类型 A 的样本
        指标   = 模型能否认出**从没见过的 A**

    这个指标才是真实泛化能力：模型必须靠"偏离正常的程度"识别新攻击，
    而不能靠"训练时见过同类样本"。

    预期结果：recall 会**明显低于**随机切分。
    这不是坏消息 —— 它诚实地反映了零日检测的真实难度，
    也印证了本项目"双引擎 + LLM 研判"的必要性：
    规则引擎补已知攻击，ML 补未知，LLM 再对两者做研判降噪。

    Args:
        attack_types: 只对这些类型做留一（大数据集上可指定子集加速）。
    """
    is_benign = df[label_column].map(_is_benign)
    normal = df[is_benign]
    attacks = df[~is_benign]

    if attack_types is None:
        attack_types = sorted(attacks[label_column].unique().tolist())

    feature_cols = [c for c in df.columns if c != label_column]
    results: dict[str, dict[str, Any]] = {}

    for attack in attack_types:
        held_out = attacks[attacks[label_column] == attack]
        # 训练集：正常流量 + 其余攻击类型（关键：不含当前攻击）
        rest_attacks = attacks[attacks[label_column] != attack]
        train_df = pd.concat([normal, rest_attacks], ignore_index=True)

        if len(held_out) == 0 or len(train_df) == 0:
            continue
        # 训练集若只有一类标签则无法训练分类器，跳过
        y_train = (~train_df[label_column].map(_is_benign)).astype(int).to_numpy()
        if len(np.unique(y_train)) < 2:
            continue

        X_train = train_df[feature_cols].to_numpy(dtype=float)
        X_test = held_out[feature_cols].to_numpy(dtype=float)
        y_test = np.ones(len(held_out), dtype=int)  # 留出集全是攻击，真值全为 1

        clf = _build_analysis_model(y_train, model)
        clf.fit(X_train, y_train)

        # 此处只看 recall：留出集全是攻击，关心的是"认出来多少"。
        # precision 在此意义有限（没有负样本），故用 evaluate 后取 recall。
        pred = clf.predict(X_test)
        m = evaluate(y_test, pred)
        results[str(attack)] = {
            "recall": m["recall"],
            "n_samples": int(len(held_out)),
            # 被误判为正常的数量 —— 即漏报数，安全场景最关心
            "missed": int((pred == 0).sum()),
        }

    return results


def feature_importances(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: list[str],
    model: Any | None = None,
    top_k: int | None = None,
) -> list[tuple[str, float]]:
    """计算特征重要性，按降序返回 [(特征名, 分数), ...]。

    用途：识别模型是否在"走捷径"。
        若 Destination Port 这类与标签强相关的特征占据主导，
        说明模型的准确率部分来自特征泄漏，而非学到了攻击行为模式。
        这个分析是报告里"诚实评估"一节的直接证据。

    对树模型用 feature_importances_；对线性模型用系数绝对值
    （两者不可直接比较数值大小，但都可看"哪些特征排前面"）。
    """
    clf = _build_analysis_model(y, model)
    clf.fit(X, y)

    if hasattr(clf, "feature_importances_"):
        scores = np.asarray(clf.feature_importances_, dtype=float)
    elif hasattr(clf, "coef_"):
        # 线性模型的系数可能有负数，取绝对值表示"影响强度"
        scores = np.abs(np.asarray(clf.coef_, dtype=float)).ravel()
    else:
        raise ValueError(f"模型 {type(clf).__name__} 不支持重要性分析")

    # 归一化为和=1，便于不同模型间对比"相对占比"
    total = scores.sum()
    if total > 0:
        scores = scores / total

    pairs = list(zip(feature_names, scores.tolist(), strict=False))
    pairs.sort(key=lambda p: p[1], reverse=True)
    return pairs[:top_k] if top_k else pairs
