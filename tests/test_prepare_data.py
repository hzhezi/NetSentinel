"""数据准备脚本的测试。

这些测试用**小样本 DataFrame**（不读真实数据），
因此快速且不依赖 data/raw 里的大文件。
真实数据的处理结果由 scripts/prepare_data.py 的 CLI 运行验证。

测试重点不是"清洗得干净"，而是**清洗原则被遵守**：
    只修"工具算出的未定义值"（inf/NaN），
    不动"数据反映的事实"（极端值，那可能就是攻击特征）。
"""

import numpy as np
import pandas as pd

from scripts.prepare_data import (
    clean_features,
    label_column,
    normalize_columns,
    split_by_label,
    to_binary_label,
)

# ── 列名处理 ───────────────────────────────────────────────────


def test_normalize_columns_strips_spaces():
    """官方 CSV 的列名带前导空格（如 ' Destination Port'）。

    不处理的话 df['Destination Port'] 会 KeyError —— 这是很隐蔽的坑。
    """
    df = pd.DataFrame({" Destination Port": [80], " Flow Duration": [1]})
    out = normalize_columns(df)
    assert list(out.columns) == ["Destination Port", "Flow Duration"]


def test_label_column_found_after_normalization():
    """strip 之后应能正确定位 Label 列。"""
    df = pd.DataFrame({" Label": ["BENIGN"], " Flow Duration": [1]})
    df = normalize_columns(df)
    assert label_column(df) == "Label"


# ── 标签处理 ───────────────────────────────────────────────────


def test_to_binary_label_maps_benign_to_zero():
    s = pd.Series(["BENIGN", "BENIGN"])
    assert list(to_binary_label(s)) == [0, 0]


def test_to_binary_label_maps_attacks_to_one():
    s = pd.Series(["DDoS", "PortScan", "Web Attack XSS"])
    assert list(to_binary_label(s)) == [1, 1, 1]


def test_to_binary_label_is_case_insensitive():
    """BENIGN 大小写可能不一致，必须归一。"""
    s = pd.Series(["Benign", "benign", "BENIGN"])
    assert list(to_binary_label(s)) == [0, 0, 0]


# ── 特征清洗：核心原则 ─────────────────────────────────────────


def test_clean_replaces_infinity():
    """inf 是"工具除零"的产物，不是真实性，必须处理。

    不处理的话 XGBoost 无法训练（数学上未定义）。
    """
    df = pd.DataFrame({"a": [1.0, np.inf, -np.inf], "b": [1, 2, 3]})
    out = clean_features(df)
    assert not np.isinf(out.to_numpy()).any()


def test_clean_preserves_extreme_values():
    """★ 核心原则：极端值必须保留。

    反例：如果把"看起来异常"的值当噪声删掉，
    DDoS 的高包速率、PortScan 的特定端口分布都会被抹掉 ——
    而那正是攻击特征本身。删掉等于删训练信号。
    """
    df = pd.DataFrame(
        {
            "normal": [1.0, 2.0],
            "extreme": [1e9, 1e-9],  # 极端但合法
        }
    )
    out = clean_features(df)
    assert out["extreme"].tolist() == [1e9, 1e-9]


def test_clean_does_not_drop_rows():
    """清洗不应删除任何行 —— 丢样本会改变数据的真实分布。"""
    df = pd.DataFrame({"a": [1.0, np.inf], "b": [np.nan, 2.0]})
    out = clean_features(df)
    assert len(out) == 2


def test_clean_only_touches_numeric_columns():
    """非数值列（如原始标签文本）不应被填充逻辑破坏。"""
    df = pd.DataFrame({"num": [1.0, np.nan], "text": ["DDoS", "BENIGN"]})
    out = clean_features(df)
    assert out["text"].tolist() == ["DDoS", "BENIGN"]


# ── 切分 ───────────────────────────────────────────────────────


def test_split_by_label_returns_normal_and_attack():
    df = pd.DataFrame(
        {
            "f": [1, 2, 3, 4],
            "Label": ["BENIGN", "DDoS", "BENIGN", "PortScan"],
        }
    )
    normal, attack = split_by_label(df)
    assert list(normal["Label"]) == ["BENIGN", "BENIGN"]
    assert list(attack["Label"]) == ["DDoS", "PortScan"]


def test_split_by_label_with_sample_limit():
    """支持采样上限，便于用小子集快速演示。"""
    df = pd.DataFrame(
        {
            "f": range(10),
            "Label": ["BENIGN"] * 5 + ["DDoS"] * 5,
        }
    )
    normal, attack = split_by_label(df, n_per_class=2)
    assert len(normal) == 2
    assert len(attack) == 2
