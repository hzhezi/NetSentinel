"""CICIDS2017 数据准备脚本。

═══════════════════════════════════════════════════════════════════
清洗原则（重要，决定了每一步的取舍）
═══════════════════════════════════════════════════════════════════
本脚本**只修"数据生成工具的错误"，不动"数据本身反映的事实"**。

具体区分：
    ✅ 该处理：inf / NaN
        这些是 CICFlowMeter 计算特征时除零的产物
        （如 Flow Bytes/s = bytes / duration，duration=0 时溢出）。
        它们在数学上是"未定义"，不是真实测量值，
        且会让 XGBoost 直接无法训练。

    ❌ 不该处理：数值极端但合法的值
        例如 DDoS 的包速率极高、PortScan 的目标端口分布特殊。
        **这些极端值正是攻击特征本身**，删掉它们等于删训练信号。

因此本脚本**不删除异常值、不做分箱、不删行**。

关于归一化（StandardScaler 等）：
    刻意**不在此脚本做**。原因：归一化器必须只用训练集拟合，
    否则测试集信息会泄漏进训练（data leakage），导致评估虚高。
    归一化在训练脚本里对训练集 fit、对测试集 transform。

使用方式：
    uv run python scripts/prepare_data.py                  # 处理 data/raw 下全部 CSV
    uv run python scripts/prepare_data.py --sample 50000   # 每类采样，快速演示用
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

RAW_DIR = Path("data/raw")
PROCESSED_DIR = Path("data/processed")


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """去掉列名的前后空格。

    官方 CSV 的列名带前导空格（如 ' Destination Port'）。
    不处理的话 df["Destination Port"] 会 KeyError —— 很隐蔽的坑。
    """
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    return df


def label_column(df: pd.DataFrame) -> str:
    """定位标签列名。

    官方数据里它叫 "Label"，但为稳妥起见做一次不区分大小写的查找，
    避免因某个镜像版本的命名差异而崩溃。
    """
    for col in df.columns:
        if col.lower() == "label":
            return col
    raise ValueError(f"找不到标签列，现有列：{list(df.columns)[:5]}...")


def to_binary_label(series: pd.Series) -> pd.Series:
    """把多类标签转成二分类：BENIGN → 0，其余（各种攻击）→ 1。

    做大小写归一：数据集里 BENIGN 的写法可能不一致。
    """
    is_benign = series.astype(str).str.strip().str.upper() == "BENIGN"
    return (~is_benign).astype(int)


def clean_features(df: pd.DataFrame) -> pd.DataFrame:
    """处理 inf / NaN。**保留所有行、保留极端值。**

    处理方式：
        inf → NaN（因为 inf 在数学上无意义，先统一成"缺失"）
        NaN → 0（用一个明确的有限值填充，让模型能训练）

    为什么用 0 填充而不是中位数：
        这里刻意选最简单的策略，避免引入"用全局统计量"这种
        可能泄漏信息的操作。若模型效果受填充策略影响大，
        那是后续实验要验证的问题，不是这里该预先优化的。
    """
    df = df.copy()
    numeric_cols = df.select_dtypes(include=[np.number]).columns

    # 只处理数值列 —— 非数值列（如攻击类型文本）不该被填充逻辑碰
    for col in numeric_cols:
        # 分两步：先 inf → NaN，再 NaN → 0。
        # 顺序不能反：直接 fillna 不会处理 inf。
        df[col] = df[col].replace([np.inf, -np.inf], np.nan)

    if len(numeric_cols) > 0:
        df[numeric_cols] = df[numeric_cols].fillna(0)

    return df


def split_by_label(df: pd.DataFrame, n_per_class: int | None = None):
    """按标签拆成 (正常, 攻击) 两个 DataFrame。

    Args:
        n_per_class: 每类最多取多少行。None 表示全取。
                     用于演示场景快速生成小子集。
    """
    col = label_column(df)
    is_benign = df[col].astype(str).str.strip().str.upper() == "BENIGN"

    normal = df[is_benign]
    attack = df[~is_benign]

    if n_per_class is not None:
        normal = normal.head(n_per_class)
        attack = attack.head(n_per_class)

    return normal, attack


def load_raw_files(raw_dir: Path = RAW_DIR) -> pd.DataFrame:
    """读取 raw 目录下所有 CSV 并合并。"""
    files = sorted(raw_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(
            f"{raw_dir} 下没有 CSV 文件。请先按 {raw_dir}/README.md 的说明下载数据。"
        )
    frames = []
    for f in files:
        df = pd.read_csv(f, low_memory=False)
        df = normalize_columns(df)
        print(f"  读取 {f.name}: {len(df):,} 行")
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="CICIDS2017 数据准备")
    parser.add_argument("--sample", type=int, default=None, help="每类采样行数（不指定则全量）")
    args = parser.parse_args()

    print("=== 1. 读取原始文件 ===")
    data = load_raw_files()
    print(f"合计: {len(data):,} 行")

    print("\n=== 2. 清洗特征（处理 inf/NaN，保留极端值与全部行）===")
    before_inf = np.isinf(data.select_dtypes(include=[np.number]).to_numpy()).sum()
    data = clean_features(data)
    after_inf = np.isinf(data.select_dtypes(include=[np.number]).to_numpy()).sum()
    print(f"  inf 数量: {before_inf} → {after_inf}")
    print(f"  行数保持: {len(data):,}")

    print("\n=== 3. 按标签拆分 ===")
    col = label_column(data)
    normal, attack = split_by_label(data, n_per_class=args.sample)
    print(f"  正常: {len(normal):,} | 攻击: {len(attack):,}")

    print("\n=== 4. 标签分布 ===")
    print(data[col].value_counts().to_string())

    print("\n=== 5. 写出 ===")
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    combined = pd.concat([normal, attack], ignore_index=True)
    out = PROCESSED_DIR / ("sample.parquet" if args.sample else "full.parquet")
    combined.to_parquet(out, index=False)
    print(f"  已写出: {out} ({out.stat().st_size / 1024 / 1024:.1f} MB)")
    print("\n注意：归一化不在此处做（必须只用训练集拟合，避免 data leakage）。")


if __name__ == "__main__":
    main()
