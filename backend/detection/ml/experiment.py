"""ML 实验 CLI。

用途：把训练、对比、严格评估串成一条命令，产出报告可直接引用的结果。

为什么做成 CLI 而不是写死脚本：
    实验需要反复跑（换参数、换子集、换模型），CLI 参数化比改代码方便。
    也便于把结果重定向到文件保存下来（报告素材）。

用法：
    # 多模型对比（标准随机切分）
    uv run python -m backend.detection.ml.experiment compare

    # 特征重要性分析
    uv run python -m backend.detection.ml.experiment importance

    # 严格评估：按攻击类型留一 + 与随机切分对比
    uv run python -m backend.detection.ml.experiment strict

    # 训练并保存主模型（供系统运行时推理用）
    uv run python -m backend.detection.ml.experiment train --out models/
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from backend.detection.ml.evaluation import (
    feature_importances,
    leave_one_attack_out,
    random_split,
)
from backend.detection.ml.train import train_models

DATA = Path("data/processed/full.parquet")
MODELS_DIR = Path("models")


def _load(data_path: Path) -> pd.DataFrame:
    if not data_path.exists():
        raise FileNotFoundError(
            f"{data_path} 不存在。请先运行：uv run python scripts/prepare_data.py"
        )
    return pd.read_parquet(data_path)


def _xy(df: pd.DataFrame, label_column: str = "Label"):
    cols = [c for c in df.columns if c != label_column]
    X = df[cols].to_numpy(dtype=float)
    y = (df[label_column].astype(str).str.upper() != "BENIGN").astype(int).to_numpy()
    return X, y, cols


def cmd_compare(data_path: Path) -> None:
    """多模型对比（随机切分）。"""
    df = _load(data_path)
    print(f"数据: {len(df):,} 行")

    X, y, _ = _xy(df)
    models = ["xgboost", "random_forest", "lightgbm", "logistic"]
    print(f"\n对比模型: {', '.join(models)}（随机切分 70/30）\n")

    results = train_models(X, y, model_names=models)

    header = f"{'模型':<16}{'accuracy':>10}{'precision':>11}{'recall':>10}{'f1':>10}"
    print(header)
    print("-" * len(header))
    for name, m in results.items():
        print(
            f"{name:<16}{m['accuracy']:>10.4f}{m['precision']:>11.4f}"
            f"{m['recall']:>10.4f}{m['f1']:>10.4f}"
        )

    out = Path("data/processed/experiment_compare.json")
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\n结果已保存: {out}")


def cmd_importance(data_path: Path, top_k: int) -> None:
    """特征重要性分析 —— 检查模型是否依赖泄漏特征。"""
    df = _load(data_path)
    X, y, cols = _xy(df)
    print(f"数据: {len(df):,} 行, {len(cols)} 个特征\n")

    imp = feature_importances(X, y, feature_names=cols, top_k=top_k)
    print(f"Top {top_k} 重要特征：\n")
    print(f"{'特征':<32}{'重要性':>10}")
    print("-" * 42)
    for name, score in imp:
        print(f"{name:<32}{score:>10.4f}")

    print("\n判读提示：若 Destination Port 等与标签强相关的特征占据主导，")
    print("说明模型的准确率部分来自**特征泄漏**而非学到攻击行为模式。")
    print("此分析用于报告的『评估诚实性』一节。")


def cmd_strict(data_path: Path) -> None:
    """严格评估：留一验证 vs 随机切分对比。"""
    df = _load(data_path)
    print(f"数据: {len(df):,} 行")
    attacks = df[df["Label"] != "BENIGN"]["Label"].value_counts()
    print(f"攻击类型: {dict(attacks)}\n")

    print("=== 1. 标准随机切分（可与文献对比的基线）===")
    base = random_split(df)
    print(f"  accuracy={base['accuracy']:.4f}  precision={base['precision']:.4f}")
    print(f"  recall  ={base['recall']:.4f}  f1       ={base['f1']:.4f}")

    print("\n=== 2. 按攻击类型留一验证（真实泛化能力）===")
    print("  说明：训练时**不含**该类攻击，测试只考它 —— 模拟零日检测\n")
    loo = leave_one_attack_out(df)
    print(f"  {'攻击类型':<16}{'检出率':>10}{'漏报数':>10}{'样本数':>10}")
    print("  " + "-" * 44)
    for attack, m in loo.items():
        print(f"  {attack:<16}{m['recall']:>10.4f}{m['missed']:>10,}{m['n_samples']:>10,}")
    avg = float(np.mean([m["recall"] for m in loo.values()]))
    print(f"\n  平均检出率: {avg:.4f}")

    print("\n=== 3. 差距说明 ===")
    gap = base["f1"] - avg
    print(f"  随机切分 f1 ({base['f1']:.4f}) - 留一平均 recall ({avg:.4f}) = {gap:+.4f}")
    if gap > 0.05:
        print("  → 差距显著，**印证了 CICIDS2017 的评估虚高**：")
        print("    随机切分下模型受益于同类样本泄漏，指标高于真实泛化能力。")
    else:
        print("  → 差距不显著。")

    out = Path("data/processed/experiment_strict.json")
    out.write_text(
        json.dumps(
            {"random_split": base, "leave_one_out": loo, "gap": gap}, indent=2, ensure_ascii=False
        )
    )
    print(f"\n结果已保存: {out}")


def cmd_train(data_path: Path, out_dir: Path) -> None:
    """训练并保存主模型（供系统运行时加载）。"""
    import joblib

    from backend.detection.ml.train import train_binary

    df = _load(data_path)
    X, y, cols = _xy(df)
    print(f"数据: {len(df):,} 行, {len(cols)} 个特征")

    print("\n训练主模型 (xgboost)...")
    model, metrics = train_binary(X, y)

    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / "xgb_binary.joblib"
    joblib.dump(model, model_path)

    # 特征名必须一起存：推理时要用它对齐输入列的顺序。
    # 只存模型不存特征名的话，推理阶段列顺序错位会静默产生错误预测。
    meta = {"feature_names": cols, "metrics": metrics, "n_samples": int(len(df))}
    (out_dir / "xgb_binary.meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))

    print(f"\n模型已保存: {model_path}")
    print(f"元数据: {out_dir / 'xgb_binary.meta.json'}")
    print(f"指标: accuracy={metrics['accuracy']:.4f} f1={metrics['f1']:.4f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ML 实验")
    parser.add_argument("--data", type=Path, default=DATA)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("compare", help="多模型对比")
    p_imp = sub.add_parser("importance", help="特征重要性分析")
    p_imp.add_argument("--top-k", type=int, default=20)
    sub.add_parser("strict", help="严格评估（留一验证）")
    p_train = sub.add_parser("train", help="训练并保存主模型")
    p_train.add_argument("--out", type=Path, default=MODELS_DIR)

    args = parser.parse_args()

    if args.command == "compare":
        cmd_compare(args.data)
    elif args.command == "importance":
        cmd_importance(args.data, args.top_k)
    elif args.command == "strict":
        cmd_strict(args.data)
    elif args.command == "train":
        cmd_train(args.data, args.out)


if __name__ == "__main__":
    main()
