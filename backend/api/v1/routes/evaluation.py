"""评测结果 API。

用途：把 scripts/run_eval.py 的产出暴露给前端 ——
答辩与报告需要"看到数据"，而不只是终端输出。

设计取舍：**只读，不提供在线触发评测**。
    评测要调真实 LLM，单次几分钟且产生费用。
    提供"点一下就跑"的接口会让用户误以为很快，
    实际会超时且账单不可控。
    跑评测是**离线动作**（CLI），这里只负责展示结果。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog
from fastapi import APIRouter

log = structlog.get_logger(__name__)

router = APIRouter()

# 评测报告目录（相对项目根）。
# 测试通过 monkeypatch 替换它以指向临时路径。
EVAL_DIR = Path("data/eval")
REPORT_FILE = "eval_report.json"


@router.get("/report")
async def get_report() -> dict[str, Any]:
    """返回最近一次评测报告。

    三种情况都返回 200（而非报错），用 available 字段区分：
        存在且合法   → {"available": true, ...报告内容}
        不存在       → {"available": false, "message": "尚未运行评测..."}
        文件损坏     → {"available": false, "message": "报告文件损坏..."}

    为什么不用 404/500：
        前端只需判断 available 就能决定渲染数据还是空状态；
        用 HTTP 状态码会让前端写一堆异常分支，且"没跑过评测"
        本来就不是错误状态。
    """
    path = EVAL_DIR / REPORT_FILE

    if not path.exists():
        return {
            "available": False,
            "message": ("尚未运行评测。请先执行：\nuv run python scripts/run_eval.py --with-l2"),
        }

    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        # 可能原因：评测中途被打断、文件被手工编辑出错
        log.warning("eval_report_unreadable", error=str(exc))
        return {
            "available": False,
            "message": f"评测报告文件无法读取（{exc}）。请在本地重新运行评测。",
        }

    return {"available": True, **report}


@router.get("/summary")
async def get_summary() -> dict[str, Any]:
    """只返回两级的核心指标，供仪表盘或概览处轻量展示。

    与 /report 分开的原因：完整报告含逐条明细（几十 KB），
    概览场景不需要 —— 单独接口可避免不必要的数据传输。
    """
    path = EVAL_DIR / REPORT_FILE
    if not path.exists():
        return {"available": False}

    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"available": False}

    results = report.get("results", {})
    summary: dict[str, Any] = {
        "available": True,
        "run_at": report.get("run_at"),
        "sample_size": report.get("sample_size"),
        "models": report.get("models"),
    }
    for level in ("l1", "l2"):
        metrics = results.get(level, {}).get("metrics")
        if metrics:
            summary[level] = {
                "agreement": metrics.get("agreement"),
                "needs_human_review_rate": metrics.get("needs_human_review_rate"),
                "total_tokens": metrics.get("total_tokens"),
                "avg_latency_ms": metrics.get("avg_latency_ms"),
            }
    return summary
