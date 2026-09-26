"""评测结果 API 的测试。

用途：把 scripts/run_eval.py 产出的评测报告暴露给前端展示 ——
答辩与报告需要能"看到数据"，而不只是终端里的一段输出。

设计要点：
    - 评测是**离线跑**的（调真实 LLM，慢且花钱），因此接口只**读取**
      已有报告文件，不提供"在线触发评测"。
      在线触发会让用户以为点一下就能出结果，实际要等几分钟且产生费用。
    - 报告不存在时返回明确的空状态，而不是 500。
"""

import json

import pytest
from httpx import ASGITransport, AsyncClient

from backend.main import create_app


@pytest.fixture
def app(tmp_path, monkeypatch):
    """构造应用，并把评测目录指向临时路径。"""
    from backend.api.v1.routes import evaluation as eval_route

    monkeypatch.setattr(eval_route, "EVAL_DIR", tmp_path)
    return create_app()


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def _write_report(tmp_path, **overrides) -> dict:
    report = {
        "run_at": "2026-09-26T12:00:00+00:00",
        "models": {"triage": "deepseek-chat", "investigation": "deepseek-reasoner"},
        "sample_size": 9,
        "results": {
            "l1": {
                "metrics": {
                    "total": 9,
                    "agreement": 0.0,
                    "decisive_count": 0,
                    "needs_human_review_count": 9,
                    "needs_human_review_rate": 1.0,
                    "confusion": {},
                    "total_tokens": 7380,
                    "avg_latency_ms": 0,
                },
                "detail": [
                    {
                        "scenario": "ssh_brute_force",
                        "signature": "SSH Brute Force",
                        "ground_truth": "true_positive",
                        "predicted": "needs_human_review",
                        "confidence": 45,
                    },
                ],
            },
            "l2": {
                "metrics": {
                    "total": 9,
                    "agreement": 1.0,
                    "decisive_count": 9,
                    "needs_human_review_count": 0,
                    "needs_human_review_rate": 0.0,
                    "confusion": {"true_positive": {"true_positive": 9}},
                    "total_tokens": 76615,
                    "avg_latency_ms": 8125,
                },
                "detail": [
                    {
                        "scenario": "ssh_brute_force",
                        "signature": "SSH Brute Force",
                        "ground_truth": "true_positive",
                        "predicted": "true_positive",
                        "confidence": 88,
                        "tools_used": ["lookup_ip_reputation"],
                    },
                ],
            },
        },
    }
    report.update(overrides)
    (tmp_path / "eval_report.json").write_text(
        json.dumps(report, ensure_ascii=False), encoding="utf-8"
    )
    return report


# ── 读取报告 ───────────────────────────────────────────────────


async def test_get_latest_eval_report(client, tmp_path):
    _write_report(tmp_path)

    r = await client.get("/api/v1/evaluation/report")
    assert r.status_code == 200
    body = r.json()

    assert body["sample_size"] == 9
    assert body["results"]["l1"]["metrics"]["agreement"] == 0.0
    assert body["results"]["l2"]["metrics"]["agreement"] == 1.0


async def test_report_returns_empty_when_missing(client):
    """报告不存在时返回明确空状态，而不是 500。

    前端据此显示"尚未运行评测"的提示 ——
    而不是弹一个错误让人以为系统坏了。
    """
    r = await client.get("/api/v1/evaluation/report")
    assert r.status_code == 200
    assert r.json()["available"] is False
    assert r.json()["message"]


async def test_report_includes_detail_for_drill_down(client, tmp_path):
    """要能拿到逐条明细 —— 前端需要展示"模型判了什么、真值是什么"。"""
    _write_report(tmp_path)
    r = await client.get("/api/v1/evaluation/report")
    detail = r.json()["results"]["l2"]["detail"]

    assert len(detail) == 1
    assert detail[0]["ground_truth"] == "true_positive"
    assert detail[0]["predicted"] == "true_positive"


async def test_available_flag_true_when_exists(client, tmp_path):
    _write_report(tmp_path)
    r = await client.get("/api/v1/evaluation/report")
    assert r.json()["available"] is True


async def test_corrupted_report_returns_error_state(client, tmp_path):
    """报告文件损坏时返回明确错误，而不是 500。

    可能的原因：评测被中途打断、文件被手工编辑出错。
    明确报错比让前端崩掉更友好。
    """
    (tmp_path / "eval_report.json").write_text("{ 这不是合法 JSON", encoding="utf-8")

    r = await client.get("/api/v1/evaluation/report")
    assert r.status_code == 200
    assert r.json()["available"] is False
