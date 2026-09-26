"""日报 API 的测试。

日报 = 统计汇总（数据库聚合） + LLM 写成人话。
测试用假 LLM，不真实调用。
"""

from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient

from backend.api.v1.routes import reports as reports_route
from backend.core.database import get_session
from backend.main import create_app
from backend.repositories import alert_repository as alert_repo
from backend.schemas.alert import AlertCreate


class FakeLLM:
    def __init__(self, text: str = "【安全日报】今日态势平稳。", raise_error: bool = False):
        self.text = text
        self.raise_error = raise_error
        self.calls: list[dict] = []
        self.last_usage = {"prompt_tokens": 300, "completion_tokens": 150}

    def complete_text(self, system: str, user: str) -> str:
        self.calls.append({"system": system, "user": user})
        if self.raise_error:
            from backend.agents.llm_client import LLMError

            raise LLMError("模拟故障")
        return self.text


@pytest.fixture
def app(pg_session, monkeypatch):
    # 让日报路由用假 LLM，避免真实调用
    monkeypatch.setattr(reports_route, "_build_llm", lambda: FakeLLM())
    application = create_app()

    async def _override():
        yield pg_session

    application.dependency_overrides[get_session] = _override
    return application


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _seed(pg_session, **overrides):
    data = {
        "source_engine": "suricata",
        "detected_at": datetime.now(UTC),
        "src_ip": "45.33.32.156",
        "dst_ip": "192.168.10.5",
        "signature": "SQL Injection",
        "severity": "high",
        "confidence": 0.9,
    }
    data.update(overrides)
    return await alert_repo.create(pg_session, AlertCreate(**data))


# ── 统计接口 ───────────────────────────────────────────────────


async def test_stats_empty(client):
    r = await client.get("/api/v1/reports/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["alerts"]["total"] == 0


async def test_stats_aggregates_by_severity(client, pg_session):
    await _seed(pg_session, severity="critical", signature="A")
    await _seed(pg_session, severity="high", signature="B")
    await _seed(pg_session, severity="high", signature="C")

    r = await client.get("/api/v1/reports/stats")
    by_sev = r.json()["alerts"]["by_severity"]

    assert by_sev["high"] == 2
    assert by_sev["critical"] == 1


async def test_stats_top_sources(client, pg_session):
    for _ in range(3):
        await _seed(pg_session, src_ip="1.1.1.1", signature="X")
    await _seed(pg_session, src_ip="2.2.2.2", signature="Y")

    r = await client.get("/api/v1/reports/stats")
    top = r.json()["alerts"]["top_sources"]

    assert top[0]["src_ip"] == "1.1.1.1"
    assert top[0]["count"] == 3


async def test_stats_includes_notable_high_severity(client, pg_session):
    """重点事件应只含高严重度 —— 日报需要聚焦。"""
    await _seed(pg_session, severity="critical", signature="CriticalThing")
    await _seed(pg_session, severity="low", signature="LowThing")

    r = await client.get("/api/v1/reports/stats")
    notable = r.json()["notable_alerts"]

    assert len(notable) == 1
    assert notable[0]["signature"] == "CriticalThing"


async def test_stats_respects_time_window(client, pg_session):
    """时间窗过滤：超出窗口的告警不计入。"""
    from datetime import timedelta

    await _seed(
        pg_session, detected_at=datetime.now(UTC) - timedelta(hours=48), signature="OldAlert"
    )
    await _seed(pg_session, detected_at=datetime.now(UTC), signature="RecentAlert")

    r = await client.get("/api/v1/reports/stats", params={"hours": 24})
    # 48 小时前那条不该计入
    assert r.json()["alerts"]["total"] == 1


# ── 日报生成 ───────────────────────────────────────────────────


async def test_daily_report_returns_content(client, pg_session):
    await _seed(pg_session)

    r = await client.get("/api/v1/reports/daily")
    assert r.status_code == 200
    body = r.json()

    assert body["report"]
    assert body["generated_by_llm"] is True
    assert body["stats"]["alerts"]["total"] == 1


async def test_daily_report_degrades_on_llm_failure(client, pg_session, monkeypatch):
    """LLM 失败时返回模板日报，仍含关键数字。"""
    monkeypatch.setattr(reports_route, "_build_llm", lambda: FakeLLM(raise_error=True))
    await _seed(pg_session, severity="critical")

    r = await client.get("/api/v1/reports/daily")
    body = r.json()

    assert body["generated_by_llm"] is False
    assert body["error"] is not None
    assert "1" in body["report"]  # 模板日报含总数


async def test_daily_report_without_llm_configured(client, pg_session, monkeypatch):
    """未配置 LLM 时同样返回模板日报，不报错。"""
    monkeypatch.setattr(reports_route, "_build_llm", lambda: None)
    await _seed(pg_session)

    r = await client.get("/api/v1/reports/daily")
    body = r.json()

    assert r.status_code == 200
    assert body["generated_by_llm"] is False
    assert body["report"]


async def test_daily_report_empty_period(client):
    """无告警时段也要能出日报。"""
    r = await client.get("/api/v1/reports/daily")
    assert r.status_code == 200
    assert r.json()["report"]


async def test_invalid_hours_rejected(client):
    r = await client.get("/api/v1/reports/daily", params={"hours": 0})
    assert r.status_code == 422
