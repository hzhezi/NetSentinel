"""手动触发深度调查的 API 测试。

用途：分析人员在告警详情页点击"深度调查"——
Human-in-the-loop 的入口，允许人工推翻 L1 的"不必深入"。

设计取舍：
    调查耗时长（实测 6-9 秒）且要花钱，因此**同步执行并等待**，
    而不是丢后台任务。理由：用户体验上"点了等几秒看到结果"
    比"点了不知道什么时候好"更清晰；
    且单次调查的耗时在 HTTP 超时范围内（默认 15 秒足够）。

    若将来要支持批量调查，应改为后台任务 + 轮询/推送结果。
"""

import uuid
from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient

from backend.api.v1.routes import alerts as alerts_route
from backend.core.database import get_session
from backend.main import create_app
from backend.repositories import alert_repository as alert_repo
from backend.repositories import triage_repository as triage_repo
from backend.schemas.alert import AlertCreate


@pytest.fixture
def app(pg_session):
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


def _verdict(**overrides) -> dict:
    data = {
        "verdict": "true_positive",
        "severity": "high",
        "confidence": 90,
        "summary": "调查确认是真实攻击。",
        "mitre_techniques": ["T1190"],
        "recommended_actions": ["封禁 IP"],
        "evidence_trail": [
            {
                "type": "tool_call",
                "tool": "lookup_ip_reputation",
                "result": {"reputation": "malicious"},
            },
            {"type": "verdict", "input": {"verdict": "true_positive"}},
        ],
    }
    data.update(overrides)
    return data


async def _seed(pg_session) -> object:
    return await alert_repo.create(
        pg_session,
        AlertCreate(
            source_engine="suricata",
            detected_at=datetime.now(UTC),
            src_ip="45.33.32.156",
            dst_ip="192.168.10.5",
            signature="Possible SQL Injection",
            severity="high",
            confidence=0.9,
        ),
    )


# ── 手动触发 ───────────────────────────────────────────────────


async def test_investigate_returns_result(client, pg_session, monkeypatch):
    """点击深度调查应返回结论与证据链。"""
    row = await _seed(pg_session)

    async def fake_investigate(alert_id, session):
        # 直接落一条 L2 结果，模拟调查完成
        return await triage_repo.create(
            session,
            alert_id=alert_id,
            stage="investigation",
            triage=_verdict(),
            usage={"prompt_tokens": 5000, "completion_tokens": 800},
            model="deepseek-reasoner",
        )

    monkeypatch.setattr(alerts_route, "_run_investigation", fake_investigate)

    r = await client.post(f"/api/v1/alerts/{row.id}/investigate")

    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "true_positive"
    assert body["stage"] == "investigation"
    assert len(body["evidence_trail"]) == 2


async def test_investigate_404_for_missing_alert(client):
    r = await client.post(f"/api/v1/alerts/{uuid.uuid4()}/investigate")
    assert r.status_code == 404


async def test_investigate_accepts_invalid_uuid_as_404(client):
    r = await client.post("/api/v1/alerts/not-a-uuid/investigate")
    assert r.status_code == 404


async def test_investigate_degrades_when_llm_unavailable(client, pg_session, monkeypatch):
    """未配置 LLM 时，调查接口应降级返回 needs_human_review 而非 500。

    安全系统的原则：功能不可用时要**明确降级**，
    而不是给用户一个报错页面让人以为系统坏了。
    """
    row = await _seed(pg_session)

    async def fake_investigate(alert_id, session):
        return await triage_repo.create(
            session,
            alert_id=alert_id,
            stage="investigation",
            triage={
                "verdict": "needs_human_review",
                "severity": "medium",
                "confidence": 0,
                "summary": "深度调查器未配置，需人工复核。",
                "evidence_trail": [],
            },
            error="not configured",
        )

    monkeypatch.setattr(alerts_route, "_run_investigation", fake_investigate)

    r = await client.post(f"/api/v1/alerts/{row.id}/investigate")
    assert r.status_code == 200
    assert r.json()["verdict"] == "needs_human_review"


# ── 证据链查询 ────────────────────────────────────────────────


async def test_triage_returns_evidence_trail(client, pg_session):
    """研判结果接口应返回证据链，供前端渲染时间线。"""
    row = await _seed(pg_session)
    await triage_repo.create(
        pg_session,
        alert_id=row.id,
        stage="investigation",
        triage=_verdict(),
        usage={},
    )

    r = await client.get(f"/api/v1/alerts/{row.id}/triage")
    body = r.json()

    assert len(body) == 1
    trail = body[0]["evidence_trail"]
    assert len(trail) == 2
    assert trail[0]["tool"] == "lookup_ip_reputation"
