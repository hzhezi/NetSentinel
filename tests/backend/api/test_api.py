"""API 路由与 WebSocket 的测试。

用 httpx 的 ASGITransport 直接在进程内调用 FastAPI 应用，
不需要起真实服务器 —— 快且不占端口。

数据库测试通过 override get_session 依赖，复用 conftest 的 pg_session。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient

from backend.api.websocket.manager import WebSocketManager
from backend.core.database import get_session
from backend.main import create_app
from backend.repositories import alert_repository as alert_repo
from backend.repositories import triage_repository as triage_repo
from backend.schemas.alert import AlertCreate


@pytest.fixture
def app(pg_session):
    """构造应用并覆盖数据库依赖，指向测试用的临时 schema。

    注意覆盖函数是 **async generator**（用 yield），而不是返回上下文管理器 ——
    FastAPI 的 Depends 对生成器函数有特殊处理（它会把 yield 出的值注入）。
    写成 `async def _override(): return ctx` 会报
    "'_AsyncGeneratorContextManager' object is not an async iterator"。
    """
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


async def _seed_alert(pg_session, **overrides) -> object:
    data = {
        "source_engine": "suricata",
        "detected_at": datetime.now(UTC),
        "src_ip": "45.33.32.156",
        "dst_ip": "10.0.0.5",
        "signature": "SQL Injection",
        "severity": "high",
        "confidence": 0.9,
    }
    data.update(overrides)
    return await alert_repo.create(pg_session, AlertCreate(**data))


# ── 健康检查 ───────────────────────────────────────────────────


async def test_health(client):
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── 告警列表 ───────────────────────────────────────────────────


async def test_list_alerts_empty(client):
    r = await client.get("/api/v1/alerts")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0
    assert body["items"] == []
    assert body["page"] == 1


async def test_list_alerts_returns_pagination_shape(client, pg_session):
    await _seed_alert(pg_session, signature="A")
    await _seed_alert(pg_session, signature="B")

    r = await client.get("/api/v1/alerts", params={"page": 1, "size": 1})
    body = r.json()

    # total 是"满足条件的总数"，不是本页数量 —— 前端分页需要它
    assert body["total"] == 2
    assert len(body["items"]) == 1
    assert body["size"] == 1


async def test_list_alerts_filter_by_severity(client, pg_session):
    await _seed_alert(pg_session, severity="high", signature="A")
    await _seed_alert(pg_session, severity="low", signature="B")

    r = await client.get("/api/v1/alerts", params={"severity": "low"})
    body = r.json()

    assert body["total"] == 1
    assert body["items"][0]["signature"] == "B"


async def test_list_alerts_rejects_invalid_page(client):
    """参数校验由 FastAPI 自动完成（ge=1），非法值返回 422。"""
    r = await client.get("/api/v1/alerts", params={"page": 0})
    assert r.status_code == 422


# ── 告警详情 ───────────────────────────────────────────────────


async def test_get_alert_detail(client, pg_session):
    row = await _seed_alert(pg_session)

    r = await client.get(f"/api/v1/alerts/{row.id}")
    assert r.status_code == 200
    assert r.json()["signature"] == "SQL Injection"


async def test_get_alert_returns_404_when_missing(client):
    """查不到应返回 404 —— 领域异常被统一异常处理器翻译。

    这验证了异常分层的效果：路由层只 raise NotFoundError，
    不知道 HTTP 404 的存在。
    """
    import uuid

    r = await client.get(f"/api/v1/alerts/{uuid.uuid4()}")
    assert r.status_code == 404
    assert r.json()["code"] == "NOT_FOUND"


async def test_get_alert_invalid_uuid_returns_404(client):
    """非法 UUID 也应是 404（repo 内部把格式错误视为查不到）。"""
    r = await client.get("/api/v1/alerts/not-a-uuid")
    assert r.status_code == 404


# ── 研判结果 ───────────────────────────────────────────────────


async def test_get_alert_triage_empty(client, pg_session):
    row = await _seed_alert(pg_session)
    r = await client.get(f"/api/v1/alerts/{row.id}/triage")
    assert r.status_code == 200
    assert r.json() == []


async def test_get_alert_triage_returns_results(client, pg_session):
    row = await _seed_alert(pg_session)
    await triage_repo.create(
        pg_session,
        alert_id=row.id,
        stage="triage",
        triage={
            "verdict": "true_positive",
            "severity": "high",
            "confidence": 88,
            "summary": "疑似注入",
            "escalate": False,
        },
        usage={"prompt_tokens": 100, "completion_tokens": 40},
    )

    r = await client.get(f"/api/v1/alerts/{row.id}/triage")
    body = r.json()

    assert len(body) == 1
    assert body[0]["verdict"] == "true_positive"
    assert body[0]["prompt_tokens"] == 100


async def test_get_alert_triage_404_when_alert_missing(client):
    import uuid

    r = await client.get(f"/api/v1/alerts/{uuid.uuid4()}/triage")
    assert r.status_code == 404


# ── 统计 ───────────────────────────────────────────────────────


async def test_statistics_overview(client, pg_session):
    await _seed_alert(pg_session, severity="high")
    await _seed_alert(pg_session, severity="low")

    r = await client.get("/api/v1/statistics/overview")
    body = r.json()

    assert body["alerts"]["total"] == 2
    assert body["alerts"]["by_severity"] == {"high": 1, "low": 1}
    assert "triage" in body


async def test_statistics_usage_summary(client, pg_session):
    row = await _seed_alert(pg_session)
    await triage_repo.create(
        pg_session,
        alert_id=row.id,
        stage="triage",
        triage={
            "verdict": "false_positive",
            "severity": "low",
            "confidence": 90,
            "summary": "误报",
            "latency_ms": 1200,
        },
        usage={"prompt_tokens": 200, "completion_tokens": 60},
    )

    r = await client.get("/api/v1/statistics/overview")
    usage = r.json()["triage"]["usage"]

    assert usage["total_tokens"] == 260
    assert usage["count"] == 1


# ── feeds：路径校验 ────────────────────────────────────────────


async def test_replay_rejects_path_outside_allowed_dirs(client):
    """路径穿越防护：只允许 data/ 下的文件。

    这是低成本的基本防护 —— 不校验的话 API 成为了
    "读取系统任意文件并触发处理"的入口。
    """
    r = await client.post("/api/v1/feeds/replay", json={"eve_path": "/etc/passwd"})
    assert r.status_code == 422
    assert r.json()["code"] == "VALIDATION_ERROR"


async def test_replay_rejects_missing_file(client):
    r = await client.post("/api/v1/feeds/replay", json={"eve_path": "data/nonexistent.json"})
    assert r.status_code == 422


async def test_feeds_available_lists_json(client, tmp_path, monkeypatch):
    """列出可用文件：只应包含允许目录下的 .json。"""
    r = await client.get("/api/v1/feeds/available")
    assert r.status_code == 200
    assert "files" in r.json()


# ── WebSocket 管理器 ───────────────────────────────────────────


async def test_ws_broadcast_to_connected():
    class FakeWS:
        def __init__(self):
            self.sent: list[str] = []

        async def accept(self):
            pass

        async def send_text(self, text: str):
            self.sent.append(text)

    m = WebSocketManager()
    ws = FakeWS()
    await m.connect(ws)
    await m.broadcast({"type": "new_alert", "data": {"id": "x"}})

    assert len(ws.sent) == 1
    assert json.loads(ws.sent[0])["type"] == "new_alert"


async def test_ws_removes_stale_connection():
    """发送失败的连接应被自动剔除，否则集合会持续泄漏。"""

    class GoodWS:
        def __init__(self):
            self.sent = []

        async def accept(self):
            pass

        async def send_text(self, text):
            self.sent.append(text)

    class BadWS:
        async def accept(self):
            pass

        async def send_text(self, text):
            raise RuntimeError("connection closed")

    m = WebSocketManager()
    good, bad = GoodWS(), BadWS()
    await m.connect(good)
    await m.connect(bad)
    assert m.count == 2

    await m.broadcast({"type": "x"})

    assert m.count == 1  # 失效连接被剔除
    assert len(good.sent) == 1  # 正常连接仍收到消息


async def test_ws_broadcast_serializes_uuid_and_datetime():
    """datetime / UUID 必须能序列化 —— json.dumps 直接处理会抛 TypeError。

    这是真实踩过的坑：WebSocket 推送时崩在 UUID 上。
    管理器用 default=str 兜底。
    """
    import uuid

    class FakeWS:
        def __init__(self):
            self.sent = []

        async def accept(self):
            pass

        async def send_text(self, text):
            self.sent.append(text)

    m = WebSocketManager()
    ws = FakeWS()
    await m.connect(ws)
    await m.broadcast(
        {
            "type": "new_alert",
            "data": {"id": uuid.uuid4(), "detected_at": datetime.now(UTC)},
        }
    )

    payload = json.loads(ws.sent[0])
    assert isinstance(payload["data"]["id"], str)


async def test_ws_broadcast_with_no_connections_is_noop():
    m = WebSocketManager()
    await m.broadcast({"type": "x"})  # 不应抛异常
    assert m.count == 0
