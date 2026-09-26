"""重放 Worker 的测试。

Worker 是"编排层"：它把 Feeder / 解析 / 归一化 / 去重 / 落库 / 推送
串成一条链路。测试用真 PostgreSQL（落库）但用回调替代 WebSocket（推送），
因此不需要启动 Web 服务。

关键设计验证：
    - 正常路径：eve 里的告警被落库并逐条回调
    - 去重生效：重复告警不重复落库、不重复回调
    - 非 alert 事件被跳过
    - 单条失败不影响整批（安全系统的关键性质）
"""

import json

import pytest

from backend.repositories import alert_repository as repo
from backend.workers.replay import run_replay


class _SessionCtx:
    """把已有的 session 包装成 async 上下文管理器。

    run_replay 期望一个 session_factory（每次调用开一个新 session）。
    测试里我们复用同一个 pg_session —— 但**不能直接传它**，
    因为 `async with session_factory()` 要求返回上下文管理器。
    """

    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, *exc):
        return False


@pytest.fixture
def session_factory(pg_session):
    return lambda: _SessionCtx(pg_session)


def _eve_file(tmp_path, events: list[dict]):
    p = tmp_path / "eve.json"
    p.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return p


def _alert(ts: str, signature: str, src: str = "45.33.32.156") -> dict:
    return {
        "timestamp": ts,
        "event_type": "alert",
        "src_ip": src,
        "src_port": 52344,
        "dest_ip": "10.0.0.5",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "signature": signature,
            "signature_id": 1000002,
            "category": "Web Attack",
            "severity": 1,
        },
    }


# ── 正常路径 ───────────────────────────────────────────────────


async def test_replay_persists_alerts(tmp_path, pg_session, session_factory):
    eve = _eve_file(
        tmp_path,
        [
            _alert("2017-07-05T10:00:00+0000", "SQL Injection"),
            _alert("2017-07-05T10:00:01+0000", "SSH Brute Force"),
        ],
    )

    result = await run_replay(
        eve_path=eve,
        speed=1_000_000,
        session_factory=session_factory,
    )

    assert result["emitted"] == 2
    rows, total = await repo.list_alerts(pg_session)
    assert total == 2
    assert {r.signature for r in rows} == {"SQL Injection", "SSH Brute Force"}


async def test_replay_invokes_callback_per_alert(tmp_path, pg_session, session_factory):
    """每条落库的告警都应触发一次回调（推送用）。"""
    eve = _eve_file(
        tmp_path,
        [
            _alert("2017-07-05T10:00:00+0000", "A"),
            _alert("2017-07-05T10:00:01+0000", "B"),
        ],
    )
    received = []

    async def on_alert(payload):
        received.append(payload)

    await run_replay(
        eve_path=eve,
        speed=1_000_000,
        session_factory=session_factory,
        on_alert=on_alert,
    )

    assert len(received) == 2
    assert all(p["type"] == "new_alert" for p in received)
    # 回调里应带数据库生成的 id，前端要它去重
    assert all("id" in p["data"] for p in received)


async def test_replay_preserves_event_time(tmp_path, pg_session, session_factory):
    """落库的 detected_at 是**事件原始时间**，不是入库时间。"""
    eve = _eve_file(tmp_path, [_alert("2017-07-05T10:00:00+0000", "A")])

    await run_replay(eve_path=eve, speed=1_000_000, session_factory=session_factory)

    rows, _ = await repo.list_alerts(pg_session)
    assert rows[0].detected_at.year == 2017


# ── 去重 ───────────────────────────────────────────────────────


async def test_replay_deduplicates_repeated_alerts(tmp_path, pg_session, session_factory):
    """重复告警（同源同签名）只落库一次 —— 防告警风暴。"""
    eve = _eve_file(
        tmp_path,
        [
            _alert("2017-07-05T10:00:00+0000", "SQL Injection"),
            _alert("2017-07-05T10:00:01+0000", "SQL Injection"),  # 同源同签名
            _alert("2017-07-05T10:00:02+0000", "SQL Injection"),
        ],
    )

    result = await run_replay(
        eve_path=eve,
        speed=1_000_000,
        session_factory=session_factory,
    )

    assert result["emitted"] == 1
    assert result["deduplicated"] == 2
    _, total = await repo.list_alerts(pg_session)
    assert total == 1


async def test_different_source_not_deduplicated(tmp_path, pg_session, session_factory):
    """不同源 IP 命中同一规则不应合并 —— 是不同攻击者。"""
    eve = _eve_file(
        tmp_path,
        [
            _alert("2017-07-05T10:00:00+0000", "SQL Injection", src="1.1.1.1"),
            _alert("2017-07-05T10:00:01+0000", "SQL Injection", src="2.2.2.2"),
        ],
    )

    result = await run_replay(
        eve_path=eve,
        speed=1_000_000,
        session_factory=session_factory,
    )

    assert result["emitted"] == 2


# ── 跳过非告警 ──────────────────────────────────────────────────


async def test_replay_skips_non_alert_events(tmp_path, pg_session, session_factory):
    eve = _eve_file(
        tmp_path,
        [
            {"timestamp": "2017-07-05T10:00:00+0000", "event_type": "flow", "flow_id": 1},
            _alert("2017-07-05T10:00:01+0000", "Real Alert"),
            {"timestamp": "2017-07-05T10:00:02+0000", "event_type": "dns", "flow_id": 2},
        ],
    )

    result = await run_replay(
        eve_path=eve,
        speed=1_000_000,
        session_factory=session_factory,
    )

    assert result["emitted"] == 1


# ── 健壮性 ─────────────────────────────────────────────────────


async def test_replay_without_callback_works(tmp_path, pg_session, session_factory):
    """on_alert 是可选的 —— CLI 场景不需要推送。"""
    eve = _eve_file(tmp_path, [_alert("2017-07-05T10:00:00+0000", "A")])

    result = await run_replay(
        eve_path=eve,
        speed=1_000_000,
        session_factory=session_factory,
    )
    assert result["emitted"] == 1


async def test_replay_empty_eve_returns_zero(tmp_path, pg_session, session_factory):
    eve = _eve_file(tmp_path, [])
    result = await run_replay(
        eve_path=eve,
        speed=1_000_000,
        session_factory=session_factory,
    )
    assert result["emitted"] == 0


async def test_replay_continues_after_single_failure(tmp_path, pg_session, session_factory):
    """单条告警落库失败不应中断整批。

    安全系统的关键性质：宁可漏掉一条，也不能因为一条异常
    让整批重放（可能几万条）全部失败。
    """
    eve = _eve_file(
        tmp_path,
        [
            _alert("2017-07-05T10:00:00+0000", "Good 1"),
            _alert("2017-07-05T10:00:01+0000", "Good 2"),
        ],
    )

    original_create = repo.create
    call_count = {"n": 0}

    async def flaky_create(session, obj):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("simulated DB error")
        return await original_create(session, obj)

    import backend.workers.replay as replay_mod

    replay_mod.repo.create = flaky_create
    try:
        result = await run_replay(
            eve_path=eve,
            speed=1_000_000,
            session_factory=session_factory,
        )
    finally:
        replay_mod.repo.create = original_create

    # 第一条失败，第二条仍应成功
    assert result["emitted"] == 1
    assert result["errors"] == 1


# ── 抑制规则 ───────────────────────────────────────────────────


async def test_replay_skips_suppressed_alerts(tmp_path, pg_session, session_factory):
    """命中抑制规则的告警应被跳过（不落库、不回调）。"""
    from backend.services.suppression import SuppressionRule, SuppressionService

    eve = _eve_file(
        tmp_path,
        [
            _alert("2017-07-05T10:00:00+0000", "SQL Injection"),
            _alert("2017-07-05T10:00:01+0000", "ET SCAN Nmap", src="192.168.10.100"),
        ],
    )
    # 抑制内部扫描器（按 src_ip + signature_id 精确匹配）
    suppressions = SuppressionService(
        rules=[
            SuppressionRule(id=1, name="内部扫描器", src_ip="192.168.10.100", signature_id=1000002),
        ]
    )
    received = []

    async def on_alert(payload):
        received.append(payload)

    result = await run_replay(
        eve_path=eve,
        speed=1_000_000,
        session_factory=session_factory,
        on_alert=on_alert,
        suppressions=suppressions,
    )

    assert result["emitted"] == 1
    assert result["suppressed"] == 1
    assert len(received) == 1
    _, total = await repo.list_alerts(pg_session)
    assert total == 1


async def test_replay_without_suppressions_processes_all(tmp_path, pg_session, session_factory):
    """未配置抑制时所有告警正常处理。"""
    eve = _eve_file(tmp_path, [_alert("2017-07-05T10:00:00+0000", "A")])
    result = await run_replay(
        eve_path=eve,
        speed=1_000_000,
        session_factory=session_factory,
    )
    assert result["emitted"] == 1
    assert result["suppressed"] == 0
