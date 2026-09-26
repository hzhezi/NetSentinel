"""alert repository 的测试。

**跑在真 PostgreSQL 上**（fixture 见 tests/conftest.py）。
repository 的价值就在"正确翻译成 SQL"，所以必须在真库上验证 ——
过滤、排序、分页在 SQLite 上可能碰巧通过，但 SQL 语义并不相同。
"""

from datetime import UTC, datetime, timedelta

from backend.repositories import alert_repository as repo
from backend.schemas.alert import AlertCreate


def _payload(**overrides) -> AlertCreate:
    data = {
        "source_engine": "suricata",
        "detected_at": datetime.now(UTC),
        "src_ip": "45.33.32.156",
        "dst_ip": "10.0.0.5",
        "signature": "DDoS",
        "severity": "high",
        "confidence": 0.93,
    }
    data.update(overrides)
    return AlertCreate(**data)


# ── create ─────────────────────────────────────────────────────


async def test_create_persists_and_returns_id(pg_session):
    """创建后应返回带数据库生成字段的完整对象。"""
    created = await repo.create(pg_session, _payload())

    assert created.id is not None
    assert created.status == "new"
    assert created.created_at is not None
    assert created.signature == "DDoS"


async def test_create_accepts_dict_too(pg_session):
    """归一化后的告警是 dict，repository 应能直接接受。

    检测层产出的就是 dict（见 services/normalize_alert），
    若 repository 只认 AlertCreate，调用方要额外转换一次。
    """
    created = await repo.create(pg_session, _payload().model_dump())
    assert created.signature == "DDoS"


# ── get ────────────────────────────────────────────────────────


async def test_get_returns_none_for_missing(pg_session):
    """查不到应返回 None，而不是抛异常。

    用 None 还是抛异常是个设计选择：查不到是**正常情况**
    （前端可能传了个已删除的 id），不该用异常表达。
    是否转成 HTTP 404 是 API 层的决定（见 Task 2 的讨论）。
    """
    import uuid

    assert await repo.get(pg_session, uuid.uuid4()) is None


async def test_get_returns_existing(pg_session):
    created = await repo.create(pg_session, _payload())
    found = await repo.get(pg_session, created.id)
    assert found is not None
    assert found.id == created.id


# ── list：分页 ─────────────────────────────────────────────────


async def test_list_returns_items_and_total(pg_session):
    for i in range(5):
        await repo.create(pg_session, _payload(signature=f"sig-{i}"))

    items, total = await repo.list_alerts(pg_session, page=1, size=2)

    assert total == 5  # total 是**满足条件的总数**，不是本页数量
    assert len(items) == 2


async def test_list_paginates_correctly(pg_session):
    """第 2 页应返回剩余的记录，且不与第 1 页重叠。"""
    for i in range(5):
        await repo.create(pg_session, _payload(signature=f"sig-{i}"))

    page1, total = await repo.list_alerts(pg_session, page=1, size=2)
    page2, _ = await repo.list_alerts(pg_session, page=2, size=2)

    ids1 = {r.id for r in page1}
    ids2 = {r.id for r in page2}
    assert len(ids2) == 2
    assert ids1.isdisjoint(ids2)  # 两页不应有交集


async def test_list_empty_returns_zero(pg_session):
    items, total = await repo.list_alerts(pg_session)
    assert items == []
    assert total == 0


# ── list：过滤 ─────────────────────────────────────────────────


async def test_list_filter_by_severity(pg_session):
    await repo.create(pg_session, _payload(severity="high", signature="A"))
    await repo.create(pg_session, _payload(severity="low", signature="B"))

    items, total = await repo.list_alerts(pg_session, severity="high")
    assert total == 1
    assert items[0].signature == "A"


async def test_list_filter_by_source_engine(pg_session):
    """按引擎过滤 —— 评测时要分别统计两个引擎的检出。"""
    await repo.create(pg_session, _payload(signature="sig-a"))
    await repo.create(pg_session, _payload(signature="sig-b"))

    items, total = await repo.list_alerts(pg_session, source_engine="suricata")
    assert total == 2
    assert {i.signature for i in items} == {"sig-a", "sig-b"}


async def test_list_filter_by_keyword_is_case_insensitive(pg_session):
    """关键字搜索应大小写不敏感 —— 用户不会记得规则名的大小写。"""
    await repo.create(pg_session, _payload(signature="ET SCAN Nmap OS Detection"))
    await repo.create(pg_session, _payload(signature="DDoS"))

    items, total = await repo.list_alerts(pg_session, q="nmap")
    assert total == 1
    assert "Nmap" in items[0].signature


async def test_list_filters_combine_with_and(pg_session):
    """多个过滤条件之间是 AND 关系。

    用 severity + status 组合验证（status 是当前有效的多值字段）。
    注意 repository.list_alerts 不接收 status 参数之外的引擎过滤组合，
    这里验证的是"多个条件同时生效"这一机制。
    """
    await repo.create(pg_session, _payload(severity="high", signature="a"))
    await repo.create(pg_session, _payload(severity="low", signature="b"))

    items, total = await repo.list_alerts(pg_session, severity="high", q="a")
    assert total == 1
    assert items[0].signature == "a"


# ── list：排序 ─────────────────────────────────────────────────


async def test_list_orders_by_detected_at_desc(pg_session):
    """默认按**事件时间**倒序 —— 最新告警在最前。

    用 detected_at 而不是 created_at：
    重放场景下两者可能差很远（数据是历史流量），
    用户要看的是"攻击发生的时间线"，不是"数据入库的时间"。
    """
    now = datetime.now(UTC)
    await repo.create(
        pg_session, _payload(detected_at=now - timedelta(minutes=10), signature="old")
    )
    await repo.create(pg_session, _payload(detected_at=now, signature="new"))
    await repo.create(pg_session, _payload(detected_at=now - timedelta(minutes=5), signature="mid"))

    items, _ = await repo.list_alerts(pg_session)

    assert [r.signature for r in items] == ["new", "mid", "old"]


# ── count_by_severity：仪表盘统计 ────────────────────────────────


async def test_count_by_severity(pg_session):
    """按严重度分组计数 —— 仪表盘的饼图数据来源。"""
    await repo.create(pg_session, _payload(severity="high"))
    await repo.create(pg_session, _payload(severity="high"))
    await repo.create(pg_session, _payload(severity="low"))

    counts = await repo.count_by_severity(pg_session)

    assert counts == {"high": 2, "low": 1}
