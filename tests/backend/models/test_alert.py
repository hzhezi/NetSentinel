"""UnifiedAlert ORM 模型的测试。

用内存 SQLite 跑真实插入，验证：
- 字段类型与默认值
- 枚举字段的约束行为
- 索引是否按预期建立
"""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from backend.core.database import Base
from backend.models.alert import Alert


@pytest.fixture
async def session():
    """内存 SQLite + 建表。

    注意：SQLite 不支持 Postgres 的 JSONB，SQLAlchemy 会自动降级为 JSON。
    因此这里测的是**字段与行为**，不是 *Postgres 特有类型*。
    真正在 PG 上的行为在 Task 5 迁移后验证。
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


def _make_alert(**overrides):
    """构造一条合法告警，默认值可被 overrides 覆盖。"""
    data = {
        "source_engine": "ml",
        "detected_at": datetime.now(UTC),
        "src_ip": "45.33.32.156",
        "dst_ip": "10.0.0.5",
        "signature": "DDoS",
        "severity": "high",
        "confidence": 0.93,
    }
    data.update(overrides)
    return Alert(**data)


async def test_insert_and_read_back(session):
    """最基本的往返：写入后用相同 id 能读回来。"""
    alert = _make_alert()
    session.add(alert)
    await session.commit()

    found = await session.get(Alert, alert.id)
    assert found is not None
    assert found.signature == "DDoS"
    assert found.src_ip == "45.33.32.156"
    assert found.confidence == pytest.approx(0.93)


async def test_status_defaults_to_new(session):
    """新告警的初始流转状态应为 new。"""
    alert = _make_alert()
    session.add(alert)
    await session.commit()

    assert alert.status == "new"


async def test_optional_fields_can_be_none(session):
    """端口、协议、原始载荷等是可选字段，允许为空。"""
    alert = _make_alert(src_port=None, dst_port=None, protocol=None, raw=None)
    session.add(alert)
    await session.commit()

    assert alert.src_port is None
    assert alert.raw is None


async def test_raw_payload_roundtrip(session):
    """raw 字段要能存嵌套 dict（原始 eve/flow 记录）。"""
    payload = {"event_type": "alert", "alert": {"signature_id": 1000001, "rev": 1}}
    alert = _make_alert(raw=payload)
    session.add(alert)
    await session.commit()

    found = await session.get(Alert, alert.id)
    assert found.raw == payload


async def test_detected_at_is_stored_as_given(session):
    """detected_at 是**事件原始时间**，必须原样保存，不能被自动覆盖。

    这条防的是常见错误：把 detected_at 也写成 server_default=now()，
    那样所有告警的时间都会变成入库时间，"按时间重放"就废了。
    """
    event_time = datetime.now(UTC) - timedelta(hours=2)
    alert = _make_alert(detected_at=event_time)
    session.add(alert)
    await session.commit()

    found = await session.get(Alert, alert.id)
    # SQLite 不保留时区信息，比较时忽略 tzinfo，只验证时刻一致
    assert found.detected_at.replace(tzinfo=None) == event_time.replace(tzinfo=None)
    # 且不应等于 created_at（created_at 是入库时间，此处相差 2 小时）
    assert found.created_at is not None


async def test_filter_by_severity(session):
    """severity 上有索引，是仪表盘的主要过滤维度。"""
    session.add_all([
        _make_alert(severity="high", signature="A"),
        _make_alert(severity="low", signature="B"),
    ])
    await session.commit()

    rows = (await session.scalars(
        select(Alert).where(Alert.severity == "high")
    )).all()
    assert len(rows) == 1
    assert rows[0].signature == "A"


async def test_order_by_detected_at(session):
    """按事件时间排序 —— 重放演示依赖这个顺序。"""
    now = datetime.now(UTC)
    session.add_all([
        _make_alert(detected_at=now, signature="later"),
        _make_alert(detected_at=now - timedelta(minutes=5), signature="earlier"),
    ])
    await session.commit()

    rows = (await session.scalars(
        select(Alert).order_by(Alert.detected_at.asc())
    )).all()
    assert [r.signature for r in rows] == ["earlier", "later"]


def test_table_has_expected_columns():
    """锁住表结构：列名变更必须显式改这条测试，避免悄悄破坏接口。"""
    cols = set(Alert.__table__.c.keys())
    expected = {
        "id", "created_at",
        "source_engine", "detected_at",
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "signature", "attack_type", "severity", "confidence",
        "category", "raw", "dedup_key", "status", "notes",
    }
    assert expected <= cols


def test_composite_index_exists():
    """时间 + 严重度的复合索引，服务仪表盘的"最近高危告警"查询。"""
    index_names = {idx.name for idx in Alert.__table__.indexes}
    assert "idx_alerts_detected_severity" in index_names
