"""UnifiedAlert ORM 模型的测试。

**跑在真 PostgreSQL 上**（fixture 见 tests/conftest.py）。
选真库的理由在这个文件里体现得最明显：raw 字段是 JSONB，
SQLite 根本渲染不了 —— 想测它就必须用 PG。
"""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text

from backend.models.alert import Alert


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


async def test_insert_and_read_back(pg_session):
    """最基本的往返：写入后按 id 能读回来。"""
    alert = _make_alert()
    pg_session.add(alert)
    await pg_session.commit()

    found = await pg_session.get(Alert, alert.id)
    assert found is not None
    assert found.signature == "DDoS"
    assert found.src_ip == "45.33.32.156"
    assert found.confidence == pytest.approx(0.93)


async def test_status_defaults_to_new(pg_session):
    """新告警的初始流转状态应为 new。"""
    alert = _make_alert()
    pg_session.add(alert)
    await pg_session.commit()

    assert alert.status == "new"


async def test_optional_fields_can_be_none(pg_session):
    """端口、协议、原始载荷等是可选字段，允许为空。"""
    alert = _make_alert(src_port=None, dst_port=None, protocol=None, raw=None)
    pg_session.add(alert)
    await pg_session.commit()

    assert alert.src_port is None
    assert alert.raw is None


async def test_raw_payload_roundtrip(pg_session):
    """raw 字段要能存嵌套 dict（原始 eve/flow 记录）。"""
    payload = {"event_type": "alert", "alert": {"signature_id": 1000001, "rev": 1}}
    alert = _make_alert(raw=payload)
    pg_session.add(alert)
    await pg_session.commit()

    found = await pg_session.get(Alert, alert.id)
    assert found.raw == payload


async def test_jsonb_supports_field_query(pg_session):
    """JSONB 的核心价值：能用 -> 运算符**按字段查询**。

    这条是选真 PG 的直接收益 —— 也就是"为什么值得为 JSONB 放弃 SQLite 替身"。
    可以在不解析整个 JSON 的前提下，直接查原始记录里的某个字段。
    """
    pg_session.add_all([
        _make_alert(raw={"alert": {"signature_id": 1000001}}, signature="nmap"),
        _make_alert(raw={"alert": {"signature_id": 1000002}}, signature="sqli"),
    ])
    await pg_session.commit()

    # 用原生 SQL 演示 JSONB 的 ->> 取值查询（ORM 层也有对应写法）
    rows = (await pg_session.execute(text(
        "SELECT signature FROM alerts "
        "WHERE raw -> 'alert' ->> 'signature_id' = '1000001'"
    ))).all()
    assert [r[0] for r in rows] == ["nmap"]


async def test_detected_at_is_stored_as_given(pg_session):
    """detected_at 是**事件原始时间**，必须原样保存，不能被自动覆盖。

    防的是常见错误：把 detected_at 也写成 server_default=now()，
    那样所有告警时间都变成入库时间，"按时间戳重放"就废了。
    """
    event_time = datetime.now(UTC) - timedelta(hours=2)
    alert = _make_alert(detected_at=event_time)
    pg_session.add(alert)
    await pg_session.commit()
    await pg_session.refresh(alert)

    assert alert.detected_at == event_time
    # created_at（入库时间）与 detected_at（事件时间）应相差约 2 小时
    assert abs((alert.created_at - alert.detected_at).total_seconds() - 7200) < 60


async def test_filter_by_severity(pg_session):
    """severity 上有索引，是仪表盘主要过滤维度。"""
    pg_session.add_all([
        _make_alert(severity="high", signature="A"),
        _make_alert(severity="low", signature="B"),
    ])
    await pg_session.commit()

    rows = (await pg_session.scalars(
        select(Alert).where(Alert.severity == "high")
    )).all()
    assert len(rows) == 1
    assert rows[0].signature == "A"


async def test_order_by_detected_at(pg_session):
    """按事件时间排序 —— 重放演示依赖这个顺序。"""
    now = datetime.now(UTC)
    pg_session.add_all([
        _make_alert(detected_at=now, signature="later"),
        _make_alert(detected_at=now - timedelta(minutes=5), signature="earlier"),
    ])
    await pg_session.commit()

    rows = (await pg_session.scalars(
        select(Alert).order_by(Alert.detected_at.asc())
    )).all()
    assert [r.signature for r in rows] == ["earlier", "later"]


async def test_composite_index_is_actually_created_in_postgres(pg_session):
    """复合索引必须真的建在 PG 里 —— 不只是写在模型里。

    这条只有真 PG 能查：读 pg_indexes 系统表。
    用 SQLite 测时只能断言"模型里声明了索引名"，那不是同一回事。
    """
    rows = (await pg_session.execute(text(
        "SELECT indexname FROM pg_indexes WHERE tablename = 'alerts'"
    ))).all()
    names = {r[0] for r in rows}
    assert "idx_alerts_detected_severity" in names


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
