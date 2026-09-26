"""Suricata EVE JSON 解析器的测试。

这些测试**不需要 pcap**，用手写的 JSON 行即可 ——
解析是纯函数，与"包从哪来"无关。

测试重点：
    1. 只认 alert 事件，其余事件类型跳过
    2. 脏数据（非 JSON、空行）返回 None 而不抛异常
    3. 缺字段时用默认值兜底
    4. **Suricata priority → 平台 severity 的映射方向不能反**
"""

from datetime import datetime

from backend.detection.parsers.eve_parser import parse_eve_line


def _alert_line(severity: int = 3, **overrides) -> str:
    """构造一行 eve.json alert 事件，可覆盖字段。"""
    import json

    evt = {
        "timestamp": "2017-07-05T10:00:00.123456+0000",
        "flow_id": 1234,
        "in_iface": "eth0",
        "event_type": "alert",
        "src_ip": "45.33.32.156",
        "src_port": 52344,
        "dest_ip": "10.0.0.5",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 1000002,
            "rev": 1,
            "signature": "Possible SQL Injection",
            "category": "Web Application Attack",
            "severity": severity,
        },
    }
    evt.update(overrides)
    return json.dumps(evt)


# ── 正常解析 ───────────────────────────────────────────────────


def test_parse_alert_event():
    event = parse_eve_line(_alert_line())

    assert event is not None
    assert event.event_type == "alert"
    assert event.signature == "Possible SQL Injection"
    assert event.signature_id == 1000002
    assert event.src_ip == "45.33.32.156"
    assert event.src_port == 52344
    assert event.dst_ip == "10.0.0.5"
    assert event.dst_port == 80
    assert event.protocol == "TCP"
    assert event.category == "Web Application Attack"


def test_parse_timestamp_with_timezone():
    """Suricata 的 +0000 格式必须被正确解析成带时区的 datetime。

    Python 的 fromisoformat 不接受 "+0000" 这种无冒号形式，
    必须转换。做错的话要么抛异常、要么丢掉时区信息（naive datetime），
    后者会导致重放时的时间计算全部错位。
    """
    event = parse_eve_line(_alert_line())

    assert isinstance(event.detected_at, datetime)
    assert event.detected_at.tzinfo is not None
    assert event.detected_at.year == 2017


def test_parse_keeps_raw_event():
    """保留完整原始事件 —— 研判层需要它作为证据，也是可追溯性的基础。"""
    event = parse_eve_line(_alert_line())

    assert event.raw["flow_id"] == 1234
    assert event.raw["alert"]["rev"] == 1


# ── 严重度映射（方向不能反）─────────────────────────────────────


def test_priority_maps_to_severity():
    """Suricata 的 priority 越小越严重，映射到平台 severity。

    这条测试防的是"映射方向写反"——如果 1 映射成 info、
    4 映射成 critical，所有告警的严重度都会颠倒，而且不会报错，
    只会静默地让研判层做出错误判断。
    """
    assert parse_eve_line(_alert_line(severity=1)).severity == "critical"
    assert parse_eve_line(_alert_line(severity=2)).severity == "high"
    assert parse_eve_line(_alert_line(severity=3)).severity == "medium"
    assert parse_eve_line(_alert_line(severity=4)).severity == "low"


def test_unknown_priority_falls_back_to_info():
    """未知 priority 降级为 info，不崩溃。"""
    assert parse_eve_line(_alert_line(severity=99)).severity == "info"


# ── 非 alert 事件 ──────────────────────────────────────────────


def test_non_alert_events_return_none():
    """flow / dns / http 等事件不产出告警。

    eve.json 里 alert 只占一部分，其余是流量统计、DNS 查询等。
    把它们也当成告警会让系统被无关事件淹没。
    """
    import json

    for etype in ("flow", "dns", "http", "tls", "stats"):
        line = json.dumps(
            {"timestamp": "2017-07-05T10:00:00+0000", "event_type": etype, "flow_id": 1}
        )
        assert parse_eve_line(line) is None


# ── 健壮性：脏数据绝不抛异常 ────────────────────────────────────


def test_malformed_json_returns_none():
    """格式错误的一行不能让整批重放崩溃。

    重放时可能有几万行，其中一行坏数据就中断整个任务是不可接受的。
    """
    assert parse_eve_line("not json at all") is None
    assert parse_eve_line("{broken json") is None


def test_empty_and_whitespace_lines_return_none():
    assert parse_eve_line("") is None
    assert parse_eve_line("   \n") is None


def test_missing_fields_use_defaults():
    """字段缺失时用默认值兜底 —— 数据库对应列是 NOT NULL。

    真实场景：不同 Suricata 版本、或自定义规则产出的 alert 字段可能不全。
    """
    line = '{"event_type":"alert","alert":{"signature":"X"}}'
    event = parse_eve_line(line)

    assert event is not None
    assert event.signature == "X"
    assert event.src_ip == "0.0.0.0"  # 不能是 None
    assert event.dst_ip == "0.0.0.0"
    assert event.detected_at is not None  # 没有时间戳也要有值


def test_missing_alert_object_does_not_crash():
    """event_type=alert 但缺少 alert 字段 —— 也要能处理。"""
    line = '{"event_type":"alert","src_ip":"1.1.1.1"}'
    event = parse_eve_line(line)

    assert event is not None
    assert event.signature == "Unknown"
    assert event.severity == "medium"  # 默认 priority 3
