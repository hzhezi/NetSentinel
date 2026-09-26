"""EveAlert → 统一告警适配的测试。

这层适配把"解析层的类型"转成"服务层接受的数据形状"。

为什么需要它（而不是让 normalize_alert 直接吃 EveAlert）：
    若 normalize_alert 直接依赖 EveAlert，服务层就绑定了具体的检测引擎，
    将来换引擎要改服务层。现在服务层只认 dict ——
    谁知道怎么转是调用方的事，依赖方向保持正确。
"""

from datetime import UTC, datetime

from backend.detection.parsers.eve_parser import EveAlert
from backend.services.alert_service import eve_to_raw, normalize_alert


def _eve_alert(**overrides) -> EveAlert:
    data = {
        "event_type": "alert",
        "detected_at": datetime(2017, 7, 5, 10, 0, 0, tzinfo=UTC),
        "src_ip": "45.33.32.156",
        "src_port": 52344,
        "dst_ip": "10.0.0.5",
        "dst_port": 80,
        "protocol": "TCP",
        "signature": "Possible SQL Injection",
        "signature_id": 1000002,
        "category": "Web Application Attack",
        "severity": "high",
        "raw": {"flow_id": 1234},
    }
    data.update(overrides)
    return EveAlert(**data)


# ── eve_to_raw：形状转换 ───────────────────────────────────────


def test_eve_to_raw_maps_core_fields():
    raw = eve_to_raw(_eve_alert())

    assert raw["source_engine"] == "suricata"
    assert raw["src_ip"] == "45.33.32.156"
    assert raw["src_port"] == 52344
    assert raw["dst_ip"] == "10.0.0.5"
    assert raw["dst_port"] == 80
    assert raw["protocol"] == "TCP"
    assert raw["signature"] == "Possible SQL Injection"
    assert raw["severity"] == "high"
    assert raw["category"] == "Web Application Attack"


def test_eve_to_raw_preserves_detected_at():
    """事件原始时间必须原样传递 —— 重放的时间线依赖它。"""
    ts = datetime(2017, 7, 5, 10, 0, 0, tzinfo=UTC)
    raw = eve_to_raw(_eve_alert(detected_at=ts))
    assert raw["detected_at"] == ts


def test_eve_to_raw_preserves_raw_event():
    """原始事件必须带上 —— 研判层要它作为证据。"""
    raw = eve_to_raw(_eve_alert())
    assert raw["raw"] == {"flow_id": 1234}


def test_eve_to_raw_does_not_include_dedup_key():
    """dedup_key 由 normalize_alert 生成，适配层不该预先算。

    两处都算的话，去重键的规则就有两个来源，改一处会不一致。
    """
    raw = eve_to_raw(_eve_alert())
    assert "dedup_key" not in raw


# ── 端到端：EveAlert → AlertCreate ─────────────────────────────


def test_eve_alert_converts_to_valid_alert_create():
    """完整链路：EveAlert → 适配 → normalize_alert → 合法 AlertCreate。"""
    out = normalize_alert(eve_to_raw(_eve_alert()))

    assert out.source_engine == "suricata"
    assert out.signature == "Possible SQL Injection"
    assert out.severity == "high"
    assert out.detected_at == datetime(2017, 7, 5, 10, 0, 0, tzinfo=UTC)
    # 去重键由服务层统一生成
    assert out.dedup_key == "45.33.32.156-Possible SQL Injection"


def test_eve_alert_with_missing_optional_fields_still_works():
    """解析器可能给出 None 的端口 —— 适配后仍应产出合法告警。"""
    out = normalize_alert(eve_to_raw(_eve_alert(src_port=None, dst_port=None)))

    assert out.src_port is None
    assert out.dst_port is None
    assert out.signature == "Possible SQL Injection"
