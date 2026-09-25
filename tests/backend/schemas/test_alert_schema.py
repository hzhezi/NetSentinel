"""告警 Pydantic Schema 的测试。

Schema 是 **API 契约**：它决定接口收什么、返回什么。
这些测试实际是在锁住契约，防止无意间破坏前端依赖的字段。
"""

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from backend.schemas.alert import AlertCreate, AlertPage, AlertResponse


def _valid_payload(**overrides):
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
    return data


# ── AlertCreate：入参契约 ──────────────────────────────────────

def test_alert_create_accepts_valid_payload():
    obj = AlertCreate(**_valid_payload())
    assert obj.severity == "high"
    assert obj.attack_type is None  # 可选字段默认 None


def test_alert_create_rejects_unknown_engine():
    """source_engine 限定为 suricata / ml —— 防止两个引擎之外的值混进来。"""
    with pytest.raises(ValidationError):
        AlertCreate(**_valid_payload(source_engine="unknown_engine"))


def test_alert_create_rejects_unknown_severity():
    """severity 是枚举，拼错必须报错而不是静默通过。

    这条很重要：如果允许任意字符串，某天引擎传来 "HIGH"（大写）
    或 "warning"，下游按 severity 做的过滤/统计就会静默漏数据。
    """
    with pytest.raises(ValidationError):
        AlertCreate(**_valid_payload(severity="critical-high"))


def test_alert_create_rejects_out_of_range_confidence():
    """confidence 是概率，必须在 0~1 之间。"""
    with pytest.raises(ValidationError):
        AlertCreate(**_valid_payload(confidence=1.5))
    with pytest.raises(ValidationError):
        AlertCreate(**_valid_payload(confidence=-0.1))


def test_alert_create_does_not_include_server_managed_fields():
    """入参不应包含 id / created_at —— 这些由数据库生成。

    防的是"API 允许客户端指定 id"这类越权设计。
    """
    fields = set(AlertCreate.model_fields.keys())
    assert "id" not in fields
    assert "created_at" not in fields


def test_alert_create_ignores_extra_fields_by_default():
    """Pydantic v2 默认忽略多余字段 —— 上游多传字段不应导致 500。"""
    obj = AlertCreate(**_valid_payload(), some_future_field="x")
    assert not hasattr(obj, "some_future_field")


# ── AlertResponse：出参契约 ────────────────────────────────────

def test_alert_response_from_orm_object():
    """响应模型必须能直接从 ORM 对象构造（from_attributes）。

    这是 ORM → API 的桥：repository 返回 Alert 对象，
    路由层用 AlertResponse.model_validate(row) 直接转换，
    不需要手工逐字段复制。
    """

    class FakeRow:
        id = uuid.uuid4()
        created_at = datetime.now(UTC)
        source_engine = "ml"
        detected_at = datetime.now(UTC)
        src_ip = "1.1.1.1"
        src_port = 1234
        dst_ip = "2.2.2.2"
        dst_port = 80
        protocol = "TCP"
        signature = "DDoS"
        attack_type = "DDoS"
        severity = "high"
        confidence = 0.9
        category = None
        raw = {"k": "v"}
        status = "new"
        notes = ""

    resp = AlertResponse.model_validate(FakeRow())
    assert resp.source_engine == "ml"
    assert resp.status == "new"
    assert resp.raw == {"k": "v"}


def test_alert_response_includes_id_and_status():
    """出参必须包含 id 和 status —— 前端靠 id 去重、靠 status 做流转。"""
    fields = set(AlertResponse.model_fields.keys())
    assert {"id", "status", "created_at"} <= fields


def test_alert_response_excludes_internal_dedup_key():
    """dedup_key 是内部实现细节，不应出现在 API 响应里。

    这是"ORM 字段 ≠ API 字段"的直接体现：schema 做了裁剪。
    """
    assert "dedup_key" not in AlertResponse.model_fields


# ── AlertPage：分页契约 ────────────────────────────────────────

def test_alert_page_wraps_items_with_total():
    """列表接口统一返回 {items, total, page, size}。

    为什么不用裸数组：前端分页组件需要 total 才能算总页数。
    返回裸数组的话，前端只能"有没有下一页"地猜。
    """
    page = AlertPage(items=[], total=0, page=1, size=20)
    assert page.total == 0
    assert page.items == []
