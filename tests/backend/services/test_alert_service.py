"""告警服务（归一化 + 去重）的测试。

这里测的是**领域逻辑**，不是数据访问，所以不需要数据库 —— 纯函数和内存缓存。
"""

from datetime import UTC, datetime

from backend.schemas.alert import AlertCreate
from backend.services.alert_service import AlertPipeline, normalize_alert

# ── normalize_alert：把引擎输出归一化为统一形状 ─────────────────


def test_normalize_returns_alert_create():
    """归一化产出的是 AlertCreate 而不是 dict。

    这条锁住一个契约：字段清单**单一来源**于 AlertCreate。
    若有人改回手写 dict，字段改名时就会两处不同步（且 mypy 查不出）。
    """
    out = normalize_alert(
        {
            "source_engine": "suricata",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "signature": "X",
            "severity": "high",
        }
    )
    assert isinstance(out, AlertCreate)


def test_normalize_passes_validation():
    """宽容兜底之后，产出必须能通过 AlertCreate 的严格校验。

    这验证了两阶段设计成立：宽容处理在前、严格闸门在后，
    脏输入经过兜底后是合法数据，不会在构造时抛 ValidationError。
    """
    out = normalize_alert(
        {
            "source_engine": "suricata",
            # 故意给一个非法严重度 + 数字型 confidence 字符串
            "severity": "WHATEVER",
            "confidence": "0.5",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "signature": "X",
        }
    )
    assert out.severity == "info"  # 降级
    assert out.confidence == 0.5  # 类型转换


def test_normalize_fills_required_fields():
    out = normalize_alert(
        {
            "source_engine": "suricata",
            "src_ip": "45.33.32.156",
            "dst_ip": "10.0.0.5",
            "signature": "DDoS",
            "severity": "high",
            "confidence": 0.93,
        }
    )

    assert out.source_engine == "suricata"
    assert out.src_ip == "45.33.32.156"
    assert out.signature == "DDoS"


def test_normalize_generates_dedup_key():
    """去重键由 (源IP, 签名) 组成。

    为什么用这两者的组合：
      同一源对同一规则的反复触发是"同一件事"，应聚合；
      不同源命中同一规则是"不同攻击者"，不该合并。
    """
    out = normalize_alert(
        {
            "source_engine": "suricata",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "signature": "ET SCAN Nmap",
            "severity": "medium",
        }
    )
    assert out.dedup_key == "1.1.1.1-ET SCAN Nmap"


def test_normalize_defaults_detected_at_to_now_when_missing():
    """没有时间戳时用当前时间兜底。

    真实场景：Suricata 的 eve 一定带时间戳，但 ML 通道可能不带。
    兜底保证字段不为 None（数据库该列是 NOT NULL）。
    """
    before = datetime.now(UTC)
    out = normalize_alert(
        {
            "source_engine": "suricata",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "signature": "X",
            "severity": "low",
        }
    )
    after = datetime.now(UTC)

    assert before <= out.detected_at <= after


def test_normalize_preserves_given_detected_at():
    """有原始时间戳时必须原样保留 —— 重放功能依赖这一点。"""
    ts = datetime(2017, 7, 5, 10, 0, 0, tzinfo=UTC)
    out = normalize_alert(
        {
            "source_engine": "suricata",
            "detected_at": ts,
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "signature": "X",
            "severity": "low",
        }
    )
    assert out.detected_at == ts


def test_normalize_fills_missing_optional_fields():
    """缺失的可选字段应填 None/默认值，而不是让 KeyError 冒出来。"""
    out = normalize_alert(
        {
            "source_engine": "suricata",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "signature": "X",
            "severity": "low",
        }
    )
    assert out.src_port is None
    assert out.protocol is None
    assert out.confidence == 0.0


def test_normalize_handles_unknown_severity_gracefully():
    """引擎传来未知严重度时，降级为 info 而不是崩溃。

    设计取舍：宁可告警"级别不准"，也不要因为一个字段异常丢掉整条告警 ——
    安全系统里"漏报"比"级别标错"严重得多。
    """
    out = normalize_alert(
        {
            "source_engine": "suricata",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "signature": "X",
            "severity": "UNKNOWN_LEVEL",
        }
    )
    assert out.severity == "info"


# ── AlertPipeline：去重 ────────────────────────────────────────


def test_first_alert_is_not_duplicate():
    p = AlertPipeline()
    alert = {"src_ip": "1.1.1.1", "signature": "DDoS"}
    assert p.is_duplicate(alert) is False


def test_same_alert_within_window_is_duplicate():
    """同一 (源IP, 签名) 在 TTL 内重复出现应被识别为重复。"""
    p = AlertPipeline()
    alert = {"src_ip": "1.1.1.1", "signature": "DDoS"}

    assert p.is_duplicate(alert) is False  # 第一次
    assert p.is_duplicate(alert) is True  # 第二次
    assert p.is_duplicate(alert) is True  # 第三次


def test_different_source_ip_is_not_duplicate():
    """不同源 IP 命中同一规则 —— 是不同攻击者，不应合并。"""
    p = AlertPipeline()
    assert p.is_duplicate({"src_ip": "1.1.1.1", "signature": "DDoS"}) is False
    assert p.is_duplicate({"src_ip": "2.2.2.2", "signature": "DDoS"}) is False


def test_different_signature_is_not_duplicate():
    """同一源触发不同规则 —— 是不同攻击行为，不应合并。"""
    p = AlertPipeline()
    assert p.is_duplicate({"src_ip": "1.1.1.1", "signature": "DDoS"}) is False
    assert p.is_duplicate({"src_ip": "1.1.1.1", "signature": "PortScan"}) is False


def test_dedup_window_expires():
    """TTL 到期后同一告警应重新被当作新告警。

    为什么需要过期：完全不过期会永远吞掉重复告警，
    攻击者在 1 小时后再次扫描就被静默丢弃了。
    TTL 表达的是"短时间内的高频重复才聚合"。
    """
    p = AlertPipeline(ttl_seconds=0.05)  # 50 毫秒，测试用
    alert = {"src_ip": "1.1.1.1", "signature": "DDoS"}

    assert p.is_duplicate(alert) is False
    assert p.is_duplicate(alert) is True

    import time

    time.sleep(0.1)
    assert p.is_duplicate(alert) is False  # 已过期，视为新告警


def test_dedup_capacity_is_bounded():
    """缓存有容量上限 —— 防止被海量唯一告警撑爆内存。

    TTLCache(maxsize=N) 在超出时会淘汰最旧的条目。
    这是必要的防护：攻击者可能用海量唯一 IP 发起告警洪泛，
    无上限的缓存会直接耗尽内存。
    """
    p = AlertPipeline(maxsize=10)
    # 塞 100 条互不相同的告警，不应报错也不应无限增长
    for i in range(100):
        p.is_duplicate({"src_ip": f"10.0.0.{i}", "signature": "X"})
    # 缓存内部大小受 maxsize 约束
    assert len(p._recent) <= 10
