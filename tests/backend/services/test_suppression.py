"""抑制规则的测试。

用途：把"已知噪声"告警自动过滤掉，不占用分析师精力与 LLM 费用。

真实场景举例：
    内部漏洞扫描器每周一凌晨扫描全网段 ——
    这类告警是预期的，不应触发研判、不该报警。

设计要点：
    1. **AND 逻辑**：规则里的多个条件必须同时满足才抑制。
       只按 src_ip 抑制会太宽（同 IP 的其他攻击也被吞掉）。
    2. **可选过期**：临时抑制（如演练期间的扫描）应能自动失效，
       否则"忘了删规则"会导致漏报。
    3. **热路径友好**：抑制检查在每条告警上都跑，
       必须快 —— 用带 TTL 的内存缓存，而不是每次查库。
"""

from datetime import UTC, datetime, timedelta

from backend.services.suppression import (
    SuppressionRule,
    SuppressionService,
    matches_rule,
)


def _alert(**overrides) -> dict:
    data = {
        "src_ip": "192.168.10.100",
        "signature": "ET SCAN Nmap OS Detection Probe",
        "signature_id": 1000007,
        "category": "Network Scan",
        "severity": "medium",
    }
    data.update(overrides)
    return data


# ── 单条规则的匹配逻辑 ─────────────────────────────────────────


def test_rule_matches_when_all_conditions_match():
    rule = SuppressionRule(
        id=1,
        name="内部扫描器",
        src_ip="192.168.10.100",
        signature_id=1000007,
    )
    assert matches_rule(rule, _alert()) is True


def test_rule_requires_all_conditions():
    """必须**全部**条件满足才抑制（AND 逻辑）。

    只按 src_ip 就抑制的话，这个 IP 发起的其他真实攻击
    也会被静默吞掉 —— 这是危险的过度抑制。
    """
    rule = SuppressionRule(
        id=1,
        name="内部扫描器",
        src_ip="192.168.10.100",
        signature_id=1000007,
    )
    # src_ip 对但 signature_id 不对 → 不抑制
    assert matches_rule(rule, _alert(signature_id=999999)) is False


def test_rule_with_only_src_ip_matches_any_signature():
    """规则只写 src_ip 时，该源的所有告警都被抑制（显式的宽松规则）。

    这是允许的用法，但需要用户明确这样写 —— 默认空字段即"不限制"。
    """
    rule = SuppressionRule(id=1, name="全抑制该源", src_ip="192.168.10.100")
    assert matches_rule(rule, _alert(signature_id=1)) is True
    assert matches_rule(rule, _alert(src_ip="8.8.8.8")) is False


def test_rule_category_is_case_insensitive():
    rule = SuppressionRule(id=1, name="扫描类", category="network scan")
    assert matches_rule(rule, _alert()) is True


def test_expired_rule_does_not_match():
    """已过期的规则不再生效 —— 防止"忘了删"导致长期漏报。"""
    rule = SuppressionRule(
        id=1,
        name="临时演练",
        src_ip="192.168.10.100",
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    assert matches_rule(rule, _alert()) is False


def test_future_expiry_still_matches():
    rule = SuppressionRule(
        id=1,
        name="演练中",
        src_ip="192.168.10.100",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    assert matches_rule(rule, _alert()) is True


def test_disabled_rule_does_not_match():
    rule = SuppressionRule(id=1, name="已停用", src_ip="192.168.10.100", enabled=False)
    assert matches_rule(rule, _alert()) is False


def test_empty_rule_never_matches():
    """什么条件都没写的规则不应匹配任何告警。

    否则一条空规则会抑制全部告警 —— 灾难性的。
    """
    rule = SuppressionRule(id=1, name="空规则")
    assert matches_rule(rule, _alert()) is False


# ── 服务层 ─────────────────────────────────────────────────────


def test_service_suppresses_matching_alert():
    svc = SuppressionService(
        rules=[
            SuppressionRule(id=1, name="r1", src_ip="192.168.10.100", signature_id=1000007),
        ]
    )
    assert svc.is_suppressed(_alert()) is True


def test_service_passes_non_matching():
    svc = SuppressionService(
        rules=[
            SuppressionRule(id=1, name="r1", src_ip="192.168.10.100", signature_id=1000007),
        ]
    )
    assert svc.is_suppressed(_alert(src_ip="45.33.32.156")) is False


def test_service_reports_which_rule_matched():
    """返回命中的规则 —— 便于解释"为什么这条告警没出现"。"""
    svc = SuppressionService(
        rules=[
            SuppressionRule(id=7, name="内部扫描器", src_ip="192.168.10.100"),
        ]
    )
    rule = svc.match(_alert())
    assert rule is not None
    assert rule.name == "内部扫描器"


def test_service_with_no_rules_suppresses_nothing():
    svc = SuppressionService(rules=[])
    assert svc.is_suppressed(_alert()) is False


def test_service_reloads_rules():
    """规则可更新（新增/删除后重新加载）。"""
    svc = SuppressionService(rules=[])
    assert svc.is_suppressed(_alert()) is False

    svc.reload([SuppressionRule(id=1, name="r1", src_ip="192.168.10.100")])
    assert svc.is_suppressed(_alert()) is True

    svc.reload([])
    assert svc.is_suppressed(_alert()) is False


def test_rule_count_reported():
    svc = SuppressionService(
        rules=[
            SuppressionRule(id=1, name="a", src_ip="1.1.1.1"),
            SuppressionRule(id=2, name="b", src_ip="2.2.2.2", enabled=False),
        ]
    )
    # 统计只算启用的规则
    assert svc.active_count == 1
