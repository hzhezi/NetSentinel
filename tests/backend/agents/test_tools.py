"""Investigation Agent 工具集的测试。

工具是 LLM 的"手"——它决定调哪个、传什么参数，我们负责执行并返回结果。

设计要点（借鉴 alert-triage-copilot）：
    1. **工具用本地数据**：演示不能因网络失败而中断。
       签名与真实 API 保持一致，将来换真实服务只改实现，不改接口。
    2. **查不到返回"未知"而非"安全"**：这是防幻觉的关键 ——
       模型容易把"没有负面信息"等同于"无害"。
    3. **工具崩了返回错误信息**：让模型能据此调整，而不是让整个调查失败。
"""

import json

from backend.agents.tools import (
    TOOL_SCHEMAS,
    get_alert_detail,
    get_asset_context,
    get_related_alerts,
    lookup_ip_reputation,
    lookup_mitre_technique,
    run_tool,
)

# ── 工具注册表 ─────────────────────────────────────────────────


def test_tool_schemas_are_well_formed():
    """每个工具必须有 name / description / input_schema 三部分。

    description 是给 LLM 看的 —— 写得含糊模型就不知道何时该用。
    """
    assert len(TOOL_SCHEMAS) >= 5
    for schema in TOOL_SCHEMAS:
        assert schema["name"]
        assert len(schema["description"]) > 20, f"{schema['name']} 的 description 太短"
        assert schema["input_schema"]["type"] == "object"
        assert "properties" in schema["input_schema"]


def test_all_schemas_have_implementations():
    """声明的工具必须有实现，否则 LLM 调用后会失败。"""
    for schema in TOOL_SCHEMAS:
        result = run_tool(schema["name"], {})
        assert "error" not in result or "未知工具" not in str(result.get("error", ""))


# ── IP 信誉 ────────────────────────────────────────────────────


def test_lookup_known_malicious_ip():
    result = lookup_ip_reputation({"ip": "45.33.32.156"})
    assert result["reputation"] == "malicious"
    assert result["abuse_score"] > 50


def test_lookup_internal_ip_gives_context_not_safe():
    """内网 IP 没有公网情报 —— 返回的是"该查资产"而非"安全"。

    这是关键设计：把未知表述成"需换角度查"，而非"没问题"。
    """
    result = lookup_ip_reputation({"ip": "192.168.10.5"})
    assert "内部" in result["note"] or "internal" in result["note"].lower()
    assert "safe" not in json.dumps(result).lower()


def test_lookup_unknown_ip_says_unknown_not_safe():
    """查不到情报时，必须明示"未知"而不是留空让人误读为安全。

    防幻觉核心：模型倾向于把"无负面信息"当作"无害"。
    工具必须显式纠正这个倾向。
    """
    result = lookup_ip_reputation({"ip": "8.8.8.8"})
    assert "unknown" in json.dumps(result).lower() or "未知" in json.dumps(result)
    assert "safe" not in json.dumps(result).lower()


# ── MITRE 查表 ─────────────────────────────────────────────────


def test_lookup_mitre_by_exact_key():
    result = lookup_mitre_technique({"behavior": "sql_injection"})
    assert result["matches"][0]["technique_id"] == "T1190"


def test_lookup_mitre_is_fuzzy():
    """行为描述不会恰好等于键名，需要模糊匹配。"""
    result = lookup_mitre_technique({"behavior": "brute force"})
    assert any("T1110" in m["technique_id"] for m in result["matches"])


def test_lookup_mitre_unknown_behavior_suggests_options():
    """匹配不到时给出可用选项，帮助模型下一步查询。"""
    result = lookup_mitre_technique({"behavior": "some totally unknown thing"})
    assert "available_behaviors" in result
    assert len(result["available_behaviors"]) > 0


def test_mitre_lookup_never_invents():
    """查不到就返回空匹配 + 提示，绝不编造编号。

    这条锁住"不得凭记忆写 MITRE 编号"的实现层面保障。
    """
    result = lookup_mitre_technique({"behavior": "zzz_not_a_real_behavior"})
    assert "matches" not in result or result.get("matches") == []


# ── 关联告警 ───────────────────────────────────────────────────


def test_related_alerts_by_src_ip():
    """同源 IP 的其他告警 —— 用于识别多步攻击/持续性扫描。"""
    pool = [
        {"id": "a1", "src_ip": "1.1.1.1", "signature": "scan"},
        {"id": "a2", "src_ip": "1.1.1.1", "signature": "bruteforce"},
        {"id": "a3", "src_ip": "2.2.2.2", "signature": "scan"},
    ]
    result = get_related_alerts(
        {"field": "src_ip", "value": "1.1.1.1"},
        {"alert_pool": pool, "exclude_id": "a1"},
    )
    assert result["count"] == 1
    assert result["alerts"][0]["id"] == "a2"


def test_related_alerts_excludes_self():
    """不应把当前正在调查的告警算作"关联告警"。"""
    pool = [{"id": "self", "src_ip": "1.1.1.1", "signature": "scan"}]
    result = get_related_alerts(
        {"field": "src_ip", "value": "1.1.1.1"},
        {"alert_pool": pool, "exclude_id": "self"},
    )
    assert result["count"] == 0


def test_related_alerts_rejects_bad_field():
    """字段名非法时给出明确提示，而不是静默返回空。"""
    result = get_related_alerts(
        {"field": "password", "value": "x"}, {"alert_pool": [], "exclude_id": None}
    )
    assert "field must be" in result["note"]


def test_related_alerts_empty_says_none_found():
    result = get_related_alerts(
        {"field": "src_ip", "value": "9.9.9.9"}, {"alert_pool": [], "exclude_id": None}
    )
    assert result["count"] == 0
    assert "No alerts" in result["note"] or "未找到" in result["note"]


# ── 资产上下文 ─────────────────────────────────────────────────


def test_asset_context_for_db_server_is_critical():
    """数据库服务器的资产重要性应为 critical —— 影响严重度判断。"""
    result = get_asset_context({"ip": "192.168.10.12"})
    assert result["criticality"] == "critical"
    assert result["type"] == "database-server"


def test_asset_context_unknown_ip():
    result = get_asset_context({"ip": "10.99.99.99"})
    assert "note" in result


# ── 告警详情 ───────────────────────────────────────────────────


def test_alert_detail_returns_raw():
    """返回原始告警记录 —— 深度调查需要看到原始字段。"""
    alert = {"id": "a1", "signature": "X", "raw": {"flow_id": 123}}
    result = get_alert_detail({"alert_id": "a1"}, {"alert_lookup": lambda _: alert})
    assert result["raw"]["flow_id"] == 123


# ── 分发与容错 ─────────────────────────────────────────────────


def test_run_tool_dispatches():
    result = run_tool("lookup_ip_reputation", {"ip": "45.33.32.156"})
    assert result["reputation"] == "malicious"


def test_run_tool_unknown_name_returns_error():
    """未知工具名返回错误信息（给模型看），而不是抛异常中断调查。"""
    result = run_tool("nonexistent_tool", {})
    assert "error" in result


def test_missing_args_are_handled_gracefully():
    """缺参数时工具应宽容处理（返回 unknown），而不是崩溃。

    设计取舍：工具对缺参尽量兜底而非报错 ——
    模型偶尔漏传参数，直接失败会让整轮调查白费。
    """
    result = run_tool("lookup_ip_reputation", {})
    assert "reputation" in result
    assert "error" not in result


def test_run_tool_catches_exceptions(monkeypatch):
    """工具实现抛异常时，把错误变成返回值让模型能反应。

    这是关键容错：工具的 bug 不该让整个调查崩掉 ——
    模型可以据此换一个工具或用其他证据继续。
    """
    import backend.agents.tools as tools_mod

    def boom(args, context=None):
        raise RuntimeError("模拟的工具故障")

    monkeypatch.setitem(tools_mod._IMPLEMENTATIONS, "lookup_ip_reputation", boom)
    result = run_tool("lookup_ip_reputation", {"ip": "1.1.1.1"})
    assert "error" in result
    assert "模拟的工具故障" in result["error"]


def test_run_tool_with_context_injection():
    """需要上下文的工具（如关联告警需告警池）通过上下文注入。"""
    pool = [{"id": "a1", "src_ip": "1.1.1.1", "signature": "s"}]
    result = run_tool(
        "get_related_alerts",
        {"field": "src_ip", "value": "1.1.1.1"},
        context={"alert_pool": pool, "exclude_id": None},
    )
    assert result["count"] == 1
