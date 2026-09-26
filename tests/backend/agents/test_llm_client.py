"""DeepSeek 客户端与结构化输出的测试。

**测试绝不真实调用 API** —— 那会花钱、依赖网络、且不稳定。
所有测试注入假的底层调用（monkeypatch `_raw_call`），
只验证本模块的逻辑：prompt 构造、JSON 解析、校验、重试、错误处理。

真实连通性验证由 `scripts/check_llm.py` 手动执行（需要 API key）。
"""

import json

import pytest
from pydantic import ValidationError

from backend.agents.llm_client import LLMClient, LLMError
from backend.schemas.triage import TriageResult


def _valid_json(**overrides) -> str:
    data = {
        "verdict": "true_positive",
        "severity": "high",
        "confidence": 85,
        "escalate": False,
        "attack_type": "SQL Injection",
        "summary": "检测到 SQL 注入尝试，来自外部 IP。",
        "mitre_techniques": ["T1190"],
        "recommended_actions": ["阻断源 IP", "检查 Web 日志"],
    }
    data.update(overrides)
    return json.dumps(data, ensure_ascii=False)


@pytest.fixture
def client(monkeypatch):
    """构造客户端并把底层调用替换成可控的假函数。"""
    c = LLMClient(api_key="test-key", base_url="http://fake", model="test-model")

    calls = {"n": 0, "prompts": []}

    def fake_raw_call(system: str, user: str) -> str:
        calls["n"] += 1
        calls["prompts"].append({"system": system, "user": user})
        return _valid_json()

    monkeypatch.setattr(c, "_raw_call", fake_raw_call)
    c._test_calls = calls  # 暴露给测试断言
    return c


# ── TriageResult Schema ────────────────────────────────────────


def test_schema_accepts_valid_payload():
    r = TriageResult.model_validate(json.loads(_valid_json()))
    assert r.verdict == "true_positive"
    assert r.escalate is False
    assert r.mitre_techniques == ["T1190"]


def test_schema_rejects_unknown_verdict():
    """verdict 必须是三个合法值之一 —— 防模型自由发挥。"""
    with pytest.raises(ValidationError):
        TriageResult.model_validate(json.loads(_valid_json(verdict="maybe_attack")))


def test_schema_rejects_out_of_range_confidence():
    with pytest.raises(ValidationError):
        TriageResult.model_validate(json.loads(_valid_json(confidence=150)))


def test_schema_allows_needs_human_review():
    """needs_human_review 是**一等结论**，不是失败。

    若不允许它，模型在证据不足时会被迫二选一，于是编造答案。
    """
    r = TriageResult.model_validate(
        json.loads(
            _valid_json(
                verdict="needs_human_review",
                confidence=40,
                escalate=True,
            )
        )
    )
    assert r.verdict == "needs_human_review"
    assert r.escalate is True


def test_schema_optional_fields_default():
    """可选字段缺失时应有合理默认，而不是报错。"""
    minimal = json.dumps(
        {
            "verdict": "false_positive",
            "severity": "low",
            "confidence": 90,
            "summary": "看起来是正常的健康检查。",
        }
    )
    r = TriageResult.model_validate(json.loads(minimal))
    assert r.escalate is False
    assert r.mitre_techniques == []
    assert r.recommended_actions == []
    assert r.attack_type is None


# ── 正常解析 ───────────────────────────────────────────────────


def test_triage_returns_parsed_result(client):
    result = client.triage({"signature": "SQL Injection", "severity": "high"})

    assert isinstance(result, TriageResult)
    assert result.verdict == "true_positive"
    assert result.severity == "high"


def test_triage_sends_alert_in_prompt(client):
    """告警内容必须出现在发给模型的 prompt 里，否则模型无从判断。"""
    client.triage({"signature": "ET SCAN Nmap", "src_ip": "45.33.32.156"})

    sent = client._test_calls["prompts"][0]["user"]
    assert "ET SCAN Nmap" in sent
    assert "45.33.32.156" in sent


def test_system_prompt_contains_anti_hallucination_rules(client):
    """系统提示必须包含防幻觉铁律。

    这四条是设计文档 §6.4 的要求，用测试锁住 ——
    谁把 prompt 改没了，测试会立刻失败。
    """
    client.triage({"signature": "X"})
    system = client._test_calls["prompts"][0]["system"]

    # 1. 查不到视为"未知"而非"安全"
    assert "未知" in system
    # 2. needs_human_review 是一等结论
    assert "needs_human_review" in system
    # 3. 不得凭记忆写 MITRE 编号
    assert "MITRE" in system
    # 4. 严重度用自己的判断，不抄检测层上报值
    assert "severity" in system.lower() or "严重度" in system


# ── 重试与错误处理 ─────────────────────────────────────────────


def test_retries_on_invalid_json(monkeypatch):
    """模型返回非 JSON 时应重试，而不是直接失败。

    LLM 偶尔会输出带 markdown 代码围栏的内容，或多说一句话。
    这种情况下重试（并在 prompt 中提示）比直接报错更实用。
    """
    c = LLMClient(api_key="k", base_url="http://fake", model="m")
    responses = iter(["这不是 JSON", _valid_json()])

    def fake(system, user):
        return next(responses)

    monkeypatch.setattr(c, "_raw_call", fake)
    result = c.triage({"signature": "X"})

    assert result.verdict == "true_positive"


def test_retries_on_schema_violation(monkeypatch):
    """JSON 合法但字段不合法（如 verdict 非法）也应重试。"""
    c = LLMClient(api_key="k", base_url="http://fake", model="m")
    responses = iter([_valid_json(verdict="unknown_thing"), _valid_json()])

    monkeypatch.setattr(c, "_raw_call", lambda s, u: next(responses))
    assert c.triage({"signature": "X"}).verdict == "true_positive"


def test_raises_after_max_retries(monkeypatch):
    """反复失败后应抛出明确的异常，而不是无限重试。"""
    c = LLMClient(api_key="k", base_url="http://fake", model="m", max_retries=2)
    monkeypatch.setattr(c, "_raw_call", lambda s, u: "一直不是 JSON")

    with pytest.raises(LLMError):
        c.triage({"signature": "X"})


def test_strips_markdown_code_fence(monkeypatch):
    """模型常把 JSON 包在 ```json ... ``` 里，应能剥离。

    这是真实高频问题：即使要求"只输出 JSON"，
    模型仍可能加代码围栏。不处理的话每次都要白重试一遍。
    """
    c = LLMClient(api_key="k", base_url="http://fake", model="m")
    monkeypatch.setattr(
        c,
        "_raw_call",
        lambda s, u: f"```json\n{_valid_json()}\n```",
    )
    assert c.triage({"signature": "X"}).verdict == "true_positive"


def test_records_token_usage(monkeypatch):
    """记录 token 用量 —— 报告需要成本数据。"""
    c = LLMClient(api_key="k", base_url="http://fake", model="m")
    monkeypatch.setattr(c, "_raw_call", lambda s, u: _valid_json())

    c.triage({"signature": "X"})

    assert "prompt_tokens" in c.last_usage
    assert "completion_tokens" in c.last_usage
