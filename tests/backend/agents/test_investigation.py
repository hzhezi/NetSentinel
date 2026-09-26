"""Investigation Agent（L2 深度调查）的测试。

这是期 2 的核心：**工具驱动的多轮调查**。

与 L1 分诊的区别：
    L1：单轮，只看告警本身 → 信息少，结论保守
    L2：多轮，主动调工具补证据 → 结论明确、有依据

核心机制（ReAct 风格）：
    1. 把告警 + 工具清单发给模型
    2. 模型回"要调工具"或"给结论"
    3. 我们执行工具，把结果回传
    4. 重复直到给出结论，或达到迭代上限
    5. **最后一轮强制输出结论**，保证一定有结构化结果

**证据链**是副产品也是核心价值：每步推理与工具调用都被记录，
结论可以逐行审计 —— 这是"不做黑盒"的具体体现。
"""

import json

import pytest

from backend.agents.investigation import InvestigationAgent, InvestigationResult


class FakeToolCallingLLM:
    """假的 LLM，按预设脚本返回"工具调用"或"最终结论"。

    真实 LLM 的工具调用响应结构较复杂，这里用最小可用的模拟：
    每次调用返回一个 dict，表示这一轮模型想干什么。
    """

    def __init__(self, script: list[dict]):
        self.script = list(script)
        self.calls: list[dict] = []
        self.last_usage = {"prompt_tokens": 100, "completion_tokens": 50}

    def complete_with_tools(self, messages, tools, force_final=False) -> dict:
        self.calls.append({"messages": list(messages), "tools": tools, "force_final": force_final})
        if self.script:
            return self.script.pop(0)
        # 脚本用尽 → 返回最终结论，避免死循环
        return {"type": "final", "content": json.dumps(_verdict_json())}


def _verdict_json(**overrides) -> dict:
    data = {
        "verdict": "true_positive",
        "severity": "high",
        "confidence": 85,
        "summary": "结合情报与资产信息，判定为真实攻击。",
        "mitre_techniques": ["T1190"],
        "recommended_actions": ["封禁源 IP", "排查 Web 日志"],
    }
    data.update(overrides)
    return data


def _tool_call(name: str, args: dict) -> dict:
    return {"type": "tool_call", "name": name, "args": args, "id": f"call_{name}"}


@pytest.fixture
def sample_alert():
    return {
        "id": "alert-1",
        "signature": "Possible SQL Injection (UNION SELECT)",
        "severity": "high",
        "src_ip": "45.33.32.156",
        "dst_ip": "192.168.10.5",
        "dst_port": 80,
        "protocol": "TCP",
    }


# ── 基本流程 ───────────────────────────────────────────────────


def test_agent_returns_structured_result(sample_alert):
    llm = FakeToolCallingLLM([{"type": "final", "content": json.dumps(_verdict_json())}])
    agent = InvestigationAgent(llm=llm)

    result = agent.investigate(sample_alert)

    assert isinstance(result, InvestigationResult)
    assert result.verdict == "true_positive"
    assert result.confidence == 85
    assert result.iterations == 1


def test_agent_sends_tools_to_llm(sample_alert):
    """必须把工具清单发给模型，否则它无从知道能调什么。"""
    llm = FakeToolCallingLLM([{"type": "final", "content": json.dumps(_verdict_json())}])
    InvestigationAgent(llm=llm).investigate(sample_alert)

    sent_tools = llm.calls[0]["tools"]
    names = [t["name"] for t in sent_tools]
    assert "lookup_ip_reputation" in names
    assert "lookup_mitre_technique" in names


def test_agent_sends_alert_in_messages(sample_alert):
    llm = FakeToolCallingLLM([{"type": "final", "content": json.dumps(_verdict_json())}])
    InvestigationAgent(llm=llm).investigate(sample_alert)

    content = json.dumps(llm.calls[0]["messages"], ensure_ascii=False)
    assert "SQL Injection" in content


# ── 工具循环 ───────────────────────────────────────────────────


def test_agent_executes_tool_calls(sample_alert):
    """模型要求调工具时，Agent 应执行并把结果回传。"""
    llm = FakeToolCallingLLM(
        [
            _tool_call("lookup_ip_reputation", {"ip": "45.33.32.156"}),
            {"type": "final", "content": json.dumps(_verdict_json())},
        ]
    )
    agent = InvestigationAgent(llm=llm)
    result = agent.investigate(sample_alert)

    assert result.iterations == 2
    # 第二次调用时应带上工具结果
    second_messages = json.dumps(llm.calls[1]["messages"], ensure_ascii=False)
    assert "malicious" in second_messages or "abuse_score" in second_messages


def test_evidence_trail_records_tool_calls(sample_alert):
    """证据链必须记录每次推理与工具调用 —— 结论可审计的基础。"""
    llm = FakeToolCallingLLM(
        [
            _tool_call("lookup_ip_reputation", {"ip": "45.33.32.156"}),
            _tool_call("get_asset_context", {"ip": "192.168.10.5"}),
            {"type": "final", "content": json.dumps(_verdict_json())},
        ]
    )
    result = InvestigationAgent(llm=llm).investigate(sample_alert)

    tool_steps = [s for s in result.evidence_trail if s["type"] == "tool_call"]
    assert len(tool_steps) == 2
    assert tool_steps[0]["tool"] == "lookup_ip_reputation"
    assert tool_steps[1]["tool"] == "get_asset_context"
    # 每个工具调用都要有结果记录
    assert all("result" in s for s in tool_steps)


def test_evidence_trail_records_reasoning(sample_alert):
    """模型的中间推理也应记录 —— 它是"为什么这么判断"的直接证据。"""
    llm = FakeToolCallingLLM(
        [
            {"type": "text", "content": "先查一下这个 IP 的信誉。"},
            _tool_call("lookup_ip_reputation", {"ip": "45.33.32.156"}),
            {"type": "final", "content": json.dumps(_verdict_json())},
        ]
    )
    result = InvestigationAgent(llm=llm).investigate(sample_alert)

    reasoning = [s for s in result.evidence_trail if s["type"] == "reasoning"]
    assert len(reasoning) == 1
    assert "IP 的信誉" in reasoning[0]["text"]


def test_evidence_trail_records_final_verdict(sample_alert):
    llm = FakeToolCallingLLM([{"type": "final", "content": json.dumps(_verdict_json())}])
    result = InvestigationAgent(llm=llm).investigate(sample_alert)

    verdicts = [s for s in result.evidence_trail if s["type"] == "verdict"]
    assert len(verdicts) == 1


# ── 迭代上限（防死循环）─────────────────────────────────────────


def test_max_iterations_forces_conclusion(sample_alert):
    """达到迭代上限时必须强制给出结论，不能让调查无限循环。

    真实风险：模型可能反复调同一个工具、或陷入"再查一个"的循环。
    没有上限会烧钱且永不返回。
    """
    # 脚本全是工具调用，永不给结论
    llm = FakeToolCallingLLM(
        [_tool_call("lookup_ip_reputation", {"ip": "1.1.1.1"}) for _ in range(20)]
    )
    agent = InvestigationAgent(llm=llm, max_iterations=3)
    result = agent.investigate(sample_alert)

    # 仍应产出结论，且迭代次数被限制
    assert result.verdict in ("true_positive", "false_positive", "needs_human_review")
    assert result.iterations <= 3


def test_iteration_count_reported(sample_alert):
    llm = FakeToolCallingLLM([{"type": "final", "content": json.dumps(_verdict_json())}])
    result = InvestigationAgent(llm=llm).investigate(sample_alert)
    assert result.iterations >= 1


# ── 失败与边界 ─────────────────────────────────────────────────


def test_invalid_json_degrades_to_human_review(sample_alert):
    """模型输出不合规时降级，而不是抛出异常让告警丢失。"""
    llm = FakeToolCallingLLM([{"type": "final", "content": "这不是 JSON"}])
    result = InvestigationAgent(llm=llm).investigate(sample_alert)

    assert result.verdict == "needs_human_review"
    assert result.error is not None


def test_tool_failure_does_not_abort_investigation(sample_alert):
    """工具执行失败时调查应继续 —— 模型可以换工具或用其他证据。"""
    llm = FakeToolCallingLLM(
        [
            _tool_call("nonexistent_tool", {}),  # 未知工具
            {"type": "final", "content": json.dumps(_verdict_json())},
        ]
    )
    result = InvestigationAgent(llm=llm).investigate(sample_alert)

    # 调查完成，且证据链里记录了这次失败
    assert result.verdict == "true_positive"
    failed = [s for s in result.evidence_trail if s.get("error")]
    assert len(failed) >= 1


def test_context_is_passed_to_tools(sample_alert):
    """工具需要的运行时上下文（告警池等）必须传进去。"""
    pool = [{"id": "other", "src_ip": "45.33.32.156", "signature": "PortScan"}]
    llm = FakeToolCallingLLM(
        [
            _tool_call("get_related_alerts", {"field": "src_ip", "value": "45.33.32.156"}),
            {"type": "final", "content": json.dumps(_verdict_json())},
        ]
    )
    result = InvestigationAgent(
        llm=llm,
        tool_context={
            "alert_pool": pool,
            "exclude_id": "alert-1",
        },
    ).investigate(sample_alert)

    related = [
        s
        for s in result.evidence_trail
        if s["type"] == "tool_call" and s["tool"] == "get_related_alerts"
    ]
    assert related[0]["result"]["count"] == 1


# ── prompt 铁律 ────────────────────────────────────────────────


def test_system_prompt_contains_investigation_rules(sample_alert):
    """调查阶段的 prompt 必须包含防幻觉铁律（延续 L1 的底线）。"""
    llm = FakeToolCallingLLM([{"type": "final", "content": json.dumps(_verdict_json())}])
    InvestigationAgent(llm=llm).investigate(sample_alert)

    system = llm.calls[0]["messages"][0]["content"]
    assert "未知" in system  # 查不到 ≠ 安全
    assert "MITRE" in system  # 不得编造编号
    assert "needs_human_review" in system  # 一等结论
