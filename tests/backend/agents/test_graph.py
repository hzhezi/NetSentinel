"""LangGraph 研判图的测试。

图是"编排层"：它不实现研判逻辑，只负责按顺序/条件调用节点。
测试注入假的 LLM 与假的持久化函数，因此不需要 API key 也不需要数据库。

验证的重点：
    1. 正常路径：triage → persist
    2. 条件边：escalate 时走调查分支（期 1 是占位节点）
    3. 状态在节点间正确传递
    4. 研判失败时降级为 needs_human_review 而非中断（安全系统关键性质）
"""

from backend.agents.graph import build_triage_graph
from backend.schemas.triage import TriageResult


def _result(**overrides) -> TriageResult:
    data = {
        "verdict": "true_positive",
        "severity": "high",
        "confidence": 85,
        "escalate": False,
        "attack_type": "SQL Injection",
        "summary": "检测到注入尝试。",
        "mitre_techniques": ["T1190"],
        "recommended_actions": ["阻断源 IP"],
    }
    data.update(overrides)
    return TriageResult(**data)


class FakeLLM:
    """假的 LLM 客户端，返回预设结果。"""

    def __init__(self, result: TriageResult | None = None, raise_error: bool = False):
        self.result = result or _result()
        self.raise_error = raise_error
        self.calls: list[dict] = []
        self.last_usage = {"prompt_tokens": 100, "completion_tokens": 50}

    def triage(self, alert: dict) -> TriageResult:
        self.calls.append(alert)
        if self.raise_error:
            from backend.agents.llm_client import LLMError

            raise LLMError("模拟的 LLM 失败")
        return self.result


class FakePersist:
    """假的持久化函数，记录调用。"""

    def __init__(self):
        self.records: list[dict] = []

    async def __call__(self, alert: dict, triage: dict, **kwargs) -> None:
        self.records.append({"alert": alert, "triage": triage, **kwargs})


# ── 正常路径 ───────────────────────────────────────────────────


async def test_graph_runs_triage_and_persists():
    llm = FakeLLM()
    persist = FakePersist()
    graph = build_triage_graph(llm=llm, persist=persist)

    out = await graph.ainvoke(
        {
            "alert": {"id": "a1", "signature": "SQL Injection", "severity": "high"},
        }
    )

    assert out["triage"]["verdict"] == "true_positive"
    assert len(persist.records) == 1
    assert persist.records[0]["alert"]["id"] == "a1"


async def test_graph_passes_alert_to_llm():
    """告警内容必须传给 LLM —— 否则模型无从判断。"""
    llm = FakeLLM()
    graph = build_triage_graph(llm=llm, persist=FakePersist())

    await graph.ainvoke({"alert": {"id": "a1", "signature": "ET SCAN Nmap"}})

    assert llm.calls[0]["signature"] == "ET SCAN Nmap"


async def test_graph_records_token_usage():
    """token 用量应写入结果 —— 报告的成本数据来源。"""
    graph = build_triage_graph(llm=FakeLLM(), persist=FakePersist())

    out = await graph.ainvoke({"alert": {"id": "a1", "signature": "X"}})

    assert out["usage"]["prompt_tokens"] == 100


# ── 条件边 ─────────────────────────────────────────────────────


async def test_escalate_true_goes_through_investigation():
    """escalate=True 时应经过调查分支。

    未配置 investigator 时（本测试场景）降级为 needs_human_review，
    但仍会落库 —— 告警不因调查器缺失而丢失。
    """
    llm = FakeLLM(_result(escalate=True, confidence=40))
    persist = FakePersist()
    graph = build_triage_graph(llm=llm, persist=persist)

    out = await graph.ainvoke({"alert": {"id": "a1", "signature": "X"}})

    assert out["escalated"] is True
    assert out["investigation"]["verdict"] == "needs_human_review"
    # 两条记录：L1 分诊 + L2 降级
    assert len(persist.records) == 2
    assert {r["stage"] for r in persist.records} == {"triage", "investigation"}


async def test_escalate_false_skips_investigation():
    llm = FakeLLM(_result(escalate=False))
    graph = build_triage_graph(llm=llm, persist=FakePersist())

    out = await graph.ainvoke({"alert": {"id": "a1", "signature": "X"}})

    assert out["escalated"] is False


async def test_needs_human_review_forces_escalation():
    """needs_human_review 必须升级 —— 拿不准就该让人看。

    这是硬规则，不依赖模型自己填 escalate。
    模型可能给出 needs_human_review 但忘记设 escalate，
    此时若跳过调查，这条"不确定"的结论就没人处理了。
    """
    llm = FakeLLM(_result(verdict="needs_human_review", escalate=False, confidence=30))
    graph = build_triage_graph(llm=llm, persist=FakePersist())

    out = await graph.ainvoke({"alert": {"id": "a1", "signature": "X"}})

    assert out["escalated"] is True


async def test_high_severity_forces_escalation():
    """critical 级别强制升级（硬规则的兜底）。"""
    llm = FakeLLM(_result(severity="critical", escalate=False))
    graph = build_triage_graph(llm=llm, persist=FakePersist())

    out = await graph.ainvoke({"alert": {"id": "a1", "signature": "X"}})

    assert out["escalated"] is True


# ── 失败降级（安全系统关键性质）─────────────────────────────────


async def test_llm_failure_degrades_to_human_review():
    """LLM 调用失败时应降级为 needs_human_review，而不是让整条告警丢失。

    为什么这很重要：LLM 可能因限流/超时/输出不合规而失败。
    若此时直接丢弃告警，就等于"因为研判器故障而漏掉了攻击" ——
    这是安全系统不能接受的。降级为人工复核，保证告警仍在队列里。
    """
    persist = FakePersist()
    graph = build_triage_graph(llm=FakeLLM(raise_error=True), persist=persist)

    out = await graph.ainvoke({"alert": {"id": "a1", "signature": "X"}})

    assert out["triage"]["verdict"] == "needs_human_review"
    assert out["triage"]["escalate"] is True
    assert out["triage"]["error"] is not None
    # 关键：仍然落库了 —— 告警没有因为研判失败而消失
    # （L1 降级 + L2 降级，共两条）
    assert len(persist.records) == 2
