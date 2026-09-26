"""期 2 图测试：L2 调查节点接入。

期 1 时 investigate 是占位节点（返回 None）。期 2 换成真实的
Investigation Agent，本文件验证这次的接线正确。

关键行为：
    - escalate=true 时走真实调查，产出 evidence_trail
    - escalate=false 时跳过调查（不浪费钱）
    - 调查失败时降级，不影响持久化（告警不丢）
    - 手动触发：即使 escalate=false 也能强制调查
"""

from backend.agents.graph import build_triage_graph
from backend.schemas.triage import TriageResult


def _triage_result(**overrides) -> TriageResult:
    data = {
        "verdict": "true_positive",
        "severity": "high",
        "confidence": 85,
        "escalate": True,
        "attack_type": "SQL Injection",
        "summary": "L1 判断为真实攻击。",
        "mitre_techniques": [],
        "recommended_actions": ["初步建议"],
    }
    data.update(overrides)
    return TriageResult(**data)


class FakeTriageLLM:
    """L1 分诊用的假客户端。"""

    def __init__(self, result: TriageResult | None = None):
        self.result = result or _triage_result()
        self.last_usage = {"prompt_tokens": 100, "completion_tokens": 50}

    def triage(self, alert):
        return self.result


class FakeInvestigator:
    """L2 调查用的假 Agent。

    接口与 InvestigationAgent 一致（investigate(alert) -> Result），
    因此可以无缝替换 —— 这正是依赖注入的价值。
    """

    def __init__(self, result=None, raise_error: bool = False):
        self.result = result
        self.raise_error = raise_error
        self.calls: list[dict] = []

    def investigate(self, alert):
        self.calls.append(alert)
        if self.raise_error:
            raise RuntimeError("模拟调查故障")

        from backend.agents.investigation import InvestigationResult

        if self.result is not None:
            return self.result
        return InvestigationResult(
            verdict="true_positive",
            severity="high",
            confidence=92,
            summary="结合情报与资产信息，确认是真实攻击。",
            mitre_techniques=["T1190"],
            recommended_actions=["封禁 IP"],
            iterations=3,
            evidence_trail=[
                {
                    "type": "tool_call",
                    "tool": "lookup_ip_reputation",
                    "result": {"reputation": "malicious"},
                },
                {"type": "verdict", "input": {"verdict": "true_positive"}},
            ],
        )


class FakePersist:
    def __init__(self):
        self.records: list[dict] = []

    async def __call__(self, alert, triage, **kwargs):
        self.records.append({"alert": alert, "triage": triage, **kwargs})


# ── 升级路径走真实调查 ─────────────────────────────────────────


async def test_escalated_alert_runs_investigation():
    """escalate=true 时应真正执行 L2 调查。"""
    investigator = FakeInvestigator()
    persist = FakePersist()
    graph = build_triage_graph(
        llm=FakeTriageLLM(),
        persist=persist,
        investigator=investigator,
    )

    out = await graph.ainvoke({"alert": {"id": "a1", "signature": "X"}})

    assert len(investigator.calls) == 1
    assert out["investigation"]["verdict"] == "true_positive"
    assert out["investigation"]["confidence"] == 92


async def test_investigation_result_is_persisted_with_evidence():
    """调查结论与证据链都要落库。"""
    persist = FakePersist()
    graph = build_triage_graph(
        llm=FakeTriageLLM(),
        persist=persist,
        investigator=FakeInvestigator(),
    )

    await graph.ainvoke({"alert": {"id": "a1", "signature": "X"}})

    # 应有两条记录：L1 分诊 + L2 调查
    stages = [r["stage"] for r in persist.records]
    assert "triage" in stages
    assert "investigation" in stages

    investigation_record = next(r for r in persist.records if r["stage"] == "investigation")
    assert investigation_record["triage"]["evidence_trail"]
    assert len(investigation_record["triage"]["evidence_trail"]) == 2


async def test_investigation_uses_l1_conclusion_as_context():
    """L2 应拿到 L1 的结论作为上下文 —— 避免重复劳动。"""
    investigator = FakeInvestigator()
    graph = build_triage_graph(
        llm=FakeTriageLLM(),
        persist=FakePersist(),
        investigator=investigator,
    )

    await graph.ainvoke({"alert": {"id": "a1", "signature": "X"}})

    # 传给调查器的告警里应带上 L1 的初步结论（字段名 l1_triage）
    passed = investigator.calls[0]
    assert "l1_triage" in passed
    assert passed["l1_triage"]["verdict"] == "true_positive"


# ── 不升级则跳过（省钱）─────────────────────────────────────────


async def test_non_escalated_skips_investigation():
    """escalate=false 时不该调用 L2 —— 每条都调查会烧钱。"""
    investigator = FakeInvestigator()
    graph = build_triage_graph(
        llm=FakeTriageLLM(_triage_result(escalate=False, severity="low")),
        persist=FakePersist(),
        investigator=investigator,
    )

    await graph.ainvoke({"alert": {"id": "a1", "signature": "X"}})

    assert len(investigator.calls) == 0


async def test_manual_force_runs_investigation_even_when_not_escalated():
    """手动触发时应强制调查，不论 L1 是否要求升级。

    用途：分析人员看到某条告警觉得可疑，点"深度调查"——
    这是 Human-in-the-loop 的入口。
    """
    investigator = FakeInvestigator()
    graph = build_triage_graph(
        llm=FakeTriageLLM(_triage_result(escalate=False, severity="low")),
        persist=FakePersist(),
        investigator=investigator,
    )

    await graph.ainvoke(
        {
            "alert": {"id": "a1", "signature": "X"},
            "force_investigate": True,
        }
    )

    assert len(investigator.calls) == 1


# ── 失败降级 ───────────────────────────────────────────────────


async def test_investigation_failure_still_persists():
    """调查失败不能影响落库 —— 告警必须留下。"""
    persist = FakePersist()
    graph = build_triage_graph(
        llm=FakeTriageLLM(),
        persist=persist,
        investigator=FakeInvestigator(raise_error=True),
    )

    out = await graph.ainvoke({"alert": {"id": "a1", "signature": "X"}})

    # 仍然有两条记录：L1 成功 + L2 降级
    assert len(persist.records) == 2
    investigation_record = next(r for r in persist.records if r["stage"] == "investigation")
    assert investigation_record["triage"]["verdict"] == "needs_human_review"
    assert investigation_record["triage"]["error"] is not None
    # 图整体仍应完成
    assert out["persisted"] is True


async def test_no_investigator_configured_degrades_gracefully():
    """未配置 investigator 时（如只有 API key 用于 L1），
    升级路径应降级而不是让整条流水线崩掉。"""
    persist = FakePersist()
    graph = build_triage_graph(llm=FakeTriageLLM(), persist=persist, investigator=None)

    out = await graph.ainvoke({"alert": {"id": "a1", "signature": "X"}})

    assert out["persisted"] is True
    assert len(persist.records) == 2
    investigation_record = next(r for r in persist.records if r["stage"] == "investigation")
    assert investigation_record["triage"]["verdict"] == "needs_human_review"
