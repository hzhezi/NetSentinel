"""LangGraph 研判图：编排分诊流程。

═══════════════════════════════════════════════════════════════════
图结构
═══════════════════════════════════════════════════════════════════
                    START
                      ↓
                  [triage]            ← LLM 分诊（L1）
                      ↓
              (条件边：是否升级？)
                 ↙          ↘
         escalate=false   escalate=true
                ↓              ↓
                │       [investigate]  ← L2 深度调查（期 2 实现，现为占位）
                │              ↓
                └──────→ [persist] ←───┘
                            ↓
                          END

为什么用 LangGraph 而不是自己写 if/else：
    1. 条件边是框架原生能力，加到 3-4 个分支时手写会乱
    2. **checkpoint 持久化**：图状态可存可恢复，天然满足"研判过程可追溯"
    3. **图可视化**：LangGraph 能导出流程图，报告与答辩直接用
    4. 期 2 加 Investigation Agent 时是"加节点"而非"重写流程"
    但编排逻辑本身很简单 —— 关键是别让框架侵蚀检测层（见 AGENTS.md §2.4）。

为什么升级判定不用纯模型输出：
    模型可能给出 needs_human_review 却忘记设 escalate。
    这里加了 **硬规则兜底**（见 _should_escalate），保证"不确定"和
    "严重"的告警一定会被升级，不依赖模型是否记得填某个字段。
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from typing import Any, TypedDict

import structlog
from langgraph.graph import END, START, StateGraph

from backend.agents.llm_client import LLMError

log = structlog.get_logger(__name__)

# 硬规则：这些严重度强制升级，不论模型怎么说。
# 理由：critical 是最严重的级别，宁可多做一次调查，不可漏过。
_FORCE_ESCALATE_SEVERITIES = {"critical"}


class TriageState(TypedDict, total=False):
    """图的状态。节点之间通过它传递数据。

    用 TypedDict 而非 dataclass：LangGraph 的约定，
    且它天然支持"字段可选"（total=False）—— 节点逐步填充。
    """

    alert: dict[str, Any]  # 输入：待研判的告警
    triage: dict[str, Any] | None  # 分诊结果
    escalated: bool  # 是否走了调查分支
    investigation: dict | None  # L2 调查结果
    usage: dict[str, int]  # token 用量
    persisted: bool  # 是否已落库
    # 手动强制调查：即使 L1 判定不必升级也执行 L2。
    # 这是 Human-in-the-loop 的入口 —— 分析人员可以推翻模型的"不必深入"。
    force_investigate: bool


def _should_escalate(triage: dict[str, Any]) -> bool:
    """判断是否升级到深度调查。

    三条判定，任一命中即升级：
        1. 模型自己说 escalate=True
        2. 结论是 needs_human_review（拿不准就该让人看）
        3. 严重度为 critical（硬规则兜底）

    第 2、3 条是**硬规则**，不依赖模型是否记得填 escalate 字段 ——
    模型漏填时若跳过调查，"不确定"的结论就没人处理了。
    """
    if triage.get("escalate"):
        return True
    if triage.get("verdict") == "needs_human_review":
        return True
    return triage.get("severity") in _FORCE_ESCALATE_SEVERITIES


def _degraded_investigation(error: str) -> dict[str, Any]:
    """构造降级的调查结论。

    调查没能完成时使用：明确标注失败原因，结论交给人工 ——
    **绝不因调查失败而让告警消失**（安全系统的基本要求）。
    """
    return {
        "verdict": "needs_human_review",
        "severity": "medium",
        "confidence": 0,
        "summary": f"深度调查未能完成，需人工复核。（原因：{error}）",
        "mitre_techniques": [],
        "recommended_actions": ["人工查看原始告警并结合其他信息判断"],
        "attack_type": None,
        "escalate": True,
        "evidence_trail": [],
        "iterations": 0,
        "error": error,
    }


def build_triage_graph(
    llm: Any,
    persist: Callable[..., Awaitable[None]],
    investigator: Any | None = None,
):
    """构建并编译研判图。

    Args:
        llm: 具备 `triage(alert) -> TriageResult` 与 `last_usage` 的对象。
             依赖注入而非内部构造：测试可注入假客户端，
             也便于将来切换模型/供应商。
        persist: 落库函数，签名 `(alert, triage, stage, usage, error) -> None`。
                 同样用注入 —— 图不该知道数据存哪。
        investigator: L2 调查器（具备 `investigate(alert)`）。
                      None 表示未配置：升级路径会降级为 needs_human_review，
                      **而不是让流水线崩掉**（可能只配了 L1 的 key）。
    """

    async def triage_node(state: TriageState) -> TriageState:
        """LLM 分诊节点。

        失败降级而非中断：LLM 可能因限流/超时/输出不合规而失败。
        若此时直接丢弃告警，等于"因为研判器故障而漏掉了攻击" ——
        安全系统不能接受。降级为 needs_human_review，保证告警仍在队列里。
        """
        alert = state["alert"]
        started = time.monotonic()

        try:
            result = llm.triage(alert)
            triage = result.model_dump()
            triage["error"] = None
            usage = dict(getattr(llm, "last_usage", {}) or {})
        except LLMError as exc:
            log.warning("triage_failed_degrading", alert_id=alert.get("id"), error=str(exc))
            triage = {
                "verdict": "needs_human_review",
                "severity": "medium",
                "confidence": 0,
                # 失败时强制升级：让人来补上这次自动研判的缺口
                "escalate": True,
                "attack_type": None,
                "summary": f"自动研判失败，需人工复核。（原因：{exc}）",
                "mitre_techniques": [],
                "recommended_actions": ["人工查看原始告警并判断"],
                "error": str(exc),
            }
            usage = {"prompt_tokens": 0, "completion_tokens": 0}

        # 记录耗时，供报告的性能数据使用
        triage["latency_ms"] = int((time.monotonic() - started) * 1000)
        # 在此写入 escalated 状态：条件边只负责"选路"，
        # 而"是否升级过"是需要被持久化/统计的事实，必须由节点写入状态。
        #
        # force_investigate 必须一并回传：LangGraph 用节点返回的 dict
        # 做部分更新，但**没有显式回传的字段不会保留在后续节点的可见状态里**。
        # 漏掉它会导致手动触发失效（条件边读不到该标志）。
        return {
            "triage": triage,
            "usage": usage,
            "escalated": _should_escalate(triage) or bool(state.get("force_investigate")),
            "force_investigate": state.get("force_investigate", False),
        }

    async def investigate_node(state: TriageState) -> TriageState:
        """L2 深度调查节点：工具驱动的多轮调查。

        把 L1 的初步结论一并传给调查器作为上下文 ——
        它已经做了一轮快速判断，L2 不必从零开始。

        三种降级情形（都不让流水线崩掉）：
            1. 未配置 investigator（可能只配了 L1 的 key）
            2. 调查过程抛异常
            3. 调查返回了失败结论（error 非空）
        统一降级为 needs_human_review 并落库 —— 告警绝不能丢。
        """
        alert = state["alert"]
        l1_triage = state.get("triage") or {}

        # 把 L1 结论附在告警上，供调查器参考
        enriched_alert = dict(alert)
        enriched_alert["l1_triage"] = {
            "verdict": l1_triage.get("verdict"),
            "severity": l1_triage.get("severity"),
            "confidence": l1_triage.get("confidence"),
            "summary": l1_triage.get("summary"),
        }

        if investigator is None:
            log.info("investigator_not_configured", alert_id=alert.get("id"))
            return {"investigation": _degraded_investigation("未配置深度调查器（缺失 LLM 配置）")}

        try:
            result = investigator.investigate(enriched_alert)
            payload = {
                "verdict": result.verdict,
                "severity": result.severity,
                "confidence": result.confidence,
                "summary": result.summary,
                "mitre_techniques": result.mitre_techniques,
                "recommended_actions": result.recommended_actions,
                "attack_type": result.attack_type,
                "escalate": True,
                "evidence_trail": result.evidence_trail,
                "iterations": result.iterations,
                "error": result.error,
            }
        except Exception as exc:
            # 调查器 bug / API 故障：降级而非中断
            log.warning(
                "investigation_failed_degrading",
                alert_id=alert.get("id"),
                error=str(exc),
            )
            payload = _degraded_investigation(str(exc))

        return {"investigation": payload}

    async def persist_node(state: TriageState) -> TriageState:
        """落库节点。

        无论走哪条分支都会到达这里，因此落库是统一收口点 ——
        不会出现"某条分支忘了存"的情况。

        保存两条记录（若走过调查）：
            stage="triage"         L1 分诊结论
            stage="investigation"  L2 调查结论 + 证据链
        分开存而非合并，是为了保留"分级研判"的完整历史 ——
        评测时能分别统计两级的准确率。
        """
        alert = state["alert"]
        triage = state.get("triage") or {}

        await persist(
            alert,
            triage,
            stage="triage",
            usage=state.get("usage", {}),
            error=triage.get("error"),
        )

        investigation = state.get("investigation")
        if investigation:
            # L2 的 token 用量已包含在 investigator 内部统计中，
            # 这里不重复传 -- 传空 dict，由 repository 用默认值兜底
            await persist(
                alert,
                investigation,
                stage="investigation",
                usage={},
                error=investigation.get("error"),
            )

        return {"persisted": True}

    def route_after_triage(state: TriageState) -> str:
        """条件边：决定 triage 之后走哪条路。

        force_investigate 优先：手动触发时不论 L1 结论如何都执行 L2。
        这是 Human-in-the-loop 的入口 —— 分析人员可以推翻模型的"不必深入"。
        """
        if state.get("force_investigate"):
            return "investigate"
        return "investigate" if _should_escalate(state.get("triage") or {}) else "persist"

    # ── 组装图 ────────────────────────────────────────────────
    graph = StateGraph(TriageState)
    graph.add_node("triage", triage_node)
    graph.add_node("investigate", investigate_node)
    graph.add_node("persist", persist_node)

    graph.add_edge(START, "triage")
    graph.add_conditional_edges(
        "triage",
        route_after_triage,
        # 显式声明分支目标：LangGraph 靠它画图与校验
        {"investigate": "investigate", "persist": "persist"},
    )
    # 两条分支都汇入 persist —— 统一收口
    graph.add_edge("investigate", "persist")
    graph.add_edge("persist", END)

    return graph.compile()


def mark_escalated(state: TriageState) -> bool:
    """供外部（如测试或调用方）判断该状态是否升级过。

    单独暴露而非写死在图里：升级判定是业务规则，
    调用方可能想用它做统计（如"升级率"指标）。
    """
    return _should_escalate(state.get("triage") or {})
