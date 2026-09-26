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
    investigation: dict | None  # L2 调查结果（期 1 为 None）
    usage: dict[str, int]  # token 用量
    persisted: bool  # 是否已落库


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


def build_triage_graph(
    llm: Any,
    persist: Callable[..., Awaitable[None]],
):
    """构建并编译研判图。

    Args:
        llm: 具备 `triage(alert) -> TriageResult` 与 `last_usage` 的对象。
             依赖注入而非内部构造：测试可注入假客户端，
             也便于将来切换模型/供应商。
        persist: 落库函数，签名 `(alert, triage, usage, error) -> None`。
                 同样用注入 —— 图不该知道数据存哪。
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
        return {
            "triage": triage,
            "usage": usage,
            "escalated": _should_escalate(triage),
        }

    async def investigate_node(state: TriageState) -> TriageState:
        """L2 深度调查节点（期 1 占位）。

        期 2 会替换为真正的 Investigation Agent：
        工具驱动的多轮调查 + evidence trail。
        现在保留节点是为了**让图结构完整**，期 2 只替换实现，流程不动。
        """
        log.info("investigate_placeholder", alert_id=state["alert"].get("id"))
        return {"investigation": None}

    async def persist_node(state: TriageState) -> TriageState:
        """落库节点。

        无论走哪条分支都会到达这里，因此落库是一个统一的收口点 ——
        不会出现"某条分支忘了存"的情况。
        """
        triage = state.get("triage") or {}
        alert = state["alert"]
        # 把耗时等信息一并交给持久化层
        await persist(
            alert,
            triage,
            stage="triage",
            usage=state.get("usage", {}),
            error=triage.get("error"),
        )
        return {"persisted": True}

    def route_after_triage(state: TriageState) -> str:
        """条件边：决定 triage 之后走哪条路。"""
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
