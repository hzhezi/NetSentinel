"""Report Agent：生成安全日报。

═══════════════════════════════════════════════════════════════════
定位：独立于实时研判主图的**汇总任务**
═══════════════════════════════════════════════════════════════════
    实时研判（Triage / Investigation）
        触发：每条告警
        视角：单条
        耗时：秒级
        模型：deepseek-chat / deepseek-reasoner

    日报（Report Agent）
        触发：定时（如每小时）或手动
        视角：全局
        耗时：十几秒
        模型：deepseek-chat（汇总任务不需要强推理）

**为什么不放进 LangGraph 主图**：
    两者的输入规模、触发时机、输出形态完全不同 ——
    混进主图会让图变脏（一个节点处理"单条告警"、
    另一个处理"一万条汇总"，状态定义会互相妥协），
    且日报无法独立调度。

═══════════════════════════════════════════════════════════════════
两个关键设计
═══════════════════════════════════════════════════════════════════

① **输入是统计摘要，不是明细**
    把几万条告警塞给 LLM 会 token 爆炸且无必要 ——
    日报的读者关心"多少、什么类型、最该关注什么"，
    这些从统计里就能得到。明细只挑**重点事件**若干条。

② **LLM 失败时降级为模板日报**
    日报的基础价值（数字汇总）不依赖 LLM：
    "今日 128 条告警、3 条严重" 这些从统计直接可得。
    模型只负责"把它写成人话"。因此模型故障时仍产出模板版，
    值班人员不会一无所获。
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

import structlog

log = structlog.get_logger(__name__)

REPORT_SYSTEM = """你是 SOC 值班分析师，撰写一份简洁的安全日报。

要求：
- 用中文，面向安全团队与管理者。
- **数字必须准确**，直接引用给出的统计数据，不得估算或编造。
- **不要夸大威胁**：有多少说多少，没有发现异常的就说"未见异常"。
- 结构：总体态势 → 重点关注 → 处置建议。控制在 300 字以内。
- 若存在需人工复核的告警，必须明确列出，不要省略。
"""


@dataclass
class ReportResult:
    """日报产出。"""

    content: str
    period_start: str
    period_end: str
    # 是否由 LLM 生成。False 表示走了模板降级路径
    generated_by_llm: bool = True
    usage: dict[str, int] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_template_report(stats: dict[str, Any]) -> str:
    """基于统计生成模板日报（LLM 不可用时的降级路径）。

    纯数字汇总 —— 不含分析，但保证"有内容、数字准"。
    """
    alerts = stats.get("alerts", {})
    triage = stats.get("triage", {})
    total = alerts.get("total", 0)

    lines = [f"【安全日报】{stats.get('period_start', '')} 至 {stats.get('period_end', '')}", ""]

    if total == 0:
        lines.append("本时段内未产生告警，未见异常。")
        return "\n".join(lines)

    lines.append(f"共处理告警 {total} 条。")

    by_sev = alerts.get("by_severity") or {}
    if by_sev:
        sev_text = "、".join(f"{k} {v} 条" for k, v in by_sev.items())
        lines.append(f"严重度分布：{sev_text}。")

    by_type = alerts.get("by_attack_type") or {}
    if by_type:
        top = sorted(by_type.items(), key=lambda kv: -kv[1])[:3]
        lines.append("主要攻击类型：" + "、".join(f"{k}（{v}）" for k, v in top) + "。")

    top_src = alerts.get("top_sources") or []
    if top_src:
        lines.append(
            "高频来源 IP："
            + "、".join(f"{s.get('src_ip')}（{s.get('count')} 次）" for s in top_src[:3])
            + "。"
        )

    by_verdict = triage.get("by_verdict") or {}
    if by_verdict:
        lines.append(
            "AI 研判结论：" + "、".join(f"{k} {v} 条" for k, v in by_verdict.items()) + "。"
        )
        nhr = by_verdict.get("needs_human_review", 0)
        if nhr:
            lines.append(f"**其中 {nhr} 条需人工复核，请优先处理。**")

    suppressed = stats.get("suppressed_count", 0)
    if suppressed:
        lines.append(f"另有 {suppressed} 条被抑制规则过滤（已知噪声）。")

    notable = stats.get("notable_alerts") or []
    if notable:
        lines.append("")
        lines.append("重点事件：")
        for a in notable[:5]:
            lines.append(
                f"  - [{a.get('severity')}] {a.get('signature')} "
                f"来自 {a.get('src_ip')}（研判：{a.get('verdict')}）"
            )

    return "\n".join(lines)


class ReportAgent:
    """日报生成器。

    依赖注入 llm（需实现 complete_text）：
        传 None 表示未配置 —— 直接走模板路径，
        而不是抛异常（日报不该因缺少 key 而完全失败）。
    """

    def __init__(self, llm: Any | None = None):
        self.llm = llm

    def generate(self, stats: dict[str, Any]) -> ReportResult:
        """根据统计数据生成日报。

        失败时降级为模板日报 —— 保证"有产出"，
        因为数字汇总本身就有价值，不该因模型故障而丢失。
        """
        period_start = stats.get("period_start", "")
        period_end = stats.get("period_end", "")

        # 未配置 LLM：直接走模板
        if self.llm is None:
            log.info("report_llm_not_configured_using_template")
            return ReportResult(
                content=build_template_report(stats),
                period_start=period_start,
                period_end=period_end,
                generated_by_llm=False,
            )

        user_prompt = self._build_prompt(stats)
        try:
            content = self.llm.complete_text(REPORT_SYSTEM, user_prompt).strip()
            return ReportResult(
                content=content,
                period_start=period_start,
                period_end=period_end,
                generated_by_llm=True,
                usage=dict(getattr(self.llm, "last_usage", {}) or {}),
            )
        except Exception as exc:
            # 模型故障：降级而非失败（见模块顶部说明）
            log.warning("report_llm_failed_using_template", error=str(exc))
            return ReportResult(
                content=build_template_report(stats),
                period_start=period_start,
                period_end=period_end,
                generated_by_llm=False,
                error=str(exc),
            )

    @staticmethod
    def _build_prompt(stats: dict[str, Any]) -> str:
        """构造提示词。

        只传统计摘要 + 少量重点事件 —— 明细不进提示词（成本控制）。
        """
        alerts = stats.get("alerts", {})
        triage = stats.get("triage", {})

        parts = [
            f"统计时段：{stats.get('period_start')} 至 {stats.get('period_end')}",
            "",
            f"告警总数：{alerts.get('total', 0)}",
            f"严重度分布：{json.dumps(alerts.get('by_severity') or {}, ensure_ascii=False)}",
            f"攻击类型分布：{json.dumps(alerts.get('by_attack_type') or {}, ensure_ascii=False)}",
            f"高频来源 IP：{json.dumps(alerts.get('top_sources') or [], ensure_ascii=False)}",
            "",
            f"AI 研判结论分布：{json.dumps(triage.get('by_verdict') or {}, ensure_ascii=False)}",
            f"被抑制规则过滤的告警数：{stats.get('suppressed_count', 0)}",
        ]

        notable = stats.get("notable_alerts") or []
        if notable:
            parts += ["", "重点事件（请务必在日报中提及）："]
            for a in notable[:8]:
                parts.append(
                    f"  - [{a.get('severity')}] {a.get('signature')} "
                    f"来自 {a.get('src_ip')}，研判结论：{a.get('verdict')}"
                )

        parts += ["", "请据此撰写安全日报。"]
        return "\n".join(parts)
