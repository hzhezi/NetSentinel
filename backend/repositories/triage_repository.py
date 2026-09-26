"""研判结果的数据访问层。

与 alert_repository 分工一致：只负责"怎么存取"，不含业务判断。
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.triage_result import TriageResultRow


async def create(
    session: AsyncSession,
    *,
    alert_id: uuid.UUID,
    stage: str,
    triage: dict,
    usage: dict | None = None,
    error: str | None = None,
    model: str | None = None,
) -> TriageResultRow:
    """保存一次研判结果。

    接受 AlertCreate 风格的分参数而非一个 Pydantic 模型：
        研判结果的字段既有"模型输出"（verdict/summary...）也有
        "调用元数据"（tokens/latency/error），来源不同。
        硬塞进一个模型反而别扭。
    """
    usage = usage or {}
    row = TriageResultRow(
        alert_id=alert_id,
        stage=stage,
        verdict=triage.get("verdict") or "needs_human_review",
        severity=triage.get("severity") or "medium",
        confidence=int(triage.get("confidence") or 0),
        escalate=bool(triage.get("escalate")),
        attack_type=triage.get("attack_type"),
        summary=triage.get("summary") or "",
        mitre_techniques=triage.get("mitre_techniques") or [],
        recommended_actions=triage.get("recommended_actions") or [],
        model=model,
        prompt_tokens=int(usage.get("prompt_tokens") or 0),
        completion_tokens=int(usage.get("completion_tokens") or 0),
        latency_ms=int(triage.get("latency_ms") or 0),
        error=error,
        evidence_trail=triage.get("evidence_trail"),
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row


async def get_for_alert(session: AsyncSession, alert_id: uuid.UUID) -> list[TriageResultRow]:
    """取某条告警的全部研判结果，最新的在前。

    返回列表而非单条：同一告警可能有多次研判
    （L1 分诊 + L2 调查 + 人工重跑），详情页需要展示历史。
    """
    stmt = (
        select(TriageResultRow)
        .where(TriageResultRow.alert_id == alert_id)
        .order_by(TriageResultRow.created_at.desc())
    )
    return list((await session.scalars(stmt)).all())


async def count_by_verdict(session: AsyncSession) -> dict[str, int]:
    """按结论分组计数 —— 仪表盘用（真实攻击/误报/待复核 各多少）。"""
    stmt = select(TriageResultRow.verdict, func.count()).group_by(TriageResultRow.verdict)
    rows = (await session.execute(stmt)).all()
    return {verdict: int(count) for verdict, count in rows}


async def usage_summary(session: AsyncSession) -> dict[str, int]:
    """汇总 token 与耗时 —— 报告的成本数据来源。

    在数据库里聚合而非拉回 Python 求和：数据量大时后者会打满内存。
    """
    stmt = select(
        func.coalesce(func.sum(TriageResultRow.prompt_tokens), 0),
        func.coalesce(func.sum(TriageResultRow.completion_tokens), 0),
        func.coalesce(func.sum(TriageResultRow.latency_ms), 0),
        func.count(),
    )
    prompt, completion, latency, count = (await session.execute(stmt)).one()
    return {
        "prompt_tokens": int(prompt),
        "completion_tokens": int(completion),
        "total_tokens": int(prompt) + int(completion),
        "total_latency_ms": int(latency),
        "count": int(count),
    }
