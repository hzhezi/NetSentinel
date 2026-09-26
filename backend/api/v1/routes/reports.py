"""安全日报 API。

流程：从数据库汇总统计数据 → 交给 ReportAgent → 返回日报。
汇总在数据库完成（GROUP BY），不把明细拉回 Python。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.agents.report import ReportAgent
from backend.core.config import settings
from backend.core.database import get_session
from backend.models.alert import Alert
from backend.models.triage_result import TriageResultRow
from backend.repositories import triage_repository as triage_repo

log = structlog.get_logger(__name__)
router = APIRouter()


async def collect_stats(session: AsyncSession, hours: int = 24) -> dict:
    """汇总指定时间窗内的统计数据。

    全部在数据库里聚合 —— 数据量大时把明细拉回 Python 会打满内存。
    """
    since = datetime.now(UTC) - timedelta(hours=hours)

    # 总数
    total = int(
        await session.scalar(
            select(func.count()).select_from(Alert).where(Alert.detected_at >= since)
        )
        or 0
    )

    # 按严重度
    sev_rows = (
        await session.execute(
            select(Alert.severity, func.count())
            .where(Alert.detected_at >= since)
            .group_by(Alert.severity)
        )
    ).all()
    by_severity = {s: int(c) for s, c in sev_rows}

    # 按攻击类型（用签名近似 —— attack_type 字段当前多为空）
    type_rows = (
        await session.execute(
            select(Alert.signature, func.count())
            .where(Alert.detected_at >= since)
            .group_by(Alert.signature)
            .order_by(func.count().desc())
            .limit(5)
        )
    ).all()
    by_attack_type = {s: int(c) for s, c in type_rows}

    # 高频来源 IP
    src_rows = (
        await session.execute(
            select(Alert.src_ip, func.count())
            .where(Alert.detected_at >= since)
            .group_by(Alert.src_ip)
            .order_by(func.count().desc())
            .limit(5)
        )
    ).all()
    top_sources = [{"src_ip": ip, "count": int(c)} for ip, c in src_rows]

    # 研判结论分布
    by_verdict = await triage_repo.count_by_verdict(session)
    usage = await triage_repo.usage_summary(session)

    # 重点事件：高严重度或需人工复核的告警
    notable_rows = (
        (
            await session.execute(
                select(Alert)
                .where(
                    Alert.detected_at >= since,
                    Alert.severity.in_(["critical", "high"]),
                )
                .order_by(Alert.detected_at.desc())
                .limit(8)
            )
        )
        .scalars()
        .all()
    )

    # 为每条重点事件附上最新研判结论
    notable = []
    for a in notable_rows:
        triage_rows = (
            (
                await session.execute(
                    select(TriageResultRow)
                    .where(TriageResultRow.alert_id == a.id)
                    .order_by(TriageResultRow.created_at.desc())
                    .limit(1)
                )
            )
            .scalars()
            .first()
        )
        notable.append(
            {
                "signature": a.signature,
                "severity": a.severity,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "verdict": triage_rows.verdict if triage_rows else "未研判",
            }
        )

    return {
        "period_start": since.isoformat(),
        "period_end": datetime.now(UTC).isoformat(),
        "alerts": {
            "total": total,
            "by_severity": by_severity,
            "by_attack_type": by_attack_type,
            "top_sources": top_sources,
        },
        "triage": {
            "by_verdict": by_verdict,
            "total_tokens": usage["total_tokens"],
            "avg_latency_ms": (
                int(usage["total_latency_ms"] / usage["count"]) if usage["count"] else 0
            ),
        },
        "notable_alerts": notable,
        # 抑制规则的统计当前未单独记录，先给 0（诚实反映"不掌握该数据"）
        "suppressed_count": 0,
    }


def _build_llm():
    """构造日报用的 LLM 客户端；未配置 key 时返回 None（走模板路径）。"""
    if not settings.DEEPSEEK_API_KEY:
        return None
    from backend.agents.llm_client import LLMClient

    return LLMClient(settings.DEEPSEEK_API_KEY, settings.DEEPSEEK_BASE_URL, settings.TRIAGE_MODEL)


@router.get("/daily")
async def get_daily_report(
    hours: int = Query(24, ge=1, le=720, description="统计最近多少小时"),
    session: AsyncSession = Depends(get_session),
):
    """生成安全日报。

    同步执行（LLM 生成约 5-15 秒）。未配置 LLM 时返回模板日报。
    """
    stats = await collect_stats(session, hours=hours)
    agent = ReportAgent(llm=_build_llm())
    result = agent.generate(stats)
    return {
        "report": result.content,
        "generated_by_llm": result.generated_by_llm,
        "error": result.error,
        "stats": stats,
    }


@router.get("/stats")
async def get_stats(
    hours: int = Query(24, ge=1, le=720),
    session: AsyncSession = Depends(get_session),
):
    """只返回统计数据（不调 LLM）—— 供前端快速展示概览。"""
    return await collect_stats(session, hours=hours)
