"""统计 API：仪表盘的聚合数据。

这些是"读多写少"的聚合查询，全部在数据库里完成（GROUP BY），
不把明细拉回 Python 再算 —— 数据量大时后者会打满内存。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.database import get_session
from backend.repositories import alert_repository as alert_repo
from backend.repositories import triage_repository as triage_repo

router = APIRouter()


@router.get("/overview")
async def overview(session: AsyncSession = Depends(get_session)):
    """仪表盘总览：告警数、严重度分布、研判结论分布、成本汇总。

    一次返回全部指标而非拆成多个接口：
        仪表盘是首屏，多次请求会串行等待、首屏变慢。
        这些查询都很轻（索引 + 聚合），合并成一次更实用。
    """
    _, alert_total = await alert_repo.list_alerts(session, page=1, size=1)

    return {
        "alerts": {
            "total": alert_total,
            "by_severity": await alert_repo.count_by_severity(session),
        },
        "triage": {
            "by_verdict": await triage_repo.count_by_verdict(session),
            "usage": await triage_repo.usage_summary(session),
        },
    }
