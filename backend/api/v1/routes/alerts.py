"""告警相关 API 路由。

**零业务逻辑**：只做参数解析、调用 service/repository、组装响应。
业务规则（什么算重复、什么该升级）都不在这里。

分页返回统一形状 {items, total, page, size} —— 前端分页组件需要 total。
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.database import get_session
from backend.core.exceptions import NotFoundError
from backend.repositories import alert_repository as repo
from backend.repositories import triage_repository as triage_repo
from backend.schemas.alert import AlertPage, AlertResponse
from backend.schemas.triage import TriageResultResponse

router = APIRouter()


@router.get("", response_model=AlertPage)
async def list_alerts(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    severity: str | None = None,
    source_engine: str | None = None,
    status: str | None = None,
    q: str | None = None,
    session: AsyncSession = Depends(get_session),
):
    """分页查询告警，支持按严重度/引擎/状态/关键字过滤。"""
    items, total = await repo.list_alerts(
        session,
        page=page,
        size=size,
        severity=severity,
        source_engine=source_engine,
        status=status,
        q=q,
    )
    return AlertPage(
        items=[AlertResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        size=size,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str, session: AsyncSession = Depends(get_session)):
    """按 id 取单条告警。查不到返回 404（由 NotFoundError 统一翻译）。"""
    row = await repo.get(session, alert_id)
    if row is None:
        raise NotFoundError(f"告警不存在: {alert_id}")
    return AlertResponse.model_validate(row)


@router.get("/{alert_id}/triage", response_model=list[TriageResultResponse])
async def get_alert_triage(alert_id: str, session: AsyncSession = Depends(get_session)):
    """取某条告警的研判结果（可能多次，最新在前）。

    这是前端"AI 研判卡片"的数据来源。
    """
    row = await repo.get(session, alert_id)
    if row is None:
        raise NotFoundError(f"告警不存在: {alert_id}")

    results = await triage_repo.get_for_alert(session, uuid.UUID(str(row.id)))
    return [TriageResultResponse.model_validate(r) for r in results]
