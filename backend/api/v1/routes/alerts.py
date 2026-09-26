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


# ── 手动触发深度调查 ────────────────────────────────────────────


async def _run_investigation(alert_id, session):
    """执行一次 L2 深度调查并落库。

    单独抽成模块级函数（而非路由内联）是为了**可测试** ——
    测试通过 monkeypatch 替换它，避免真实调用 LLM（花钱且慢）。

    与图中 investigate 节点的区别：
        图中节点是"L1 判定升级时自动执行"；
        这里入口是"人工点击触发"，两者共用同一个 InvestigationAgent，
        但入口与触发条件不同。
    """
    from backend.agents.investigation import InvestigationAgent
    from backend.agents.llm_client import LLMClient
    from backend.core.config import settings
    from backend.repositories import alert_repository as alert_repo
    from backend.repositories import triage_repository as triage_repo

    row = await alert_repo.get(session, alert_id)
    if row is None:
        raise NotFoundError(f"告警不存在: {alert_id}")

    # 构造调查上下文：提供近期告警池让"关联告警"工具可用
    recent, _ = await alert_repo.list_alerts(session, page=1, size=100)
    alert_pool = [
        {
            "id": str(a.id),
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "signature": a.signature,
            "severity": a.severity,
            "detected_at": a.detected_at.isoformat() if a.detected_at else None,
        }
        for a in recent
    ]

    def _lookup(aid: str):
        """给 get_alert_detail 工具用的查询函数。"""
        for a in recent:
            if str(a.id) == aid:
                return {
                    "id": str(a.id),
                    "signature": a.signature,
                    "category": a.category,
                    "severity": a.severity,
                    "src_ip": a.src_ip,
                    "dst_ip": a.dst_ip,
                    "raw": a.raw,
                }
        return None

    context = {"alert_pool": alert_pool, "exclude_id": str(row.id), "alert_lookup": _lookup}

    # 未配置 key 时降级
    if not settings.DEEPSEEK_API_KEY:
        return await triage_repo.create(
            session,
            alert_id=row.id,
            stage="investigation",
            triage={
                "verdict": "needs_human_review",
                "severity": "medium",
                "confidence": 0,
                "summary": "未配置 LLM API Key，无法执行深度调查，需人工复核。",
                "mitre_techniques": [],
                "recommended_actions": [],
                "evidence_trail": [],
            },
            error="LLM API key not configured",
        )

    llm = LLMClient(
        settings.DEEPSEEK_API_KEY,
        settings.DEEPSEEK_BASE_URL,
        settings.INVESTIGATION_MODEL,
    )
    agent = InvestigationAgent(llm=llm, tool_context=context)

    alert_dict = {
        "id": str(row.id),
        "signature": row.signature,
        "category": row.category,
        "severity": row.severity,
        "src_ip": row.src_ip,
        "src_port": row.src_port,
        "dst_ip": row.dst_ip,
        "dst_port": row.dst_port,
        "protocol": row.protocol,
        "detected_at": row.detected_at.isoformat() if row.detected_at else None,
    }

    result = agent.investigate(alert_dict)

    return await triage_repo.create(
        session,
        alert_id=row.id,
        stage="investigation",
        triage={
            "verdict": result.verdict,
            "severity": result.severity,
            "confidence": result.confidence,
            "summary": result.summary,
            "mitre_techniques": result.mitre_techniques,
            "recommended_actions": result.recommended_actions,
            "attack_type": result.attack_type,
            "escalate": True,
            "evidence_trail": result.evidence_trail,
            "latency_ms": result.latency_ms,
        },
        usage=result.usage,
        error=result.error,
        model=settings.INVESTIGATION_MODEL,
    )


@router.post("/{alert_id}/investigate", response_model=TriageResultResponse)
async def investigate_alert(alert_id: str, session: AsyncSession = Depends(get_session)):
    """手动触发深度调查（L2）。

    用途：分析人员看到某条告警觉得可疑，主动要求深入调查 ——
    即使 L1 判定"无需升级"。这是 Human-in-the-loop 的入口。

    同步执行（实测 6-9 秒）：用户体验上"等待后看到结果"
    比"丢后台任务不知何时好"更清晰，也便于前端直接渲染。
    """
    row = await repo.get(session, alert_id)
    if row is None:
        raise NotFoundError(f"告警不存在: {alert_id}")

    result_row = await _run_investigation(row.id, session)
    return TriageResultResponse.model_validate(result_row)
