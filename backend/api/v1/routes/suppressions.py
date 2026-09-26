"""抑制规则的 API。

用途：让用户通过界面管理"已知噪声"规则，而不必直接改数据库。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.database import get_session
from backend.core.exceptions import NotFoundError
from backend.repositories import suppression_repository as repo
from backend.schemas.suppression import SuppressionRuleCreate, SuppressionRuleResponse

router = APIRouter()


@router.get("", response_model=list[SuppressionRuleResponse])
async def list_rules(session: AsyncSession = Depends(get_session)):
    """列出全部抑制规则（含已停用的，便于管理）。"""
    rows = await repo.list_all(session)
    return [SuppressionRuleResponse.model_validate(r) for r in rows]


@router.post("", response_model=SuppressionRuleResponse, status_code=201)
async def create_rule(body: SuppressionRuleCreate, session: AsyncSession = Depends(get_session)):
    """创建抑制规则。

    空规则（无条件）会被 schema 校验拒绝 —— 它会匹配所有告警。
    """
    row = await repo.create(session, body)
    return SuppressionRuleResponse.model_validate(row)


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(rule_id: str, session: AsyncSession = Depends(get_session)):
    """删除规则。不存在返回 404。"""
    if not await repo.delete(session, rule_id):
        raise NotFoundError(f"抑制规则不存在: {rule_id}")
