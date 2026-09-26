"""抑制规则的数据访问层。

职责：DB 行 ↔ 领域对象（SuppressionRule dataclass）的转换。
领域层不认识 SQLAlchemy，本层不认识匹配逻辑 —— 边界清晰。
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.suppression import SuppressionRuleRow
from backend.schemas.suppression import SuppressionRuleCreate
from backend.services.suppression import SuppressionRule


def _to_domain(row: SuppressionRuleRow) -> SuppressionRule:
    """DB 行 → 领域对象。"""
    return SuppressionRule(
        id=row.id.int % (2**31),  # 领域对象用 int id；UUID 取模得到稳定整数
        name=row.name,
        src_ip=row.src_ip,
        signature_id=row.signature_id,
        category=row.category,
        reason=row.reason,
        expires_at=row.expires_at,
        enabled=row.enabled,
        created_by=row.created_by,
    )


async def create(session: AsyncSession, obj: SuppressionRuleCreate) -> SuppressionRuleRow:
    row = SuppressionRuleRow(**obj.model_dump())
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row


async def list_all(session: AsyncSession, only_enabled: bool = False) -> list[SuppressionRuleRow]:
    stmt = select(SuppressionRuleRow).order_by(SuppressionRuleRow.created_at.desc())
    if only_enabled:
        stmt = stmt.where(SuppressionRuleRow.enabled.is_(True))
    return list((await session.scalars(stmt)).all())


async def load_domain_rules(session: AsyncSession) -> list[SuppressionRule]:
    """加载为领域对象列表，供 SuppressionService 使用。

    只加载**启用且未过期**的规则 —— 减少热路径上的无效比较。
    （matches_rule 里仍会再检查一次过期，那是防御性的双保险。）
    """
    now = datetime.now(UTC)
    stmt = select(SuppressionRuleRow).where(
        SuppressionRuleRow.enabled.is_(True),
        (SuppressionRuleRow.expires_at.is_(None)) | (SuppressionRuleRow.expires_at > now),
    )
    rows = (await session.scalars(stmt)).all()
    return [_to_domain(r) for r in rows]


async def delete(session: AsyncSession, rule_id: str) -> bool:
    """删除规则。返回是否真的删掉了（便于路由层返回 404）。"""
    import uuid

    try:
        row = await session.get(SuppressionRuleRow, uuid.UUID(rule_id))
    except ValueError:
        return False
    if row is None:
        return False
    await session.delete(row)
    await session.commit()
    return True
