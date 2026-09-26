"""抑制规则 ORM 模型。

与 services/suppression.py 的 SuppressionRule（dataclass）分开：
    - dataclass 是**领域对象**：用于匹配逻辑，无 IO 依赖，便于测试
    - 本模型是**持久化形态**：数据库表结构
两者转换由 repository 负责。这样领域逻辑不依赖 SQLAlchemy，
也让匹配逻辑的测试不需要数据库。
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base
from backend.models.base import TimestampMixin, UUIDMixin


class SuppressionRuleRow(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "suppression_rules"

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    # 匹配条件，全部可空 —— 为空表示"不限制该字段"（AND 逻辑，见 services 说明）
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    signature_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # 为什么加这条规则（供后人理解，避免"不知道为什么有这么条规则")
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 可选过期时间。临时抑制应能自动失效，防止"忘了删"造成长期漏报。
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (Index("idx_suppression_enabled_expires", "enabled", "expires_at"),)

    def __repr__(self) -> str:
        return f"<SuppressionRule {self.name!r} src={self.src_ip} enabled={self.enabled}>"
