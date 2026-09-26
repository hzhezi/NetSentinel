"""抑制规则的 API 契约。"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SuppressionRuleCreate(BaseModel):
    """创建抑制规则的入参。"""

    name: str = Field(min_length=1, max_length=128, description="规则名称")
    src_ip: str | None = Field(default=None, description="限定源 IP（可选）")
    signature_id: int | None = Field(default=None, description="限定规则 ID（可选）")
    category: str | None = Field(default=None, description="限定分类（可选）")
    reason: str | None = Field(default=None, description="为什么加这条规则")
    expires_at: datetime | None = Field(default=None, description="过期时间（可选，用于临时抑制）")
    created_by: str | None = None

    @model_validator(mode="after")
    def require_at_least_one_condition(self):
        """至少要有一个条件 —— 空规则会匹配所有告警（等于关闭系统）。

        在**入参阶段**就拒绝，而不是等到匹配时静默失效：
        用户以为规则生效了、实际没生效，这种情况更难发现。
        """
        if not any((self.src_ip, self.signature_id, self.category)):
            raise ValueError(
                "至少要指定一个条件（src_ip / signature_id / category）—— 空规则会匹配所有告警"
            )
        return self


class SuppressionRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    src_ip: str | None = None
    signature_id: int | None = None
    category: str | None = None
    reason: str | None = None
    expires_at: datetime | None = None
    enabled: bool = True
    created_by: str | None = None
    created_at: datetime
