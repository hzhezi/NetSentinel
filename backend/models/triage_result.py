"""研判结果 ORM 模型。

存储 LLM 对每条告警的研判结论。与 alerts 是一对多（一条告警可能被
研判多次 —— 重试、模型升级后重跑、人工触发深度调查）。

为什么单独一张表而不是在 alerts 上加字段：
    1. 一条告警可能有多次研判（L1 分诊 + L2 深度调查），需要历史
    2. 研判结论包含较多字段（证据链、token 用量等），混进 alerts 会让
       主表臃肿，而告警列表查询并不需要这些
    3. 模型/提示词会迭代，保留多次结果便于对比评测
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base
from backend.models.base import TimestampMixin, UUIDMixin


class TriageResultRow(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "triage_results"

    # 外键 + 级联删除：告警被删时研判结果一起消失，避免孤儿记录。
    # 用 UUID 而非自增，与 Alert 保持一致（见 models/base.py 的说明）。
    alert_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # 哪个阶段的研判："triage"（L1 快研判）/ "investigation"（L2 深度调查）
    stage: Mapped[str] = mapped_column(String(20), nullable=False, default="triage")

    # 三态结论。注意保存原始值而非布尔 —— needs_human_review 是独立结论，
    # 用 bool 表达会丢失这个语义。
    verdict: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    escalate: Mapped[bool] = mapped_column(nullable=False, default=False)
    attack_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # MITRE 技术编号与处置建议都是列表，用 JSONB 存
    mitre_techniques: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    recommended_actions: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # ── 可观测性字段（报告的成本与性能数据来源）──
    model: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prompt_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # 失败原因。成功时为 None。保留它是为了让"失败的研判"也可追溯 ——
    # 直接丢弃失败记录会让评测时的分母失真。
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # 未来 L2 深度调查的完整证据链（每步推理与工具调用）。
    # 期 1 留空，结构已备好。
    evidence_trail: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        # 仪表盘高频查询："最近的、需要人工复核的研判结果"
        Index("idx_triage_verdict_created", "verdict", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<TriageResult alert={self.alert_id} {self.verdict} conf={self.confidence}>"
