"""统一告警模型（UnifiedAlert）。

这是整个系统的**核心数据结构**。设计意图：

    两个检测引擎的输出形态完全不同 ——
        Suricata 给的是 eve.json（签名、sid、优先级）
        ML 给的是模型预测（标签、概率）
    如果下游管道分别处理两套结构，就等于把"引擎差异"泄漏到了
    存储层、研判层、展示层。将来加第三个引擎要改所有地方。

    所以这里定义一个**归一化目标**：两引擎各自把输出映射成 UnifiedAlert，
    下游（去重 / 抑制 / 富化 / LLM 研判 / 存储 / 推送）只认这一种结构。

字段命名注意：
    `detected_at` 是**事件本来发生的时间**（来自数据集时间戳），
    不是入库时间。入库时间是 TimestampMixin 的 `created_at`。
    两者必须分开 —— 否则"按时间戳重放"就失去意义了。
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base
from backend.models.base import TimestampMixin, UUIDMixin


class Alert(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "alerts"

    # ── 来源 ────────────────────────────────────────────────
    # "suricata" | "ml" —— 记录这条告警由哪个引擎产出，
    # 便于评测时按引擎分别统计检出率与误报率。
    source_engine: Mapped[str] = mapped_column(String(16), nullable=False, index=True)

    # ── 时间 ────────────────────────────────────────────────
    # 事件原始时间（带时区）。索引是必须的：告警列表默认按它倒序，
    # 仪表盘的时间线图也按它聚合。
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # ── 五元组 ──────────────────────────────────────────────
    # IPv6 最长 45 字符，所以给 45 而不是常见的 15（只够 IPv4）。
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    src_port: Mapped[int | None] = mapped_column(nullable=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dst_port: Mapped[int | None] = mapped_column(nullable=True, index=True)
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)

    # ── 判定 ────────────────────────────────────────────────
    # Suricata 填签名文本；ML 填预测出来的攻击类别。
    signature: Mapped[str] = mapped_column(String(512), nullable=False)
    # 归一化后的攻击类型，用于分组统计（如 DDoS / PortScan / BruteForce）。
    attack_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    # ML 给预测概率；Suricata 由 priority 映射过来。0.0 ~ 1.0。
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # ── 原始数据 ────────────────────────────────────────────
    # 用 JSON 类型，但通过 with_variant 指定"在 Postgres 上实际用 JSONB"。
    #
    # 为什么这么绕：
    #   直接写 JSONB 会让模型**只能跑在 Postgres** —— SQLite 编译器不认识它，
    #   内存库测试全部报 CompileError（我们已经踩到过）。
    #   而通用 JSON 在 Postgres 上会退化成 json（文本存储，无 GIN 索引）。
    #   with_variant 让两边各取所长：测试可移植，生产享 JSONB 的索引与查询能力。
    #
    # 保留原始记录的目的是可追溯 —— 研判结果可疑时能回看原始证据。
    raw: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    # ── 处理状态 ────────────────────────────────────────────
    # 去重键，形如 "45.33.32.156-ET SCAN Nmap OS Detection Probe"。
    # 单独存一列而非查询时拼接，是为了能用索引加速去重判断。
    dedup_key: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    # 流转状态：new → triaged → escalated / closed / suppressed
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="new", index=True
    )
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        # 复合索引：仪表盘高频查询是"最近的、高危的告警"。
        # 单列索引无法同时服务"按时间排序 + 按严重度过滤"，
        # 复合索引让两者走同一个索引。
        Index("idx_alerts_detected_severity", "detected_at", "severity"),
    )

    def __repr__(self) -> str:
        return f"<Alert {self.severity} {self.src_ip}->{self.dst_ip} {self.signature[:30]!r}>"
