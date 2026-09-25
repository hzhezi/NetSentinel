"""告警相关的 Pydantic Schema（API 数据契约）。

与 models/alert.py 的关系：
    models 定义**数据库**结构，schemas 定义**API**接口结构。
    两者刻意分开，而不是让 ORM 模型直接当接口模型 —— 原因：

    1. 入参/出参需要的字段不同。创建时不该让客户端传 id（数据库生成）；
       响应时又必须带上 id、created_at、status。
    2. 数据库内部字段不该暴露给前端（如 dedup_key）。
    3. ORM 模型若同时承担 API 契约，改一个字段会同时影响两边，
       无法独立演进。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# 用 Literal 而不是普通 str 声明枚举字段：
# 拼错的值会在**进模型那一刻**报错，而不是流到数据库或前端才出问题。
# 这也让 OpenAPI 文档（/docs）里这些字段自动变成下拉选项。
Severity = Literal["critical", "high", "medium", "low", "info"]
Engine = Literal["suricata", "ml"]
Status = Literal["new", "triaged", "escalated", "closed", "suppressed"]


class AlertCreate(BaseModel):
    """创建告警的入参。

    谁在用它：检测层在把引擎输出归一化后，用这个模型校验并落库。
    注意这里**不含** id / created_at / status —— 它们由数据库或服务层决定。
    """

    source_engine: Engine
    detected_at: datetime  # 事件原始时间，必填（重放功能依赖它）
    src_ip: str
    src_port: int | None = None
    dst_ip: str
    dst_port: int | None = None
    protocol: str | None = None
    signature: str
    attack_type: str | None = None
    severity: Severity
    # ge/le 是 Pydantic 的数值边界约束：超出范围直接报 422，
    # 避免"confidence=1.5"这种脏数据流进统计与前端进度条。
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    category: str | None = None
    raw: dict | None = None
    dedup_key: str | None = None


class AlertResponse(BaseModel):
    """告警出参（API 返回给前端）。

    这里**刻意不继承 AlertCreate**，而是独立声明字段。

    为什么放弃继承（虽然继承能省几行）：
        AlertCreate 含 dedup_key（去重内部字段）。若继承它，
        dedup_key 会一起出现在 API 响应里 —— 要么暴露内部实现，
        要么用 exclude 之类的技巧去裁剪，反而更绕。
        接口契约的**精确性**比少写几行更重要：所有对外字段一目了然，
        也不会因为将来给 AlertCreate 加字段而意外泄漏到响应中。
    """

    # from_attributes=True 允许 model_validate(orm_obj) 直接把 ORM 对象
    # 按属性名转成 Pydantic 对象。没有它，路由层就得手写
    # AlertResponse(id=row.id, src_ip=row.src_ip, ...) 逐字段复制。
    model_config = ConfigDict(from_attributes=True)

    # ── 数据库生成的字段 ──
    id: uuid.UUID
    created_at: datetime
    status: Status
    notes: str = ""

    # ── 业务字段（与 AlertCreate 对应，但不含 dedup_key）──
    source_engine: Engine
    detected_at: datetime
    src_ip: str
    src_port: int | None = None
    dst_ip: str
    dst_port: int | None = None
    protocol: str | None = None
    signature: str
    attack_type: str | None = None
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    category: str | None = None
    raw: dict | None = None


class AlertPage(BaseModel):
    """分页响应包装。

    统一形状 {items, total, page, size}：
    前端分页组件需要 total 才能算总页数；裸数组做不到。
    """

    items: list[AlertResponse]
    total: int
    page: int
    size: int
