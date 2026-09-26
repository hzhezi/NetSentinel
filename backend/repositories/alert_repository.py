"""告警数据访问层。

职责边界（重要）：
    这里**只负责"怎么存取数据"** —— 拼查询、做分页、排序、聚合。
    不包含任何业务判断（如"这条该不该被抑制"），也不抛业务异常。
    业务规则属于 services/ 层。

    这样划分的好处：将来换数据库、加缓存、改索引策略，只动这一层，
    service 层的行为语义不变。

关于返回 None 而不是抛异常：
    get() 查不到返回 None。查不到是**正常情况**（前端可能传了已删除的 id），
    用异常表达"正常情况"会让调用方被迫写 try/except 来控制流程。
    至于上层要不要把它变成 HTTP 404，那是 API 层的决定。
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.alert import Alert
from backend.schemas.alert import AlertCreate


async def create(session: AsyncSession, obj: AlertCreate | dict) -> Alert:
    """创建一条告警。

    同时接受 AlertCreate 和 dict：
        检测层归一化后产出的是 dict（normalize_alert 的返回值），
        如果只接受 AlertCreate，调用方就得手动多转一次。
        这里用 model_dump() 统一成 dict 再实例化，两种入参走同一条路径。
    """
    data = obj.model_dump() if isinstance(obj, AlertCreate) else dict(obj)
    alert = Alert(**data)
    session.add(alert)
    await session.commit()
    # commit 后刷新，把数据库生成的字段（id/created_at/status 默认值）
    # 读回对象。因为 expire_on_commit=False，refresh 是唯一可靠的
    # "拿到最终状态"的方式（尤其 status 有 Python 侧 default）。
    await session.refresh(alert)
    return alert


async def get(session: AsyncSession, alert_id: uuid.UUID | str) -> Alert | None:
    """按 id 查单条，查不到返回 None。"""
    # 允许传 str：URL 路径参数是字符串，没必要让每个调用方自己转 UUID
    if isinstance(alert_id, str):
        try:
            alert_id = uuid.UUID(alert_id)
        except ValueError:
            return None  # 格式非法的 id 同样视为"查不到"
    return await session.get(Alert, alert_id)


async def list_alerts(
    session: AsyncSession,
    page: int = 1,
    size: int = 20,
    severity: str | None = None,
    source_engine: str | None = None,
    status: str | None = None,
    q: str | None = None,
) -> tuple[list[Alert], int]:
    """分页查询告警，返回 (本页数据, 满足条件的总数)。

    函数名刻意不叫 `list`：那会**遮蔽 Python 内置的 list**，
    使本模块内任何 `list(...)` 调用变成递归调用自身（返回 coroutine）。
    报错信息是 'coroutine' object is not iterable，完全不指向真实原因 ——
    这是真实踩过的坑。

    为什么同时返回 total：
        前端分页组件需要它算总页数。分开查两次（一次取数据一次 count）
        会导致两次查询条件必须手工保持一致，容易漏。
        这里在同一次调用里完成，保证两者口径一致。
    """
    # 构造过滤条件：所有非空条件之间是 AND
    conditions = []
    if severity:
        conditions.append(Alert.severity == severity)
    if source_engine:
        conditions.append(Alert.source_engine == source_engine)
    if status:
        conditions.append(Alert.status == status)
    if q:
        # ilike = 不区分大小写的 LIKE。用户搜 "nmap" 应能匹配 "Nmap"。
        # 注意：这里用 %q% 是"任意位置包含"。
        conditions.append(Alert.signature.ilike(f"%{q}%"))

    # count 查询：复用同一组 conditions，保证与数据查询口径一致。
    # select(func.count()).select_from(...) 是 SQLAlchemy 2.0 的推荐写法，
    # 比旧的 `query.count()` 更明确。
    count_stmt = select(func.count()).select_from(Alert)
    if conditions:
        count_stmt = count_stmt.where(*conditions)
    total = int(await session.scalar(count_stmt) or 0)

    # 数据查询
    stmt = select(Alert)
    if conditions:
        stmt = stmt.where(*conditions)
    # 默认按**事件时间**倒序，而不是 created_at：
    # 重放历史流量时，detected_at 才是用户关心的"攻击时间线"，
    # created_at 只是"数据入库时间"，两者可能相差很大。
    # 加 id 作为次级排序键，避免 detected_at 相同时的顺序不确定
    # （不确定的排序会导致分页时记录重复或遗漏）。
    stmt = stmt.order_by(Alert.detected_at.desc(), Alert.id.desc())
    stmt = stmt.offset((page - 1) * size).limit(size)

    items = list((await session.scalars(stmt)).all())
    return items, total


async def count_by_severity(session: AsyncSession) -> dict[str, int]:
    """按严重度统计数量，供仪表盘的分布图使用。

    在数据库里用 GROUP BY 聚合，而不是把全部记录拉到 Python 再统计 ——
    后者在数据量大时会把内存打满。
    """
    stmt = select(Alert.severity, func.count()).group_by(Alert.severity)
    rows = (await session.execute(stmt)).all()
    return {severity: int(count) for severity, count in rows}
