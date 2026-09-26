"""数据库连接与 Session 管理。

三个东西：engine（连接池）、AsyncSessionLocal（Session 工厂）、Base（ORM 基类）。

为什么要单独一个模块：engine 是**进程级单例**，全项目共用同一个连接池。
如果每处都 `create_async_engine(...)`，会开出 N 个连接池，
很快耗尽 Postgres 的 `max_connections`（默认才 100）。
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from backend.core.config import settings

# ── 引擎（进程级单例）───────────────────────────────────────────
# pool_pre_ping：每次从池里取连接前先探活。
#   必要性：Postgres 会主动断开空闲连接（或被防火墙/NAT 掐断），
#   池子里可能躺着"看起来存在、实际已死"的连接，用它就会报
#   "server closed the connection unexpectedly"。pre_ping 用一次
#   极轻量的探测换掉这条死连接，避免这种偶发故障。
engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    echo=False,  # 设为 True 可打印所有 SQL，调试时很有用（但很吵）
)

# ── Session 工厂 ───────────────────────────────────────────────
# expire_on_commit=False 的原因：
#   SQLAlchemy 默认在 commit 后让 ORM 对象"过期"，下次访问属性会重新查库。
#   但我们是 async 的 —— commit 之后若已离开 session 上下文，
#   访问属性会触发一次"隐式的同步查询"而爆炸（MissingGreenlet）。
#   关掉它，commit 后对象仍持有已加载的数据，可以安全地传给上层序列化。
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """所有 ORM 模型的基类。

    SQLAlchemy 2.0 风格：用 DeclarativeBase 而非旧的 declarative_base()。
    所有模型都继承它，Alembic 通过 Base.metadata 感知全部表结构。
    """


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI 依赖注入用的 Session 提供者。

    每次请求拿一个新 session，请求结束自动 close（归还连接）。
    注意：这里**不自动 commit** —— commit 由 repository 层显式控制，
    因为某些操作需要多个写操作在一个事务里原子完成。
    """
    async with AsyncSessionLocal() as session:
        yield session
