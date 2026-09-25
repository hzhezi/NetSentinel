"""ORM Mixin 的测试。

设计说明：这里不测 SQLAlchemy 的内部实现（如 default 函数的签名），
那属于框架的职责，测它只会让测试变脆。
改为**测我们真正依赖的行为**：插入后 id 自动生成、created_at 自动填充。
用内存 SQLite 跑真实插入，不依赖 Docker。
"""

import uuid

import pytest
from sqlalchemy import String, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base
from backend.models.base import TimestampMixin, UUIDMixin


# ── 定义一个临时模型用于测试 ────────────────────────────────────
class _Widget(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "tmp_widget"
    name: Mapped[str] = mapped_column(String(20))


@pytest.fixture
async def session():
    """内存 SQLite + 建表 + 自动回滚。

    为什么用 SQLite 而不是 Postgres：
      这些测试只关心 ORM 行为（default 是否生效），不关心 PG 特有能力。
      内存库免去对 Docker 的依赖，测试跑得更快、更可移植。
      Postgres 特有功能（如 JSONB）的测试放到 Task 7。
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


async def test_uuid_generated_on_insert(session):
    """插入后 id 应被自动填上合法 UUID —— 这是 UUIDMixin 的核心契约。"""
    widget = _Widget(name="a")
    session.add(widget)
    await session.commit()

    assert isinstance(widget.id, uuid.UUID)


async def test_each_row_gets_distinct_uuid(session):
    """两行的 id 必须不同。

    这条测试防的是"default 在类定义时求值一次"的经典错误 ——
    如果写成 `id = mapped_column(default=uuid.uuid4())`（带括号），
    所有行会共享同一个 id，这条测试就会挂。
    """
    a, b = _Widget(name="a"), _Widget(name="b")
    session.add_all([a, b])
    await session.commit()

    assert a.id != b.id


async def test_created_at_filled_on_insert(session):
    """created_at 由数据库填充，插入后不应为 None。"""
    widget = _Widget(name="a")
    session.add(widget)
    await session.commit()

    assert widget.created_at is not None


async def test_mixins_compose_together(session):
    """两个 Mixin 同时生效，且能被正常查询回来。"""
    session.add(_Widget(name="roundtrip"))
    await session.commit()

    rows = (await session.scalars(select(_Widget))).all()
    assert len(rows) == 1
    assert rows[0].name == "roundtrip"
    assert rows[0].id is not None
