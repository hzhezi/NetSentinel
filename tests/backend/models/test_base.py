"""ORM Mixin 的测试。

**跑在真 PostgreSQL 上**（fixture 见 tests/conftest.py）。
这里测的是"插入后 id/created_at 是否自动生成"这类真实行为，
需要真实数据库语义（尤其 server_default 由数据库执行，SQLite 不可信）。
"""

import uuid

from sqlalchemy import String, select
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base
from backend.models.base import TimestampMixin, UUIDMixin


# 临时模型用于测试 Mixin。表建在测试专用 schema 里，测完随 schema 销毁。
class _Widget(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "tmp_widget"
    name: Mapped[str] = mapped_column(String(20))


async def test_uuid_generated_on_insert(pg_session):
    """插入后 id 应被自动填上合法 UUID —— UUIDMixin 的核心契约。"""
    widget = _Widget(name="a")
    pg_session.add(widget)
    await pg_session.commit()

    assert isinstance(widget.id, uuid.UUID)


async def test_each_row_gets_distinct_uuid(pg_session):
    """两行的 id 必须不同。

    防的是"default 在类定义时求值一次"的经典错误 ——
    若写成 `default=uuid.uuid4()`（带括号），所有行会共享同一 id。
    """
    a, b = _Widget(name="a"), _Widget(name="b")
    pg_session.add_all([a, b])
    await pg_session.commit()

    assert a.id != b.id


async def test_created_at_filled_by_database(pg_session):
    """created_at 由数据库的 now() 填充 —— 这才是真正验证了 server_default。"""
    widget = _Widget(name="a")
    pg_session.add(widget)
    await pg_session.commit()

    assert widget.created_at is not None


async def test_created_at_is_timezone_aware(pg_session):
    """PG 的 timestamptz 读回来必须带时区。

    这条是**只有真 PG 才能测**的：SQLite 不保留时区信息，
    用内存库测时我们不得不写 .replace(tzinfo=None) 绕过，
    那等于放弃了时区正确性的验证。
    """
    widget = _Widget(name="a")
    pg_session.add(widget)
    await pg_session.commit()
    await pg_session.refresh(widget)

    assert widget.created_at.tzinfo is not None


async def test_mixins_compose_together(pg_session):
    """两个 Mixin 同时生效，且能被正常查询回来。"""
    pg_session.add(_Widget(name="roundtrip"))
    await pg_session.commit()

    rows = (await pg_session.scalars(select(_Widget))).all()
    assert len(rows) == 1
    assert rows[0].name == "roundtrip"
    assert rows[0].id is not None
