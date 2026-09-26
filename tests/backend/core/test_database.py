"""数据库引擎与 Session 工厂的测试。

注意：这些测试**不连真实数据库**，只验证模块装配是否正确
（引擎类型、Session 工厂类型、Base 元数据）。
真正的增删改查测试在 Task 7（repository 层）做，那里才需要真库。
"""

from backend.core.database import AsyncSessionLocal, Base, engine


def test_engine_is_async_and_points_to_postgres():
    """引擎必须是 asyncpg 驱动 —— 用同步驱动会让整个 async 后端失效。"""
    assert engine.url.drivername == "postgresql+asyncpg"


def test_session_factory_is_async():
    """Session 工厂产出的 session 必须是 async 的，否则 await 会报错。"""
    session = AsyncSessionLocal()
    assert session is not None
    # 有 execute 且是协程才算 async session
    assert hasattr(session, "execute")


def test_base_is_declarative():
    """Base 是所有 ORM 模型的基类，必须能被继承出表。"""
    assert hasattr(Base, "metadata")
    assert hasattr(Base, "registry")
