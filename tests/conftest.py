"""pytest 全局 fixture。

测试策略（重要，与 AGENTS.md §1.1 的讨论结论一致）：
    **在目标环境上测试** —— 用真 PostgreSQL，不用 SQLite 替身。

为什么不用 SQLite：
    SQLite 与 PostgreSQL 行为有实质差异（无 JSONB、不存时区、
    `now()` 语义不同、无并发锁语义）。用替身测生产代码，
    会掩盖真实缺陷，属于"测了个寂寞"。

为什么可以承受：本地 Docker 常开，Postgres 一直跑着；
    CI 里用 services 起容器（Task 21）。启动成本远低于"假绿"的代价。

隔离机制：**每个测试跑在独立 schema 里**，测试结束整个 schema 删除。
    相比"连同一个库再回滚"的做法，schema 级隔离更彻底 ——
    连 DDL（建表/改表）也不会互相影响，且不依赖事务回滚的正确性。
"""

import uuid
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from backend.core.config import settings
from backend.core.database import Base


@pytest.fixture(scope="session")
def pg_url() -> str:
    """测试库连接串。

    默认从 settings 取，可用环境变量 TEST_DATABASE_URL 覆盖 ——
    这样 CI 可以指向别的实例，而不必改代码。
    """
    import os

    return os.getenv("TEST_DATABASE_URL", settings.DATABASE_URL)


@pytest.fixture
async def pg_engine(pg_url: str) -> AsyncGenerator[AsyncEngine, None]:
    """建一个临时 schema 的引擎，测试后销毁。

    每个测试一个 schema 名（带随机后缀），因此测试之间完全隔离，
    也不会碰开发库里的 public schema 数据。
    """
    from sqlalchemy.ext.asyncio import create_async_engine

    schema = f"test_{uuid.uuid4().hex[:12]}"
    # connect_args 里设置 search_path，让所有建表和查询都落在该 schema，
    # 无需在每个表名上写 schema 前缀。
    engine = create_async_engine(
        pg_url,
        poolclass=None,  # 测试用单连接，避免 schema 与会话跨连接漂移
        connect_args={"server_settings": {"search_path": schema}},
    )

    async with engine.begin() as conn:
        await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    await engine.dispose()


@pytest.fixture
async def pg_session(pg_engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """绑定到临时 schema 的 Session。"""
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with maker() as session:
        yield session
