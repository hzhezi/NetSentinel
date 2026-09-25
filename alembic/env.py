"""Alembic 运行环境。

脚手架生成的版本有三处必须改，否则 autogenerate 会用不了：
    1. target_metadata = None  → 必须指向 Base.metadata，否则扫不到任何表
    2. url 从 alembic.ini 读    → 改为从 settings.DATABASE_URL 读，
                                 避免连接串在 .ini 和 .env 两处重复维护（易漂移）
    3. 不 import 模型            → 必须 import，让模型类被注册进 metadata
"""

import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# ── 关键 import：把项目配置、Base 和**所有模型**加载进来 ──────────
# 注意 `backend.models` 这个 import 看似没用，实则必需：
# Alembic 的 autogenerate 依赖 Base.metadata 里已注册的表，
# 而表只有在模型类被 import 过才会注册（详见 backend/models/__init__.py 注释）。
# 漏掉它会让 autogenerate 生成**空迁移**，且不会报错 —— 最容易踩的坑。
import backend.models  # noqa: F401
from alembic import context
from backend.core.config import settings
from backend.core.database import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# 把连接串注入 Alembic 配置，覆盖 alembic.ini 里可能存在的占位值。
# 单一事实来源：连接串只由 settings 决定（来自 .env）。
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# autogenerate 的比对基准：拿模型元数据与数据库实际结构做 diff。
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """离线模式：只生成 SQL 文本，不连数据库。

    用途：`alembic upgrade head --sql` 可以把要执行的 SQL 打印出来，
    供 DBA 审查后再手工执行。生产环境变更前常这么做。
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # 生成 SQL 时带上比较逻辑，保证离线生成的迁移与在线一致
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # compare_type: 检测列类型变化（如 String(45) → String(64)）
        # compare_server_default: 检测 server_default 变化
        # 这两项默认关闭，不开的话"改了字段类型但 autogenerate 检测不到"，
        # 迁移会静默漏掉变更。
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """在线模式：真正连库执行迁移。

    用 NullPool 的理由：Alembic 是一次性短命进程，
    跑完就退出，没必要维护连接池。
    """
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
