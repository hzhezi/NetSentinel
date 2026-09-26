"""可复用的 ORM 列定义（Mixin）。

为什么要拆成 Mixin 而不是每个模型都写一遍：
    本项目 8 张表左右，每张都有 id 和 created_at。
    复制粘贴 8 遍 = 改一处要改 8 处，且容易漏。
    Mixin 让"每张表都有的列"只定义一次。

为什么拆成**两个**而不是一个：
    有些表需要 UUID 主键但不需要 created_at（如纯关联表），
    有些反之。拆开后可自由组合，按需继承。
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy.orm import Mapped, mapped_column


class UUIDMixin:
    """提供 UUID 主键。

    为什么用 UUID 而不是自增整数：
        - 自增 ID 会**泄露业务量**（竞对能从 ID 增长推出你有多少告警）
        - 多实例/分库时自增会冲突，UUID 天然不冲突
        - 前端拿到 UUID 也无法枚举遍历，安全性更好
    代价：UUID 占 16 字节（vs 8 字节 bigint），索引稍大。
    对这个项目的数据量，这点代价可忽略。
    """

    # default=uuid.uuid4 是**可调用对象**，SQLAlchemy 在每次 insert 时调用它，
    # 而不是在类定义时调用一次（那样所有行会得到同一个 id）。
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    """提供 created_at 记录时间。

    两个刻意的选择：
    1. server_default=func.now() —— 让**数据库**填时间，而非 Python。
       好处：多实例部署时时间源统一，不受各机器时钟偏差影响，
       且即使绕过 ORM 直接写 SQL 也有值。
    2. DateTime(timezone=True) —— 存带时区的时间（Postgres 里是 timestamptz）。
       教训：用不带时区的 naive datetime，跨时区/夏令时必然出错。
       UTC 存储 + 展示时转换，是唯一稳妥的做法。
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
