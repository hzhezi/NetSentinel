"""ORM 模型的统一导出。

在这里集中 import 有一个**关键作用**：Alembic 的 autogenerate 靠
`Base.metadata` 感知全部表结构。而 metadata 只有当模型类被**真正导入**过
才会被注册。如果某个模型模块从未被 import，Alembic 就看不到它的表，
生成的迁移会遗漏 —— 这是 Alembic 最常见的坑。

因此约定：**每新增一个模型，必须在此文件 import 一次。**
"""

from backend.models.alert import Alert
from backend.models.base import TimestampMixin, UUIDMixin
from backend.models.triage_result import TriageResultRow

__all__ = ["Alert", "TimestampMixin", "TriageResultRow", "UUIDMixin"]
