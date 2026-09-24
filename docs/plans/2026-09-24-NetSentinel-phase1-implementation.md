# NetSentinel 实施计划（期 1 详细版）

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 打通最小可用闭环 —— 上传 CICIDS2017 CSV → 按时间戳准实时重放 → ML 检测 → 统一告警 → LLM 分诊 → PostgreSQL + Web 实时流。

**Architecture:** FastAPI 分层架构（api / services / repositories / models / schemas / core），检测层与展示层通过统一告警模型解耦，LLM 研判用 LangGraph 承载。前端 React + TS 通过 WebSocket 消费实时告警。

**Tech Stack:** Python 3.12 · FastAPI · Pydantic v2 · SQLAlchemy 2.0(async) · Alembic · PostgreSQL 16 · Redis 7 · XGBoost/scikit-learn · LangGraph · DeepSeek API · React 18 + TypeScript + Vite + Ant Design + TanStack Query + Zustand

---

## 0. 前置约定

### 0.1 仓库结构（目标）
```
NetSentinel/
├── backend/                  # Python 包
│   ├── __init__.py
│   ├── main.py               # FastAPI app factory
│   ├── core/                 # config / logging / database / event_bus / exceptions
│   ├── models/               # SQLAlchemy ORM
│   ├── schemas/              # Pydantic 出入参
│   ├── repositories/         # 数据访问（Unit of Work）
│   ├── services/             # 领域逻辑
│   ├── detection/            # feeders / parsers / pipeline / ml
│   ├── agents/               # LangGraph 图、节点、prompts、tools
│   ├── api/                  # routes + websocket
│   ├── middleware/           # rate limiter / request logger / error handler
│   └── workers/              # 重放、评测、日报
├── tests/                    # pytest（镜像 backend 结构）
├── alembic/                  # 数据库迁移
├── frontend/                 # React + TS + Vite
├── scripts/                  # 数据准备、一键启动
├── docker/                   # Dockerfile / nginx.conf
├── docker-compose.yml
├── pyproject.toml
├── .env.example
└── docs/
```

### 0.2 分支策略
从 `main` 开 `feat/phase-1`，每个 Task 一次提交，阶段结束 PR 合并。

### 0.3 常用命令
```bash
uv sync                                   # 安装依赖
uv run pytest -v                          # 全部测试
uv run pytest tests/test_x.py::test_y -v  # 单测
uv run ruff check . && uv run ruff format .
uv run mypy backend
docker compose up -d db redis
uv run alembic upgrade head
uv run uvicorn backend.main:app --reload
```

### 0.4 TDD 约定
每个 Task 严格：**先写失败测试 → 运行确认失败 → 写最小实现 → 运行确认通过 → 提交**。
不允许"先实现后补测试"。

### 0.5 敏感信息约定
- `.env` 永不入库（已在 `.gitignore`）
- 只提交 `.env.example`
- **`DEEPSEEK_API_KEY` 只经环境变量注入，不写进任何代码/文档/DB**

---

# 期 1：基础闭环

## Task 1: 项目脚手架与配置

**Files:**
- Create: `pyproject.toml`
- Create: `backend/__init__.py`
- Create: `backend/core/__init__.py`
- Create: `backend/core/config.py`
- Create: `.env.example`
- Create: `.pre-commit-config.yaml`
- Test: `tests/backend/core/test_config.py`

**Step 1: 写失败测试**

```python
# tests/backend/core/test_config.py
from backend.core.config import Settings


def test_settings_defaults():
    s = Settings(_env_file=None)
    assert s.APP_ENV == "development"
    assert s.TRIAGE_MODEL == "deepseek-chat"
    assert s.ESCALATE_MIN_SEVERITY == "high"


def test_settings_reads_env(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    s = Settings(_env_file=None)
    assert s.DEEPSEEK_API_KEY == "sk-test"
```

**Step 2: 运行确认失败**

Run: `uv run pytest tests/backend/core/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'backend'`

**Step 3: 写实现**

```toml
# pyproject.toml
[project]
name = "netsentinel"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
  "fastapi>=0.115", "uvicorn[standard]>=0.32",
  "pydantic>=2.9", "pydantic-settings>=2.6",
  "sqlalchemy[asyncio]>=2.0.36", "asyncpg>=0.30", "alembic>=1.14",
  "redis>=5.2", "arq>=0.26",
  "pandas>=2.2", "numpy>=2.1", "scikit-learn>=1.5", "xgboost>=2.1", "joblib>=1.4",
  "langgraph>=0.2", "langgraph-checkpoint-postgres>=2.0",
  "openai>=1.54",
  "structlog>=24.4", "cachetools>=5.5",
  "aiofiles>=24.1", "httpx>=0.27",
]

[dependency-groups]
dev = ["pytest>=8.3", "pytest-asyncio>=0.24", "ruff>=0.8", "mypy>=1.13", "pre-commit>=4.0"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.mypy]
python_version = "3.12"
ignore_missing_imports = true
```

```python
# backend/core/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    APP_ENV: str = "development"
    APP_PORT: int = 8000

    DATABASE_URL: str = (
        "postgresql+asyncpg://netsentinel:netsentinel@localhost:5432/netsentinel"
    )
    REDIS_URL: str = "redis://localhost:6379/0"

    DEEPSEEK_API_KEY: str = ""
    DEEPSEEK_BASE_URL: str = "https://api.deepseek.com"
    TRIAGE_MODEL: str = "deepseek-chat"
    INVESTIGATION_MODEL: str = "deepseek-reasoner"

    ESCALATE_MIN_SEVERITY: str = "high"
    ESCALATE_MAX_CONFIDENCE: int = 60
    DEDUP_TTL_SECONDS: int = 60


settings = Settings()
```

```bash
# .env.example
APP_ENV=development
APP_PORT=8000
DATABASE_URL=postgresql+asyncpg://netsentinel:netsentinel@localhost:5432/netsentinel
REDIS_URL=redis://localhost:6379/0
DEEPSEEK_API_KEY=
DEEPSEEK_BASE_URL=https://api.deepseek.com
TRIAGE_MODEL=deepseek-chat
INVESTIGATION_MODEL=deepseek-reasoner
```

**Step 4: 运行确认通过**

Run: `uv sync && uv run pytest tests/backend/core/test_config.py -v`
Expected: PASS（2 passed）

**Step 5: 提交**

```bash
git add pyproject.toml backend/ tests/ .env.example .pre-commit-config.yaml
git commit -m "chore: 初始化项目脚手架与配置"
```

---

## Task 2: 结构化日志与异常基类

**Files:**
- Create: `backend/core/logging.py`
- Create: `backend/core/exceptions.py`
- Test: `tests/backend/core/test_exceptions.py`

**Step 1: 写失败测试**

```python
def test_app_error_has_code_and_message():
    from backend.core.exceptions import AppError

    err = AppError("boom", code="E_BOOM")
    assert err.message == "boom"
    assert err.code == "E_BOOM"


def test_not_found_is_subclass():
    from backend.core.exceptions import AppError, NotFoundError

    assert issubclass(NotFoundError, AppError)
    assert NotFoundError("alert").code == "NOT_FOUND"
```

**Step 2: 运行确认失败** — Run: `uv run pytest tests/backend/core/test_exceptions.py -v`；Expected: FAIL

**Step 3: 写实现**

```python
# backend/core/exceptions.py
class AppError(Exception):
    code = "APP_ERROR"

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code


class NotFoundError(AppError):
    code = "NOT_FOUND"


class ValidationError(AppError):
    code = "VALIDATION_ERROR"


class UpstreamError(AppError):
    code = "UPSTREAM_ERROR"
```

```python
# backend/core/logging.py
import logging
import structlog


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(format="%(message)s", level=level)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level)
        ),
    )
```

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 提交**

```bash
git commit -am "feat: 添加结构化日志与异常基类"
```

---

## Task 3: 本地依赖服务（PostgreSQL + Redis）

**Files:**
- Create: `docker-compose.yml`
- Create: `docker/Dockerfile.backend`
- Create: `docker/nginx.conf`

**Step 1: 写 compose**

```yaml
# docker-compose.yml
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: netsentinel
      POSTGRES_PASSWORD: netsentinel
      POSTGRES_DB: netsentinel
    ports: ["5432:5432"]
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U netsentinel"]
      interval: 5s
      retries: 10

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      retries: 10

volumes:
  pgdata:
```

**Step 2: 启动并验证**

Run:
```bash
docker compose up -d db redis
docker compose ps
```
Expected: 两个容器 `healthy`

**Step 3: 提交**

```bash
git add docker-compose.yml docker/
git commit -m "chore: 添加 PostgreSQL 与 Redis 本地服务"
```

---

## Task 4: 数据库基类与 UnifiedAlert ORM 模型

**Files:**
- Create: `backend/core/database.py`
- Create: `backend/models/__init__.py`
- Create: `backend/models/base.py`
- Create: `backend/models/alert.py`
- Test: `tests/backend/models/test_alert_model.py`

**Step 1: 写失败测试**

```python
import uuid

from backend.models.alert import Alert


def test_alert_has_required_fields():
    a = Alert(
        source_engine="ml",
        detected_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        signature="DDoS",
        severity="high",
        confidence=0.93,
    )
    assert a.source_engine == "ml"
    assert a.status == "new"
    assert isinstance(a.id, uuid.UUID)
```

**Step 2: 运行确认失败** — Expected: FAIL

**Step 3: 写实现**

```python
# backend/core/database.py
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from backend.core.config import settings

engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
```

```python
# backend/models/base.py
import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, func
from sqlalchemy.orm import Mapped, mapped_column


class UUIDMixin:
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
```

```python
# backend/models/alert.py
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.database import Base
from backend.models.base import TimestampMixin, UUIDMixin


class Alert(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "alerts"

    source_engine: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    src_port: Mapped[int | None] = mapped_column(nullable=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dst_port: Mapped[int | None] = mapped_column(nullable=True, index=True)
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)
    signature: Mapped[str] = mapped_column(String(512), nullable=False)
    attack_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    dedup_key: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="new", index=True
    )
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        Index("idx_alerts_detected_severity", "detected_at", "severity"),
    )
```

```python
# backend/models/__init__.py
from backend.models.alert import Alert
from backend.models.base import TimestampMixin, UUIDMixin

__all__ = ["Alert", "TimestampMixin", "UUIDMixin"]
```

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 提交**

```bash
git commit -am "feat: 添加 UnifiedAlert ORM 模型"
```

---

## Task 5: Alembic 迁移

**Files:**
- Create: `alembic.ini`, `alembic/env.py`, `alembic/versions/0001_create_alerts.py`

**Step 1: 初始化**

Run: `uv run alembic init -t async alembic`
Then 修改 `alembic/env.py`：导入 `Base.metadata` 与 `settings.DATABASE_URL`，设置 `target_metadata = Base.metadata`。

**Step 2: 生成迁移**

Run: `uv run alembic revision --autogenerate -m "create alerts"`
Expected: 生成 `alembic/versions/*_create_alerts.py`，含 `alerts` 表

**Step 3: 应用并验证**

Run: `uv run alembic upgrade head`
然后验证表存在：
```bash
docker compose exec db psql -U netsentinel -d netsentinel -c "\d alerts"
```
Expected: 输出 alerts 表结构与索引

**Step 4: 提交**

```bash
git add alembic.ini alembic/
git commit -m "feat: 添加 Alembic 迁移与 alerts 表"
```

---

## Task 6: 告警 Pydantic Schema

**Files:**
- Create: `backend/schemas/__init__.py`
- Create: `backend/schemas/alert.py`
- Test: `tests/backend/schemas/test_alert_schema.py`

**Step 1: 写失败测试**

```python
import uuid
from datetime import UTC, datetime

from backend.schemas.alert import AlertCreate, AlertResponse


def test_alert_create_validates_severity():
    a = AlertCreate(
        source_engine="ml",
        detected_at=datetime.now(UTC),
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        signature="DDoS",
        severity="high",
        confidence=0.9,
    )
    assert a.severity == "high"


def test_alert_response_from_attributes():
    class Row:
        id = uuid.uuid4()
        source_engine = "ml"
        detected_at = datetime.now(UTC)
        src_ip = "1.1.1.1"
        src_port = None
        dst_ip = "2.2.2.2"
        dst_port = None
        protocol = "TCP"
        signature = "DDoS"
        attack_type = "DDoS"
        severity = "high"
        confidence = 0.9
        category = None
        raw = None
        status = "new"
        notes = ""

    r = AlertResponse.model_validate(Row(), from_attributes=True)
    assert r.source_engine == "ml"
```

**Step 2: 运行确认失败** — Expected: FAIL

**Step 3: 写实现**

```python
# backend/schemas/alert.py
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Engine = Literal["suricata", "ml"]
Status = Literal["new", "triaged", "escalated", "closed", "suppressed"]


class AlertCreate(BaseModel):
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
    dedup_key: str | None = None


class AlertResponse(AlertCreate):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    status: Status
    notes: str = ""


class AlertPage(BaseModel):
    items: list[AlertResponse]
    total: int
    page: int
    size: int
```

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 提交**

```bash
git commit -am "feat: 添加告警 Pydantic schema"
```

---

## Task 7: 数据访问层（Unit of Work + alert 仓库）

**Files:**
- Create: `backend/repositories/__init__.py`
- Create: `backend/repositories/alert_repository.py`
- Test: `tests/backend/repositories/test_alert_repository.py`

**Step 1: 写失败测试**（使用事务回滚的 SQLite/临时 PG fixture）

```python
@pytest.mark.asyncio
async def test_create_and_list(session):
    from backend.repositories import alert_repository as repo
    from backend.schemas.alert import AlertCreate
    from datetime import UTC, datetime

    obj = AlertCreate(
        source_engine="ml", detected_at=datetime.now(UTC),
        src_ip="1.1.1.1", dst_ip="2.2.2.2", signature="DDoS",
        severity="high", confidence=0.9,
    )
    created = await repo.create(session, obj)
    assert created.id is not None

    items, total = await repo.list(session, page=1, size=10)
    assert total == 1
    assert items[0].signature == "DDoS"
```

（`session` fixture 放 `tests/conftest.py`：建内存/临时库、建表、yield、回滚）

**Step 2: 运行确认失败** — Expected: FAIL

**Step 3: 写实现**

```python
# backend/repositories/alert_repository.py
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.alert import Alert
from backend.schemas.alert import AlertCreate


async def create(session: AsyncSession, obj: AlertCreate) -> Alert:
    alert = Alert(**obj.model_dump())
    session.add(alert)
    await session.commit()
    await session.refresh(alert)
    return alert


async def get(session: AsyncSession, alert_id) -> Alert | None:
    return await session.get(Alert, alert_id)


async def list(
    session: AsyncSession,
    page: int = 1,
    size: int = 20,
    severity: str | None = None,
    source_engine: str | None = None,
    q: str | None = None,
) -> tuple[list[Alert], int]:
    stmt = select(Alert)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if source_engine:
        stmt = stmt.where(Alert.source_engine == source_engine)
    if q:
        stmt = stmt.where(Alert.signature.ilike(f"%{q}%"))
    total = await session.scalar(
        select(func.count()).select_from(stmt.subquery())
    )
    stmt = stmt.order_by(Alert.detected_at.desc()).offset((page - 1) * size).limit(size)
    rows = (await session.scalars(stmt)).all()
    return list(rows), int(total or 0)
```

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 提交**

```bash
git commit -am "feat: 添加 alert 数据访问层"
```

---

## Task 8: 告警服务（去重 + 抑制 + 归一化）

**Files:**
- Create: `backend/services/__init__.py`
- Create: `backend/services/alert_service.py`
- Test: `tests/backend/services/test_alert_service.py`

**Step 1: 写失败测试**

```python
def test_dedup_within_ttl():
    from backend.services.alert_service import AlertPipeline

    p = AlertPipeline(ttl_seconds=60)
    a = {"src_ip": "1.1.1.1", "signature": "DDoS"}
    assert p.is_duplicate(a) is False
    assert p.is_duplicate(a) is True


def test_normalize_maps_severity():
    from backend.services.alert_service import normalize_alert

    out = normalize_alert(
        {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "signature": "X",
         "severity": "high", "confidence": 0.5, "source_engine": "ml",
         "detected_at": None}
    )
    assert out["severity"] == "high"
```

**Step 2: 运行确认失败** — Expected: FAIL

**Step 3: 写实现**

```python
# backend/services/alert_service.py
from __future__ import annotations

from datetime import UTC, datetime

from cachetools import TTLCache


def normalize_alert(raw: dict) -> dict:
    """把任意引擎输出归一化为 AlertCreate 字段。"""
    return {
        "source_engine": raw["source_engine"],
        "detected_at": raw.get("detected_at") or datetime.now(UTC),
        "src_ip": raw.get("src_ip", "0.0.0.0"),
        "src_port": raw.get("src_port"),
        "dst_ip": raw.get("dst_ip", "0.0.0.0"),
        "dst_port": raw.get("dst_port"),
        "protocol": raw.get("protocol"),
        "signature": raw.get("signature", "Unknown"),
        "attack_type": raw.get("attack_type"),
        "severity": raw.get("severity", "info"),
        "confidence": float(raw.get("confidence", 0.0)),
        "category": raw.get("category"),
        "raw": raw.get("raw"),
        "dedup_key": f"{raw.get('src_ip')}-{raw.get('signature')}",
    }


class AlertPipeline:
    """去重 + 抑制（期 1 抑制为空实现）"""

    def __init__(self, ttl_seconds: int = 60, maxsize: int = 10000):
        self._recent: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl_seconds)

    def is_duplicate(self, alert: dict) -> bool:
        key = f"{alert.get('src_ip')}-{alert.get('signature')}"
        if key in self._recent:
            return True
        self._recent[key] = True
        return False
```

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 提交**

```bash
git commit -am "feat: 添加告警归一化与去重"
```

---

## Task 9: 数据准备脚本（CICIDS2017）

**Files:**
- Create: `scripts/prepare_data.py`
- Create: `scripts/README.md`
- Test: `tests/test_prepare_data.py`（对样本 fixture 测试，不联网）

**Step 1: 写失败测试**

```python
def test_pick_attack_sample_returns_rows():
    from scripts.prepare_data import split_and_sample

    import pandas as pd
    df = pd.DataFrame({
        " Label": ["BENIGN", "DDoS", "BENIGN"],
        "Destination Port": [80, 80, 443],
        "Flow Duration": [1, 2, 3],
    })
    normal, attack = split_and_sample(df, n=1)
    assert len(normal) == 1 and len(attack) == 1
```

**Step 2: 运行确认失败** — Expected: FAIL

**Step 3: 写实现**

`scripts/prepare_data.py` 职责：
1. 从 `data/raw/` 读取 CICIDS CSV（若不存在，打印下载指引与镜像链接，**不自动下载**）
2. 清洗：列名去空格、`Label` 归一化、inf/NaN 处理
3. 切分 normal / attack 并采样，写出 `data/processed/{train,test}.parquet`
4. 打印样本数与标签分布

```python
# scripts/prepare_data.py（核心函数）
import pandas as pd


def split_and_sample(df: pd.DataFrame, n: int | None = None):
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]
    normal = df[df["Label"].str.upper() == "BENIGN"]
    attack = df[df["Label"].str.upper() != "BENIGN"]
    if n:
        normal, attack = normal.head(n), attack.head(n)
    return normal, attack
```

**Step 4: 运行确认通过** — Run: `uv run pytest tests/test_prepare_data.py -v`；Expected: PASS

**Step 5: 下载数据并生成产物**

Run: `uv run python scripts/prepare_data.py`
（若数据未下载，按提示从 Kaggle/HuggingFace 镜像获取后放入 `data/raw/`）
Expected: 打印标签分布，生成 `data/processed/*.parquet`

**Step 6: 提交**

```bash
git add scripts/ tests/test_prepare_data.py
git commit -m "feat: 添加 CICIDS2017 数据准备脚本"
```

---

## Task 10: ML 训练脚本与指标

**Files:**
- Create: `backend/detection/ml/train.py`
- Create: `backend/detection/ml/__init__.py`
- Test: `tests/backend/detection/ml/test_train.py`

**Step 1: 写失败测试**

```python
def test_train_returns_model_and_metrics():
    import numpy as np
    from backend.detection.ml.train import train_binary

    rng = np.random.default_rng(0)
    X = rng.random((200, 5))
    y = (X[:, 0] > 0.5).astype(int)
    model, metrics = train_binary(X, y)
    assert "accuracy" in metrics
    assert metrics["accuracy"] >= 0.6
    assert hasattr(model, "predict")
```

**Step 2: 运行确认失败** — Expected: FAIL

**Step 3: 写实现**

```python
# backend/detection/ml/train.py
from __future__ import annotations

import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier


def train_binary(X, y) -> tuple[XGBClassifier, dict]:
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    model = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.1,
        subsample=0.9, eval_metric="logloss", n_jobs=-1,
    )
    model.fit(X_tr, y_tr)
    pred = model.predict(X_te)
    metrics = {
        "accuracy": float(accuracy_score(y_te, pred)),
        "precision": float(precision_score(y_te, pred, zero_division=0)),
        "recall": float(recall_score(y_te, pred, zero_division=0)),
        "f1": float(f1_score(y_te, pred, zero_division=0)),
    }
    return model, metrics
```

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 训练真实模型**

Run: `uv run python -m backend.detection.ml.train --data data/processed/train.parquet --out models/xgb_binary.joblib`
Expected: 打印 accuracy / precision / recall / f1，生成 `models/xgb_binary.joblib`（`models/` 已 gitignore，不入库）

**Step 6: 提交**

```bash
git add backend/detection/ml/ tests/backend/detection/ml/
git commit -m "feat: 添加 ML 训练脚本与指标"
```

---

## Task 11: ML 推理器

**Files:**
- Create: `backend/detection/ml/predictor.py`
- Test: `tests/backend/detection/ml/test_predictor.py`

**Step 1: 写失败测试**

```python
def test_predictor_returns_prediction(tmp_path):
    import joblib, numpy as np
    from backend.detection.ml.train import train_binary
    from backend.detection.ml.predictor import MLPredictor

    rng = np.random.default_rng(0)
    X = rng.random((200, 5)); y = (X[:, 0] > 0.5).astype(int)
    model, _ = train_binary(X, y)
    path = tmp_path / "m.joblib"; joblib.dump(model, path)

    p = MLPredictor(path, feature_names=[f"f{i}" for i in range(5)])
    r = p.predict({"f0": 0.9, "f1": 0.1, "f2": 0.1, "f3": 0.1, "f4": 0.1})
    assert r.label in (0, 1)
    assert 0.0 <= r.confidence <= 1.0
```

**Step 2: 运行确认失败** — Expected: FAIL

**Step 3: 写实现**

```python
# backend/detection/ml/predictor.py
from __future__ import annotations

from dataclasses import dataclass

import joblib
import numpy as np


@dataclass
class Prediction:
    label: int
    confidence: float


class MLPredictor:
    def __init__(self, model_path, feature_names: list[str]):
        self.model = joblib.load(model_path)
        self.feature_names = feature_names

    def predict(self, features: dict) -> Prediction:
        vec = np.array([[float(features.get(f, 0.0)) for f in self.feature_names]])
        proba = self.model.predict_proba(vec)[0]
        label = int(np.argmax(proba))
        return Prediction(label=label, confidence=float(proba[label]))
```

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 提交**

```bash
git commit -am "feat: 添加 ML 推理器"
```

---

## Task 12: CsvFeeder（按时间戳准实时重放）

**Files:**
- Create: `backend/detection/feeders/__init__.py`
- Create: `backend/detection/feeders/csv_feeder.py`
- Test: `tests/backend/detection/feeders/test_csv_feeder.py`

**Step 1: 写失败测试**

```python
@pytest.mark.asyncio
async def test_feeder_emits_in_time_order(tmp_path):
    import pandas as pd
    from backend.detection.feeders.csv_feeder import CsvFeeder

    df = pd.DataFrame({
        "Timestamp": ["2017-07-05 10:00:00", "2017-07-05 10:00:01",
                      "2017-07-05 10:00:02"],
        "src_ip": ["1.1.1.1"] * 3, "Label": ["BENIGN", "DDoS", "BENIGN"],
    })
    p = tmp_path / "s.csv"; df.to_csv(p, index=False)

    feeder = CsvFeeder(p, speed=1000.0, max_delay=0.001)
    rows = [r async for r in feeder.stream()]
    assert len(rows) == 3
    assert [r["Label"] for r in rows] == ["BENIGN", "DDoS", "BENIGN"]
```

**Step 2: 运行确认失败** — Expected: FAIL

**Step 3: 写实现**

```python
# backend/detection/feeders/csv_feeder.py
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pandas as pd

MAX_SLEEP = 5.0  # 单步最长等待，防止真实间隔过大拖垮演示


class CsvFeeder:
    """按行时间戳节奏重放 CICIDS flow CSV。"""

    def __init__(self, path: str | Path, speed: float = 1.0, max_delay: float = MAX_SLEEP):
        self.path = Path(path)
        self.speed = max(speed, 1e-6)
        self.max_delay = max_delay

    async def stream(self) -> AsyncIterator[dict]:
        df = pd.read_csv(self.path)
        df.columns = [c.strip() for c in df.columns]
        ts = pd.to_datetime(df.get("Timestamp"), errors="coerce")
        prev = None
        for (_, row), t in zip(df.iterrows(), ts, strict=False):
            if prev is not None and pd.notna(t):
                delay = (t - prev).total_seconds() / self.speed
                if delay > 0:
                    await asyncio.sleep(min(delay, self.max_delay))
            if pd.notna(t):
                prev = t
            yield row.to_dict()
```

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 提交**

```bash
git commit -am "feat: 添加 CsvFeeder 准实时重放"
```

---

## Task 13: DeepSeek 客户端与结构化输出

**Files:**
- Create: `backend/agents/__init__.py`
- Create: `backend/agents/llm_client.py`
- Create: `backend/agents/prompts.py`
- Create: `backend/schemas/triage.py`
- Test: `tests/backend/agents/test_llm_client.py`（用 monkeypatch 假响应，不真实调用）

**Step 1: 写失败测试**

```python
def test_triage_result_schema():
    from backend.schemas.triage import TriageResult

    r = TriageResult.model_validate({
        "verdict": "true_positive", "severity": "high", "confidence": 80,
        "escalate": True, "attack_type": "Scan", "summary": "s",
        "mitre_techniques": ["T1046"], "recommended_actions": ["block"],
    })
    assert r.escalate is True


def test_client_parses_json_response(monkeypatch):
    from backend.agents.llm_client import LLMClient

    client = LLMClient(api_key="x", base_url="http://x", model="m")
    monkeypatch.setattr(client, "_raw_call", lambda *a, **k: '{"verdict": "false_positive", "severity": "low", "confidence": 90, "escalate": false, "attack_type": null, "summary": "fp", "mitre_techniques": [], "recommended_actions": []}')
    r = client.triage({"signature": "X"})
    assert r.verdict == "false_positive"
```

**Step 2: 运行确认失败** — Expected: FAIL

**Step 3: 写实现**

```python
# backend/schemas/triage.py
from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["true_positive", "false_positive", "needs_human_review"]


class TriageResult(BaseModel):
    verdict: Verdict
    severity: Literal["critical", "high", "medium", "low"]
    confidence: int = Field(ge=0, le=100)
    escalate: bool = False
    attack_type: str | None = None
    summary: str
    mitre_techniques: list[str] = []
    recommended_actions: list[str] = []
```

```python
# backend/agents/llm_client.py
from __future__ import annotations

import json

from openai import OpenAI

from backend.agents.prompts import TRIAGE_SYSTEM, build_triage_prompt
from backend.schemas.triage import TriageResult


class LLMClient:
    """DeepSeek（OpenAI 兼容）客户端。"""

    def __init__(self, api_key: str, base_url: str, model: str):
        self.model = model
        self._client = OpenAI(api_key=api_key, base_url=base_url)

    def _raw_call(self, system: str, user: str) -> str:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format={"type": "json_object"},
            temperature=0.1,
        )
        self.last_usage = resp.usage
        return resp.choices[0].message.content or "{}"

    def triage(self, alert: dict) -> TriageResult:
        raw = self._raw_call(TRIAGE_SYSTEM, build_triage_prompt(alert))
        return TriageResult.model_validate(json.loads(raw))
```

```python
# backend/agents/prompts.py
TRIAGE_SYSTEM = """你是 SOC 值班分析师，对一条 IDS 告警做快速分诊。
只引用告警本身提供的信息，不要臆测。输出严格 JSON，字段：
verdict(true_positive|false_positive|needs_human_review)、severity(critical|high|medium|low)、
confidence(0-100)、escalate(bool)、attack_type、summary(2-3句中文)、
mitre_techniques(数组，如 ["T1110"]；不确定就留空)、recommended_actions(数组，2-4条)。
规则：拿不准时选 needs_human_review 并把 escalate 设为 true；不得凭记忆编造 MITRE 编号。"""


def build_triage_prompt(alert: dict) -> str:
    return f"告警内容：\n{alert}"
```

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 真实连通性验证（需 key）**

Run:
```bash
DEEPSEEK_API_KEY=sk-xxx uv run python -c "
from backend.agents.llm_client import LLMClient
from backend.core.config import settings
c = LLMClient(settings.DEEPSEEK_API_KEY, settings.DEEPSEEK_BASE_URL, settings.TRIAGE_MODEL)
print(c.triage({'signature': 'ET SCAN Nmap OS Detection Probe', 'severity': 'high', 'src_ip': '45.33.32.156'}))
"
```
Expected: 输出 TriageResult，`verdict` 合理

**Step 6: 提交**

```bash
git commit -am "feat: 添加 DeepSeek 客户端与分诊结构化输出"
```

---

## Task 14: LangGraph 最小图（triage → persist）

**Files:**
- Create: `backend/agents/state.py`
- Create: `backend/agents/graph.py`
- Test: `tests/backend/agents/test_graph.py`

**Step 1: 写失败测试**

```python
@pytest.mark.asyncio
async def test_graph_runs_triage_then_persist(fake_llm_client, fake_persist):
    from backend.agents.graph import build_triage_graph

    graph = build_triage_graph(llm=None, persist=fake_persist)
    out = await graph.ainvoke({"alert": {"signature": "X"}, "triage": None})
    assert out["triage"]["verdict"] == "false_positive"
    assert fake_persist.called is True
```

**Step 2: 运行确认失败** — Expected: FAIL

**Step 3: 写实现**

```python
# backend/agents/state.py
from typing import Any, TypedDict


class TriageState(TypedDict, total=False):
    alert: dict[str, Any]
    triage: dict[str, Any] | None
    persisted: bool
```

```python
# backend/agents/graph.py
from __future__ import annotations

from collections.abc import Awaitable, Callable

from langgraph.graph import END, START, StateGraph

from backend.agents.state import TriageState


def build_triage_graph(
    llm,
    persist: Callable[[dict, dict], Awaitable[None]],
    client_factory=None,
):
    """期 1：START → triage → persist → END（期 2 会增加条件边与 investigate）"""

    async def triage_node(state: TriageState) -> TriageState:
        client = llm or client_factory()
        result = client.triage(state["alert"])
        return {"triage": result.model_dump()}

    async def persist_node(state: TriageState) -> TriageState:
        await persist(state["alert"], state["triage"] or {})
        return {"persisted": True}

    g = StateGraph(TriageState)
    g.add_node("triage", triage_node)
    g.add_node("persist", persist_node)
    g.add_edge(START, "triage")
    g.add_edge("triage", "persist")
    g.add_edge("persist", END)
    return g.compile()
```

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 提交**

```bash
git commit -am "feat: 添加 LangGraph 分诊图"
```

---

## Task 15: API 路由（alerts / feeds）

**Files:**
- Create: `backend/api/__init__.py`, `backend/api/v1/__init__.py`
- Create: `backend/api/v1/routes/__init__.py`
- Create: `backend/api/v1/routes/alerts.py`
- Create: `backend/api/v1/routes/feeds.py`
- Create: `backend/middleware/error_handler.py`
- Test: `tests/backend/api/test_alerts_api.py`（httpx AsyncClient + ASGITransport）

**Step 1: 写失败测试**

```python
@pytest.mark.asyncio
async def test_list_alerts_empty(app):
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/alerts")
    assert r.status_code == 200
    assert r.json()["total"] >= 0
```

**Step 2: 运行确认失败** — Expected: FAIL

**Step 3: 写实现**

```python
# backend/api/v1/routes/alerts.py
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.database import get_session
from backend.repositories import alert_repository as repo
from backend.schemas.alert import AlertPage, AlertResponse

router = APIRouter()


@router.get("", response_model=AlertPage)
async def list_alerts(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    severity: str | None = None,
    source_engine: str | None = None,
    q: str | None = None,
    session: AsyncSession = Depends(get_session),
):
    items, total = await repo.list(
        session, page=page, size=size,
        severity=severity, source_engine=source_engine, q=q,
    )
    return AlertPage(
        items=[AlertResponse.model_validate(i) for i in items],
        total=total, page=page, size=size,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str, session: AsyncSession = Depends(get_session)):
    row = await repo.get(session, alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return AlertResponse.model_validate(row)
```

```python
# backend/main.py
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.v1.routes import alerts, feeds
from backend.core.logging import setup_logging
from backend.middleware.error_handler import register_exception_handlers


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="NetSentinel API", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
    )
    register_exception_handlers(app)
    app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["alerts"])
    app.include_router(feeds.router, prefix="/api/v1/feeds", tags=["feeds"])
    return app


app = create_app()
```

（`error_handler.py` 注册 `AppError` → JSON 响应；`feeds.py` 期 1 先提供 `POST /replay` 触发 worker，下一 Task 实现）

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 手动验证**

Run: `uv run uvicorn backend.main:app --reload`
然后访问 `http://localhost:8000/docs`，确认接口列出。
Expected: Swagger 页面可见 alerts / feeds

**Step 6: 提交**

```bash
git commit -am "feat: 添加 alerts/feeds API"
```

---

## Task 16: WebSocket 实时推送

**Files:**
- Create: `backend/api/websocket/__init__.py`
- Create: `backend/api/websocket/manager.py`
- Create: `backend/api/websocket/handlers.py`
- Test: `tests/backend/api/test_ws_manager.py`

**Step 1: 写失败测试**

```python
@pytest.mark.asyncio
async def test_broadcast_to_connections():
    from backend.api.websocket.manager import WebSocketManager

    class FakeWS:
        def __init__(self): self.sent = []
        async def send_text(self, t): self.sent.append(t)

    m = WebSocketManager()
    ws = FakeWS()
    await m.connect(ws)
    await m.broadcast({"type": "new_alert", "data": {"a": 1}})
    assert len(ws.sent) == 1
```

**Step 2: 运行确认失败** — Expected: FAIL

**Step 3: 写实现**（`connect` 对 FakeWS 不调用 `accept()`，需容错）

```python
# backend/api/websocket/manager.py
from __future__ import annotations

import asyncio
import json
from typing import Any


class WebSocketManager:
    def __init__(self) -> None:
        self._conns: set = set()
        self._lock = asyncio.Lock()

    @property
    def count(self) -> int:
        return len(self._conns)

    async def connect(self, ws) -> None:
        accept = getattr(ws, "accept", None)
        if accept is not None:
            await accept()
        async with self._lock:
            self._conns.add(ws)

    async def disconnect(self, ws) -> None:
        async with self._lock:
            self._conns.discard(ws)

    async def broadcast(self, message: dict[str, Any]) -> None:
        if not self._conns:
            return
        text = json.dumps(message, default=str)
        async with self._lock:
            snapshot = set(self._conns)
        stale = set()
        for ws in snapshot:
            try:
                await ws.send_text(text)
            except Exception:
                stale.add(ws)
        if stale:
            async with self._lock:
                self._conns -= stale


ws_manager = WebSocketManager()
```

```python
# backend/api/websocket/handlers.py
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.api.websocket.manager import ws_manager

router = APIRouter()


@router.websocket("/ws/events")
async def ws_events(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws)
```

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 提交**

```bash
git commit -am "feat: 添加 WebSocket 实时推送"
```

---

## Task 17: 重放 Worker（串联全链路）

**Files:**
- Create: `backend/workers/__init__.py`
- Create: `backend/workers/replay.py`
- Modify: `backend/api/v1/routes/feeds.py`
- Test: `tests/backend/workers/test_replay.py`

**Step 1: 写失败测试**（用假 feeder、假 predictor、假 llm，断言广播被调用）

```python
@pytest.mark.asyncio
async def test_replay_publishes_alerts(monkeypatch):
    from backend.workers import replay

    published = []

    async def fake_broadcast(msg): published.append(msg)

    monkeypatch.setattr("backend.api.websocket.manager.ws_manager.broadcast", fake_broadcast)
    monkeypatch.setattr("backend.workers.replay.build_triage_graph", lambda **k: _FakeGraph())
    # 其余依赖注入见实现
    ...
```

**Step 2: 运行确认失败** — Expected: FAIL

**Step 3: 写实现**

`backend/workers/replay.py` 职责：
1. 用 `CsvFeeder` 逐条读 flow
2. 每条经 `MLPredictor` 得到 `label`/`confidence`；`label==1` 才生成告警
3. `normalize_alert` → `AlertPipeline.is_duplicate` 过滤
4. 写库（`alert_repository.create`）
5. 经 `ws_manager.broadcast({"type": "new_alert", "data": ...})` 推送
6. 对高严重度告警调用 `build_triage_graph(...).ainvoke(...)`，结果再广播 `{"type": "triage", ...}`

```python
# backend/workers/replay.py（骨架）
async def run_replay(csv_path: str, *, speed: float = 1.0, model_path: str,
                     feature_names: list[str], llm, session_factory,
                     pipeline=None, on_alert=None) -> dict:
    from backend.detection.feeders.csv_feeder import CsvFeeder
    from backend.detection.ml.predictor import MLPredictor
    from backend.repositories import alert_repository as repo
    from backend.schemas.alert import AlertCreate
    from backend.services.alert_service import AlertPipeline, normalize_alert

    feeder = CsvFeeder(csv_path, speed=speed)
    predictor = MLPredictor(model_path, feature_names)
    pipeline = pipeline or AlertPipeline()
    emitted = 0

    async for row in feeder.stream():
        pred = predictor.predict(row)
        if pred.label != 1:
            continue
        alert = normalize_alert({
            "source_engine": "ml",
            "detected_at": None,
            "src_ip": row.get("Source IP", "0.0.0.0"),
            "dst_ip": row.get("Destination IP", "0.0.0.0"),
            "protocol": "TCP",
            "signature": row.get("Label", "ATTACK"),
            "attack_type": row.get("Label"),
            "severity": "high" if pred.confidence >= 0.9 else "medium",
            "confidence": pred.confidence,
            "raw": row,
        })
        if pipeline.is_duplicate(alert):
            continue
        async with session_factory() as session:
            row_db = await repo.create(session, AlertCreate(**alert))
        payload = {"type": "new_alert", "data": {"id": str(row_db.id), **alert}}
        if on_alert:
            await on_alert(payload)
        emitted += 1
    return {"emitted": emitted}
```

`feeds.py` 增加：
```python
@router.post("/replay")
async def start_replay(body: ReplayRequest, background: BackgroundTasks):
    background.add_task(run_replay, body.csv_path, speed=body.speed, ...)
    return {"status": "started"}
```

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 端到端手动验证**

Run: 启动 API，然后
```bash
curl -X POST localhost:8000/api/v1/feeds/replay -H 'Content-Type: application/json' \
  -d '{"csv_path":"data/processed/test.parquet","speed":200}'
```
同时用 `websocat ws://localhost:8000/ws/events` 观察。
Expected: 告警消息持续输出

**Step 6: 提交**

```bash
git commit -am "feat: 添加重放 worker 打通检测链路"
```

---

## Task 18: 前端脚手架

**Files:**
- Create: `frontend/`（Vite + React + TS 模板）
- Create: `frontend/src/lib/api.ts`
- Create: `frontend/src/lib/ws.ts`

**Step 1: 脚手架**

Run:
```bash
cd frontend && npm create vite@latest . -- --template react-ts
npm install
npm i antd @ant-design/icons echarts echarts-for-react
npm i @tanstack/react-query zustand axios dayjs
npm i -D vitest @testing-library/react jsdom
```
Expected: 可 `npm run dev` 起前端

**Step 2: API 与 WS 客户端**

```ts
// frontend/src/lib/api.ts
import axios from "axios";
export const api = axios.create({ baseURL: import.meta.env.VITE_API_URL ?? "http://localhost:8000/api/v1" });
export const fetchAlerts = (params: Record<string, unknown>) => api.get("/alerts", { params });
```

```ts
// frontend/src/lib/ws.ts
export function connectWS(onMessage: (m: unknown) => void) {
  let delay = 1000;
  let ws: WebSocket;
  const url = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000/ws/events";
  const open = () => {
    ws = new WebSocket(url);
    ws.onmessage = (e) => onMessage(JSON.parse(e.data));
    ws.onopen = () => (delay = 1000);
    ws.onclose = () => { setTimeout(open, delay); delay = Math.min(delay * 2, 32000); };
  };
  open();
  return () => ws?.close();
}
```

**Step 3: 测试**

```bash
npm run test
```
Expected: 模板测试通过（含 1 个自写 `ws.test.ts` 断言退避计算）

**Step 4: 提交**

```bash
git commit -am "feat: 添加前端脚手架与 API/WS 客户端"
```

---

## Task 19: 前端状态与实时 hook

**Files:**
- Create: `frontend/src/store/alerts.ts`
- Create: `frontend/src/hooks/useAlertStream.ts`
- Test: `frontend/src/store/alerts.test.ts`

**Step 1: 写失败测试**

```ts
import { beforeEach, expect, test } from "vitest";
import { useAlertStore } from "./alerts";

beforeEach(() => useAlertStore.setState({ alerts: [] }));

test("prependNewest 去重并保持倒序", () => {
  const { prependNewest } = useAlertStore.getState();
  prependNewest({ id: "1" } as never);
  prependNewest({ id: "2" } as never);
  prependNewest({ id: "1" } as never);
  const ids = useAlertStore.getState().alerts.map((a) => a.id);
  expect(ids).toEqual(["2", "1"]);
});
```

**Step 2: 运行确认失败** — Run: `cd frontend && npm run test`；Expected: FAIL

**Step 3: 写实现**

```ts
// frontend/src/store/alerts.ts
import { create } from "zustand";

export type Alert = { id: string; severity?: string; [k: string]: unknown };
const MAX = 1000;

type State = {
  alerts: Alert[];
  prependNewest: (a: Alert) => void;
};

export const useAlertStore = create<State>((set) => ({
  alerts: [],
  prependNewest: (a) =>
    set((s) => {
      if (s.alerts.some((x) => x.id === a.id)) return s;
      return { alerts: [a, ...s.alerts].slice(0, MAX) };
    }),
}));
```

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 提交**

```bash
git commit -am "feat: 添加前端告警 store 与实时 hook"
```

---

## Task 20: 前端页面（Dashboard + Alerts + Feed 控制）

**Files:**
- Create: `frontend/src/pages/Dashboard.tsx`
- Create: `frontend/src/pages/Alerts.tsx`
- Create: `frontend/src/pages/FeedControl.tsx`
- Create: `frontend/src/App.tsx`（路由）
- Create: `frontend/src/components/AlertTable.tsx`, `SeverityTag.tsx`, `TriageCard.tsx`

**Step 1: 写失败测试**

```tsx
import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { SeverityTag } from "./SeverityTag";

test("渲染严重度文本", () => {
  render(<SeverityTag severity="high" />);
  expect(screen.getByText(/high/i)).toBeTruthy();
});
```

**Step 2: 运行确认失败** — Expected: FAIL

**Step 3: 写实现**（Ant Design 组件；Dashboard 用 ECharts 画严重度分布与时间线；Alerts 表格订阅 store；FeedControl 表单 POST `/feeds/replay`）

**Step 4: 运行确认通过** — Expected: PASS

**Step 5: 目视验证**

Run: 前后端都启动，打开页面，触发重放
Expected: 告警实时出现在表格，Dashboard 图表更新

**Step 6: 提交**

```bash
git commit -am "feat: 添加 Dashboard/Alerts/Feed 页面"
```

---

## Task 21: 一键启动与端到端验收

**Files:**
- Create: `scripts/dev.sh`
- Create: `README.md`
- Create: `.github/workflows/ci.yml`

**Step 1: 一键启动脚本**

`scripts/dev.sh`：`docker compose up -d db redis` → `alembic upgrade head` → 后台起 uvicorn → 前台起前端 dev server。

**Step 2: CI**

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  backend:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env: { POSTGRES_USER: netsentinel, POSTGRES_PASSWORD: netsentinel, POSTGRES_DB: netsentinel }
        ports: ["5432:5432"]
        options: >-
          --health-cmd pg_isready --health-interval 5s --health-retries 10
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv sync
      - run: uv run ruff check .
      - run: uv run mypy backend
      - run: uv run alembic upgrade head
      - run: uv run pytest -v
  frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: cd frontend && npm ci && npm run test && npm run build
```

**Step 3: 端到端验收清单**

- [ ] `./scripts/dev.sh` 后无需额外操作，前后端均可访问
- [ ] 上传/指定 CSV 后可启动重放
- [ ] 告警按时间顺序流式出现在 Web
- [ ] 高严重度告警出现 AI 分诊卡片
- [ ] `pytest` / `ruff` / `mypy` / 前端测试全绿
- [ ] CI 通过

**Step 4: 提交并开 PR**

```bash
git add -A
git commit -m "chore: 添加一键启动、CI 与验收清单"
git push -u origin feat/phase-1
```
然后在 GitHub 开 PR 合并到 main。

---

# 期 2：规则引擎 + 深度调查（任务级，执行前展开为同等粒度）

| # | 任务 | 关键文件 | 验证 |
|---|---|---|---|
| 2.1 | Suricata Docker 集成 | `docker/Dockerfile.suricata`, `suricata/rules/*.rules`, `backend/detection/suricata_runner.py` | 离线跑样例 pcap 生成 eve.json |
| 2.2 | EVE 解析器 | `backend/detection/parsers/eve_parser.py` | 单测：正常/脏数据/缺字段不崩 |
| 2.3 | EveFeeder（按时间戳重放 eve.json）| `backend/detection/feeders/eve_feeder.py` | 单测：顺序与节奏；集成：广播告警 |
| 2.4 | GeoIP 富化 | `backend/detection/enrichment/geoip.py` | 单测：查 IP 返回国家/城市 |
| 2.5 | 抑制规则（表 + API + 热路径缓存）| `backend/models/suppression.py`, `services/suppression_service.py` | 单测：AND 逻辑、过期、缓存命中 |
| 2.6 | 条件边路由（escalate 判定）| `backend/agents/graph.py`, `backend/agents/routing.py` | 单测：高严重度/低置信度升级 |
| 2.7 | Investigation Agent + 工具集 | `backend/agents/nodes/investigate.py`, `backend/agents/tools/*.py` | 单测：工具契约、强制 verdict、迭代上限 |
| 2.8 | Evidence trail 持久化 | `backend/models/triage_result.py`, migration | 单测：证据链完整落库 |
| 2.9 | Human Review（interrupt）| `backend/agents/graph.py`, `api/v1/routes/alerts.py::investigate` | 集成：手动触发深度调查 |
| 2.10 | Postgres checkpointer 接入 | `backend/agents/graph.py` | 集成：中断后恢复 |
| 2.11 | 演示保底模拟器 | `backend/detection/demo_simulator.py` | 集成：无数据也能出告警 |
| 2.12 | 前端证据链与调查按钮 | `frontend/src/pages/AlertDetail.tsx`, `EvidenceTrail.tsx` | 目视：可展开证据链 |

# 期 3：评测与打磨（任务级）

| # | 任务 | 关键文件 | 验证 |
|---|---|---|---|
| 3.1 | 多模型对比实验 | `backend/detection/ml/experiments.py`, `scripts/run_experiments.py` | 输出指标表（XGB/RF/LGBM/LR）|
| 3.2 | 评测落库与结果 API | `backend/models/evaluation.py`, `services/evaluation_service.py`, `api/v1/routes/evaluation.py` | 单测 + API 返回指标 |
| 3.3 | 前端评测页 | `frontend/src/pages/Evaluation.tsx` | 目视：指标表与混淆矩阵 |
| 3.4 | LLM 研判评测集与打分 | `scripts/llm_eval.py`, `data/eval/labeled_sample.json` | 输出一致率/耗时/成本 |
| 3.5 | Report Agent + 日报 | `backend/agents/report.py`, `api/v1/routes/reports.py` | 集成：生成可读日报 |
| 3.6 | 前端日报页 | `frontend/src/pages/Reports.tsx` | 目视 |
| 3.7 | 演示脚本与录屏 | `scripts/demo.md` | 按脚本跑一遍不失败 |
| 3.8 | 报告素材整理 | `docs/report/` | 图表与数据齐备 |

---

## 验收总清单（期 1 结束即应满足）

- [ ] 全部 Task 提交且 CI 绿
- [ ] `uv run pytest -v` 全绿
- [ ] `uv run ruff check . && uv run mypy backend` 无错误
- [ ] 前端 `npm run test && npm run build` 通过
- [ ] 启动后可完成：指定 CSV → 重放 → 告警流 → AI 分诊卡片
- [ ] `.env` 未入库，`DEEPSEEK_API_KEY` 仅经环境变量
- [ ] README 说明如何一键启动

---

## 执行方式（二选一）

1. **子代理逐任务执行（本会话）**：每个 Task 派一个全新子代理实现，我在任务之间做代码审查。迭代快，适合当前对话。
2. **独立会话批量执行**：新开一个会话，用 `superpowers:executing-plans` 按计划批量执行，带检查点。

选哪个？
