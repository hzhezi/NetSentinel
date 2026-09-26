"""NetSentinel 后端应用入口。

应用工厂模式（create_app）而非模块级直接建 app：
    便于测试用不同配置构造实例，也便于将来在 WSGI/ASGI 服务器
    中以工厂方式引用（uvicorn 支持 "backend.main:create_app --factory"）。
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.v1.routes import alerts, feeds, statistics, suppressions
from backend.api.websocket.handlers import router as ws_router
from backend.core.config import settings
from backend.core.logging import setup_logging

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """启动/关闭钩子。

    刻意不在此处做数据库建表 —— 表结构由 Alembic 迁移管理
    （见 alembic/），应用启动时不该隐式改结构。
    """
    setup_logging()
    log.info("netsentinel_starting", env=settings.APP_ENV)
    yield
    log.info("netsentinel_stopping")


def create_app() -> FastAPI:
    app = FastAPI(
        title="NetSentinel API",
        description="准实时 NIDS 检测与研判平台",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS：开发阶段允许前端 dev server（5173）访问。
    # 生产应由 Nginx 同源代理，不需要放宽 CORS。
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 统一异常处理：把领域异常翻译成 HTTP 响应
    from backend.middleware.error_handler import register_exception_handlers

    register_exception_handlers(app)

    prefix = "/api/v1"
    app.include_router(alerts.router, prefix=f"{prefix}/alerts", tags=["alerts"])
    app.include_router(feeds.router, prefix=f"{prefix}/feeds", tags=["feeds"])
    app.include_router(statistics.router, prefix=f"{prefix}/statistics", tags=["statistics"])
    app.include_router(suppressions.router, prefix=f"{prefix}/suppressions", tags=["suppressions"])
    app.include_router(ws_router, tags=["websocket"])

    @app.get("/health", tags=["system"])
    async def health():
        """健康检查 —— 容器编排与 CI 用。

        只检查"进程活着"，不检查数据库连通性：
        数据库不可用时应由监控发现，而不是让健康检查失败导致
        容器被反复重启（重启并不能修复数据库问题）。
        """
        from backend.api.websocket.manager import ws_manager

        return {
            "status": "ok",
            "env": settings.APP_ENV,
            "ws_connections": ws_manager.count,
        }

    return app


app = create_app()
