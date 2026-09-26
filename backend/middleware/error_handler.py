"""统一异常处理：把领域异常翻译成 HTTP 响应。

这是**唯一**知道"业务错误对应什么 HTTP 状态码"的地方。
领域层（services）只管抛语义化异常，不知道 HTTP 的存在 ——
详见 backend/core/exceptions.py 的说明。
"""

from __future__ import annotations

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from backend.core.exceptions import (
    AppError,
    NotFoundError,
    UpstreamError,
    ValidationError,
)

log = structlog.get_logger(__name__)

# 领域错误 code → HTTP 状态码的映射表。
# 集中在一处的好处：改状态码不用碰业务代码。
_STATUS_BY_CODE = {
    "NOT_FOUND": 404,
    "VALIDATION_ERROR": 422,
    "UPSTREAM_ERROR": 502,
}


async def _handle_app_error(request: Request, exc: Exception) -> JSONResponse:
    """把领域异常翻译成 HTTP 响应。

    参数类型声明为 Exception（而非 AppError）以匹配 Starlette 的
    add_exception_handler 签名 —— 它要求处理器接受基类 Exception。
    运行时 FastAPI 只会把 AppError 及其子类路由到这里，因此
    函数体里用 isinstance 做一次收窄（mypy 也据此通过）。
    """
    if not isinstance(exc, AppError):
        # 理论上不可达（只注册给 AppError 家族），但保持防御性
        raise exc

    status = _STATUS_BY_CODE.get(exc.code, 500)
    # 5xx 才算服务端问题，需要告警；4xx 是调用方问题，不必刷日志
    if status >= 500:
        log.error("app_error", code=exc.code, message=exc.message, path=request.url.path)
    else:
        log.info("app_error", code=exc.code, message=exc.message, path=request.url.path)

    return JSONResponse(
        status_code=status,
        content={"code": exc.code, "message": exc.message},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """注册全局异常处理器。

    父类 + 各子类都注册一遍：父类注册保证"新增子类时自动被覆盖"，
    子类显式注册则消除不同 Starlette 版本对"父类处理器是否匹配子类"
    的行为差异。多注册几行没有副作用。
    """
    for exc_type in (AppError, NotFoundError, ValidationError, UpstreamError):
        app.add_exception_handler(exc_type, _handle_app_error)
