"""异常体系的测试。

目的：保证业务代码抛出的错误都带一个**机器可读的 code**，
这样上层（API 层）就能统一转成 JSON 响应，而不用去解析错误消息字符串。
"""

from backend.core.exceptions import (
    AppError,
    NotFoundError,
    UpstreamError,
    ValidationError,
)


def test_app_error_has_message_and_default_code():
    """不带 code 时，用基类默认值 APP_ERROR。"""
    err = AppError("boom")
    assert err.message == "boom"
    assert err.code == "APP_ERROR"
    assert str(err) == "boom"


def test_app_error_accepts_custom_code():
    """允许显式指定 code。"""
    err = AppError("boom", code="E_BOOM")
    assert err.code == "E_BOOM"


def test_subclasses_inherit_from_app_error():
    """所有业务异常都应是 AppError 的子类，方便统一捕获。"""
    assert issubclass(NotFoundError, AppError)
    assert issubclass(ValidationError, AppError)
    assert issubclass(UpstreamError, AppError)


def test_subclasses_have_their_own_codes():
    """每个子类有自己的默认 code，无需调用方传。"""
    assert NotFoundError("alert").code == "NOT_FOUND"
    assert ValidationError("bad input").code == "VALIDATION_ERROR"
    assert UpstreamError("llm down").code == "UPSTREAM_ERROR"
