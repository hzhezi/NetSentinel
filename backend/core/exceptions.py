"""业务异常体系。

设计目的：
- 业务代码只管抛 `NotFoundError(...)` 这类语义化异常，
  具体转成什么 HTTP 状态码由 API 层的统一异常处理器决定。
  这样领域逻辑不必知道 HTTP 的存在（保持分层干净）。
- 每个异常带一个稳定的 `code`（机器可读），前端可据此做差异化提示，
  而不必去匹配错误消息里的中文/英文字符串。
"""


class AppError(Exception):
    """所有业务异常的基类。

    注意这里没有直接继承 HTTPException —— 那是 FastAPI 的概念，
    不该渗进领域层。
    """

    # 类属性：子类通过覆盖它提供自己的默认 code
    code = "APP_ERROR"

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.message = message
        # 允许调用方临时覆盖 code；不传则用类属性里的默认值
        if code:
            self.code = code


class NotFoundError(AppError):
    """资源不存在，对应 HTTP 404。"""

    code = "NOT_FOUND"


class ValidationError(AppError):
    """输入不合法，对应 HTTP 422。"""

    code = "VALIDATION_ERROR"


class UpstreamError(AppError):
    """下游依赖失败（如 LLM API、Suricata），对应 HTTP 502。

    区分它和普通内部错误的意义：上游失败通常是**可重试**的，
    而且不该把下游的原始报错直接暴露给用户。
    """

    code = "UPSTREAM_ERROR"
