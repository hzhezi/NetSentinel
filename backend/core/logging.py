"""结构化日志配置。

选 structlog 而非标准库 logging 的原因：
- 标准库输出的是给人读的字符串，要按字段查询/聚合得写正则去抠，很脆。
- structlog 输出 JSON，每个字段都是独立 key，日志系统（Loki/ES）能直接索引。

一个高频踩坑点：**标准库的 logging 与 structlog 是两套系统**。
第三方库（uvicorn、sqlalchemy、httpx）都用标准库 logging 打日志，
如果不把 structlog 的输出接到标准库上，日志会分裂成两种格式。
这里用 `structlog.stdlib` 系列 processor 让两边格式统一。
"""

import logging
import sys

import structlog


def setup_logging(level: str = "INFO") -> None:
    """初始化全局日志配置。进程启动时调用一次即可。

    Args:
        level: 日志级别字符串，如 "INFO" / "DEBUG" / "WARNING"。
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # ── 1. 配置标准库 root logger ──────────────────────────────
    # structlog 本身不做输出，最终仍由标准库的 handler 写出。
    # 所以这里先把标准库配好，structlog 的输出会流经它。
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=numeric_level,
        force=True,  # 允许重复调用时覆盖旧配置（测试里会反复调用）
    )

    # ── 2. 配置 structlog 的处理链 ─────────────────────────────
    structlog.configure(
        processors=[
            # 合并 contextvars 里的上下文（如 requ  est_id），
            # 实现"一次绑定的字段自动出现在后续每条日志里"
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            # 统一的时间戳字段名，便于日志系统索引
            structlog.processors.TimeStamper(fmt="iso", key="timestamp"),
            # 最终渲染成单行 JSON
            structlog.processors.JSONRenderer(),
        ],
        # make_filtering_bound_logger 让低于该级别的调用直接短路，
        # 不产生任何开销（比"先生成再丢弃"更省）
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
