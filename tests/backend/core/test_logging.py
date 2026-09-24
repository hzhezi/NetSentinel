"""结构化日志的测试。

测试日志模块有个常见难点：structlog 是全局单例配置。
这里用一个小技巧 —— 配置一次后在测试内部直接断言"渲染出的内容"，
而不是去捕获 stdout。
"""

import json

import structlog

from backend.core.logging import setup_logging


def test_setup_logging_produces_json(capsys):
    """配置后，日志应以 JSON 输出，且携带 level / event 字段。"""
    setup_logging("INFO")
    log = structlog.get_logger("test")

    log.info("alert_processed", alert_id="a1b2")

    # structlog 默认写到 stdout，capsys 能捕获
    captured = capsys.readouterr().out.strip()
    payload = json.loads(captured.splitlines()[-1])

    assert payload["event"] == "alert_processed"
    assert payload["alert_id"] == "a1b2"
    assert payload["level"] == "info"
    assert "timestamp" in payload


def test_level_filters_lower_priority(capsys):
    """设为 WARNING 时，info 级别的日志应被过滤掉。"""
    setup_logging("WARNING")
    log = structlog.get_logger("test")

    log.info("should_not_appear")
    log.warning("should_appear")

    out = capsys.readouterr().out
    assert "should_not_appear" not in out
    assert "should_appear" in out
