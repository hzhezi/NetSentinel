"""WebSocket 端点。"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.api.websocket.manager import ws_manager

log = structlog.get_logger(__name__)

router = APIRouter()


@router.websocket("/ws/events")
async def ws_events(websocket: WebSocket) -> None:
    """实时事件推送端点。

    这个方向是**服务端单向推送**（告警、研判结果），客户端不需要发消息。
    但必须保持一个 receive 循环 —— 否则无法感知客户端断开，
    连接会一直挂在 _conns 里泄漏。

    收到客户端消息时只记日志（当前无客户端→服务端的需要）；
    保留这个入口是为了将来支持"客户端主动请求"（如订阅过滤）。
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            message = await websocket.receive_text()
            log.debug("ws_client_message", message=message[:100])
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as exc:
        # 任何异常都要清理连接，否则集合会持续泄漏
        log.warning("ws_error", error=str(exc))
        await ws_manager.disconnect(websocket)
