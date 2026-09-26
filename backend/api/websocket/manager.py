"""WebSocket 连接管理与广播。

设计参考 IntruShield NIDS（MIT）的 ConnectionManager：
    连接集合 + asyncio.Lock 保护 + 广播时快照 + 自动剔除失效连接。

为什么需要"快照"：
    广播时若直接遍历 _conns，而某个 send 失败触发 disconnect 修改集合，
    就会 "set changed size during iteration" 报错。
    先复制一份再遍历，规避这个并发问题。
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog

log = structlog.get_logger(__name__)


class WebSocketManager:
    """管理所有活跃 WebSocket 连接并广播消息。"""

    def __init__(self) -> None:
        self._conns: set[Any] = set()
        self._lock = asyncio.Lock()

    @property
    def count(self) -> int:
        """当前连接数 —— 健康检查与调试用。"""
        return len(self._conns)

    async def connect(self, ws: Any) -> None:
        """接受并注册一个连接。

        用 getattr 取 accept：测试用的假对象不需要实现 accept，
        避免为了可测而强迫测试写多余的 mock 方法。
        """
        accept = getattr(ws, "accept", None)
        if accept is not None:
            await accept()
        async with self._lock:
            self._conns.add(ws)
        log.info("ws_connected", total=self.count)

    async def disconnect(self, ws: Any) -> None:
        async with self._lock:
            self._conns.discard(ws)
        log.info("ws_disconnected", total=self.count)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """向所有连接广播一条 JSON 消息（实为 async 回调，见说明）。

        注意本方法是 async 的，因此可以直接作为 run_replay 的 on_alert
        回调传入 —— worker 不需要知道推送方式是 WebSocket。
        """
        if not self._conns:
            return

        # default=str 兜底序列化：datetime/UUID 等对象直接 json.dumps 会报错。
        # 这是真实踩过的坑（WebSocket 推送时崩在 UUID 上）。
        text = json.dumps(message, default=str, ensure_ascii=False)

        async with self._lock:
            snapshot = set(self._conns)

        stale: set[Any] = set()
        for ws in snapshot:
            try:
                await ws.send_text(text)
            except Exception:
                # 任何发送失败都视为连接已失效 —— 不去区分异常类型，
                # 因为失效方式多样（断开/超时/底层错误），一律剔除更简单可靠。
                stale.add(ws)

        if stale:
            async with self._lock:
                self._conns -= stale
            log.info("ws_removed_stale", count=len(stale))


# 模块级单例：全应用共享一份连接表
ws_manager = WebSocketManager()
