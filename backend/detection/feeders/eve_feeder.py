"""按时间戳节奏重放 Suricata eve.json。

═══════════════════════════════════════════════════════════════════
这是"准实时演示"的核心机制
═══════════════════════════════════════════════════════════════════
问题：数据集是离线文件，直接一次性读完处理，Web 上告警会"唰"地全出现，
      没有实时 IDS 的观感。

解法：eve.json 里每条告警都带**事件原始时间戳**。按时间戳排序后，
      依据相邻事件的时间差逐条延迟发出，就能复现实时节奏 ——
      告警按攻击真实发生的顺序一条条涌出，而无需网卡、root、靶场。

三个关键处理：
    1. **先排序**：单文件通常有序，但多文件拼接/人工处理后可能乱序。
       按时间排序保证时间线正确，否则演示时会出现"时光倒流"。
    2. **延迟封顶**（max_delay）：真实数据里两次攻击可能相隔数小时，
       严格按原速等待会让演示无法进行。封顶保证"可演示"。
    3. **倍速**（speed）：演示用高倍速（如 100x）缩短等待；
       调试时可用 1x 观察真实节奏。

注意本模块是"纯读取"：它不写库、不推送、不做业务判断。
落库与推送由调用方（workers/replay.py）负责 —— 保持 Feeder 职责单一。
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

from backend.detection.parsers.eve_parser import EveAlert, parse_eve_line

# 单步最长等待（秒）。防止原始数据里相邻告警间隔过大（可能数小时）
# 导致演示被卡住。这是"可演示性"与"时间真实性"之间的必要折中。
MAX_SLEEP_SECONDS = 5.0


class EveFeeder:
    """读取 eve.json，按事件时间节奏逐条产出 EveAlert。"""

    def __init__(
        self,
        path: str | Path,
        speed: float = 1.0,
        max_delay: float = MAX_SLEEP_SECONDS,
    ):
        """
        Args:
            path: eve.json 路径。
            speed: 倍速。10 表示 10 倍速（相邻事件的时间差除以 10）。
                   speed=0 会被夹到一个极小正数，避免除零。
            max_delay: 单步等待上限（秒），见模块顶部说明。
        """
        self.path = Path(path)
        # 夹到极小正数而非直接报错：调用方传 0 通常是想"越快越好"，
        # 直接崩掉不如给出接近无限大的速度。
        self.speed = max(speed, 1e-9)
        self.max_delay = max_delay

    def _load_sorted_alerts(self) -> list[EveAlert]:
        """读取全部 alert 事件并按事件时间升序排序。

        一次性读入而非流式逐行：
            eve.json 单文件通常几 MB 到几百 MB，内存可容纳；
            而排序必须看到全部数据才能做。若将来遇到超大文件，
            可改为"分块读取 + 归并"，但那是没必要提前做的优化。
        """
        events: list[EveAlert] = []
        try:
            with open(self.path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    parsed = parse_eve_line(line)
                    if parsed is not None:
                        events.append(parsed)
        except FileNotFoundError:
            # 文件不存在视为"没有告警"而不是异常：
            # 调用方（重放任务）应能优雅结束，而非让后台任务崩溃。
            return []

        events.sort(key=lambda e: e.detected_at)
        return events

    async def stream(self) -> AsyncIterator[EveAlert]:
        """按时间节奏逐条产出告警。

        实现方式：先取出上一条的时间，与当前条对比算出应有的间隔，
        sleep 后 yield。用 asyncio.sleep 而非 time.sleep —— 后者会
        阻塞整个事件循环，导致 WebSocket 推送、API 响应全部卡住。
        """
        events = self._load_sorted_alerts()
        previous = None

        for event in events:
            if previous is not None:
                # 相邻事件的真实时间差，按倍速缩短
                delay = (event.detected_at - previous).total_seconds() / self.speed
                if delay > 0:
                    # 封顶：见模块顶部说明
                    await asyncio.sleep(min(delay, self.max_delay))
            previous = event.detected_at
            yield event
