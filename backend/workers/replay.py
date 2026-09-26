"""重放 Worker：把检测层的零件串成一条完整链路。

═══════════════════════════════════════════════════════════════════
职责
═══════════════════════════════════════════════════════════════════
    eve.json
        ↓ EveFeeder（按时间戳节奏重放）
    EveAlert
        ↓ eve_to_raw + normalize_alert（归一化 + 校验）
    AlertCreate
        ↓ AlertPipeline.is_duplicate（去重）
        ↓ repository.create（落库）
    Alert（带数据库生成的 id）
        ↓ on_alert 回调（推送）
    WebSocket / 日志 / 其他

这是"编排层"——**它自己不实现任何零件**，只按顺序调用。
每个零件都能独立测试（前三个 Task 已覆盖），这里测的是"组装是否正确"。

设计要点：
    1. **推送用回调而非直接 import ws_manager**：
       worker 不该知道"推送方式是 WebSocket"。将来可能改成 Redis 发布、
       或 CLI 直接打印。回调让推送方式可替换，也让测试不必启动 Web 服务。
    2. **单条失败不中断整批**：
       安全系统的关键性质 —— 宁可漏掉一条，也不能因一条异常
       让几万条的重放全部失败。
    3. **session_factory 而非 session**：
       每条告警用独立的 session（独立事务）。若共用一条长事务，
       中途失败会回滚掉之前所有已成功的告警。
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import structlog

from backend.detection.feeders.eve_feeder import EveFeeder
from backend.repositories import alert_repository as repo
from backend.services.alert_service import AlertPipeline, eve_to_raw, normalize_alert
from backend.services.suppression import SuppressionService

log = structlog.get_logger(__name__)


async def run_replay(
    eve_path: str | Path,
    *,
    speed: float = 1.0,
    max_delay: float | None = None,
    session_factory: Callable[[], Any],
    on_alert: Callable[[dict], Awaitable[None]] | None = None,
    pipeline: AlertPipeline | None = None,
    suppressions: SuppressionService | None = None,
) -> dict[str, int]:
    """重放 eve.json 并落库、可选推送。

    Args:
        eve_path: eve.json 路径。
        speed: 倍速。演示用高倍速（如 100），调试用 1。
        max_delay: 单步等待上限（秒）。None 则用 Feeder 默认值。
        session_factory: 每次调用返回一个 async 上下文管理器（新 session）。
        on_alert: 可选回调，每条成功落库的告警调用一次。
        pipeline: 去重管道。不传则新建（TTL 默认 60 秒）。
        suppressions: 抑制规则服务。命中已知噪声的告警会被跳过
                      （不落库、不研判、不推送）—— 省存储也省 LLM 费用。

    Returns:
        {"emitted": 落库并回调的条数,
         "deduplicated": 被去重跳过的条数,
         "errors": 落库失败的条数}
    """
    feeder_kwargs: dict[str, Any] = {"speed": speed}
    if max_delay is not None:
        feeder_kwargs["max_delay"] = max_delay
    feeder = EveFeeder(eve_path, **feeder_kwargs)

    # 不传 pipeline 就新建一个：一次重放内共享去重状态，
    # 这正是我们想要的（同一次重放里的重复应被合并）。
    dedup = pipeline or AlertPipeline()

    emitted = 0
    deduplicated = 0
    suppressed = 0
    errors = 0

    async for event in feeder.stream():
        # 归一化：解析层类型 → 服务层形状 → 校验过的合法数据
        alert_create = normalize_alert(eve_to_raw(event))

        # 去重：同源同签名在 TTL 窗口内只算一条，防告警风暴
        if dedup.is_duplicate(
            {
                "src_ip": alert_create.src_ip,
                "signature": alert_create.signature,
            }
        ):
            deduplicated += 1
            continue

        # 抑制：命中"已知噪声"规则则跳过。
        # 放在去重之后 —— 去重是内存比较（更便宜），抑制涉及多字段匹配。
        # 被抑制的告警不落库、不研判、不推送：省存储也省 LLM 费用。
        if suppressions is not None:
            hit = suppressions.match(
                {
                    "src_ip": alert_create.src_ip,
                    "signature_id": event.signature_id,
                    "category": alert_create.category,
                }
            )
            if hit is not None:
                suppressed += 1
                log.debug(
                    "alert_suppressed",
                    rule=hit.name,
                    signature=alert_create.signature,
                    src_ip=alert_create.src_ip,
                )
                continue

        # 落库：每条独立 session/事务，见模块顶部说明
        try:
            async with session_factory() as session:
                row = await repo.create(session, alert_create)
        except Exception as exc:
            # 单条失败不中断整批。记日志便于事后排查，
            # 但不向上抛 —— 一条坏数据不该让几万条重放全废。
            errors += 1
            log.warning(
                "replay_alert_persist_failed",
                signature=alert_create.signature,
                src_ip=alert_create.src_ip,
                error=str(exc),
            )
            continue

        # 回调推送。这里也做失败保护：推送失败不该回滚已落库的数据
        # （数据已持久化，是事实；推送只是通知）。
        if on_alert is not None:
            try:
                await on_alert(
                    {
                        "type": "new_alert",
                        "data": {
                            "id": str(row.id),
                            "source_engine": row.source_engine,
                            "detected_at": row.detected_at.isoformat(),
                            "src_ip": row.src_ip,
                            "src_port": row.src_port,
                            "dst_ip": row.dst_ip,
                            "dst_port": row.dst_port,
                            "protocol": row.protocol,
                            "signature": row.signature,
                            "severity": row.severity,
                            "category": row.category,
                            "status": row.status,
                        },
                    }
                )
            except Exception as exc:
                log.warning("replay_alert_notify_failed", error=str(exc))

        emitted += 1

    log.info(
        "replay_finished",
        eve_path=str(eve_path),
        emitted=emitted,
        deduplicated=deduplicated,
        suppressed=suppressed,
        errors=errors,
    )
    return {
        "emitted": emitted,
        "deduplicated": deduplicated,
        "suppressed": suppressed,
        "errors": errors,
    }
