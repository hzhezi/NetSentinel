"""Suricata EVE JSON 解析。

═══════════════════════════════════════════════════════════════════
这个模块的职责：把 Suricata 的"方言"翻译成我们的类型
═══════════════════════════════════════════════════════════════════
Suricata 输出的 eve.json 是 NDJSON（每行一个 JSON 事件），混有
多种事件类型：alert（告警）、flow（流统计）、dns、http、tls 等。

下游（存储 / 研判 / 展示）只关心 alert，且只认统一的领域模型，
不应被 eve.json 的字段结构绑架。所以这里做一层**解析 + 归一**：
    eve.json 行  →  EveAlert（类型化对象）
将来若换检测引擎，只改这一层，下游管道完全不动。

设计要点：
    1. **只认 alert**，其余事件返回 None。
    2. **任何脏数据都返回 None，绝不抛异常** ——
       重放时可能有几万行，一行坏数据中断整个任务是不可接受的。
    3. **缺字段用默认值兜底**，因为对应数据库列是 NOT NULL，
       且不同 Suricata 版本 / 自定义规则产出的字段可能不全。
    4. **priority → severity 的映射方向必须正确**（见下）。
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

# Suricata 的 priority **数值越小越严重**（1 最高，4 最低）；
# 而平台的 severity 语义是"越靠前越严重"（critical 最高）。
# 两者方向相反，必须显式映射 —— 写反了不会报错，
# 只会静默地让所有告警的严重度颠倒，导致研判层做出错误判断。
_PRIORITY_TO_SEVERITY: dict[int, str] = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}

_DEFAULT_PRIORITY = 3  # Suricata 默认 priority，映射为 medium


@dataclass
class EveAlert:
    """类型化后的 Suricata 告警事件。

    只保留系统真正需要的字段；完整原始事件存在 raw 里 ——
    研判层需要它作为证据，也是"结论可追溯"的基础。
    """

    event_type: str
    detected_at: datetime  # 事件原始时间（带时区）
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    protocol: str | None
    signature: str  # 规则签名文本，如 "SQL Injection Attempt"
    signature_id: int  # Suricata 规则 sid
    category: str  # 规则分类，如 "Web Application Attack"
    severity: str  # 已映射为平台语义（critical/high/...）
    raw: dict[str, Any]  # 原始 eve 事件，供追溯


def _parse_timestamp(value: str) -> datetime:
    """解析 Suricata 时间戳。

    格式：`2017-07-05T10:00:00.123456+0000`

    坑：Python 的 `datetime.fromisoformat` 在 3.11 之前**不接受** `+0000`
    这种不带冒号的时区写法，必须替换成 `+00:00`。
    解析失败时回退到当前时间，保证字段不为 None（数据库列 NOT NULL）。
    """
    if not value:
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(value.replace("+0000", "+00:00"))
    except ValueError:
        # 时间戳格式异常时不让整条告警作废 —— 用当前时间兜底
        return datetime.now(UTC)


def parse_eve_line(line: str) -> EveAlert | None:
    """解析 eve.json 的一行。

    Returns:
        EveAlert  —— 若该行是合法的 alert 事件
        None      —— 若该行是其他事件类型、空行、或无法解析
    """
    line = line.strip()
    if not line:
        return None

    try:
        evt = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        # 脏行直接跳过。不记日志的原因：重放时日志会被刷爆，
        # 统计"跳过了多少行"由调用方（Feeder）负责。
        return None

    # 只处理 alert 事件。eve.json 里 alert 只占一部分，
    # 把 flow/dns/http 也当告警会让系统被无关事件淹没。
    if evt.get("event_type") != "alert":
        return None

    alert = evt.get("alert") or {}
    priority = alert.get("severity", _DEFAULT_PRIORITY)

    return EveAlert(
        event_type="alert",
        detected_at=_parse_timestamp(evt.get("timestamp", "")),
        # 用 "0.0.0.0" 而非 None：数据库该列 NOT NULL，
        # 且去重键需要它参与拼接（见 services/alert_service.py）。
        src_ip=evt.get("src_ip") or "0.0.0.0",
        src_port=evt.get("src_port"),
        dst_ip=evt.get("dest_ip") or "0.0.0.0",
        dst_port=evt.get("dest_port"),
        protocol=evt.get("proto"),
        signature=alert.get("signature") or "Unknown",
        signature_id=int(alert.get("signature_id") or 0),
        category=alert.get("category") or "",
        severity=_PRIORITY_TO_SEVERITY.get(priority, "info"),
        raw=evt,
    )
