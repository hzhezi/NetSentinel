"""Investigation Agent 的工具集。

═══════════════════════════════════════════════════════════════════
工具是什么
═══════════════════════════════════════════════════════════════════
LLM 本身只能读告警文本。工具让它能**主动获取更多证据**：
    - 这个源 IP 的信誉如何？
    - 同一来源还触发过什么告警？（多步攻击线索）
    - 目标是内网的什么资产？（影响严重度判断）
    - 这个行为对应哪个 MITRE 技术？（防编造）

每个工具由两部分组成（借鉴 alert-triage-copilot）：
    1. **schema**：给 LLM 看的 JSON 描述（做什么、要什么参数）
       —— 模型只能"申请调用"，执行权在我们手里
    2. **实现**：真正运行的函数

═══════════════════════════════════════════════════════════════════
两个关键设计
═══════════════════════════════════════════════════════════════════

① **数据用本地的，签名保持真实**
    演示/答辩不能因外部 API 超时或限流而中断。
    但每个工具的入参出参与真实服务（AbuseIPDB / VirusTotal）一致 ——
    将来换真实服务只改本文件的实现，接口与 prompt 都不用动。

② **"查不到"必须显式说"未知"，不能说"安全"**
    LLM 的天然倾向是把"没有负面信息"读成"没问题"。
    在安全场景下这是危险的：一个没有情报记录的 IP
    可能是全新的攻击源。所以工具返回时要主动纠正这个倾向，
    而不是留空让模型自由解读。

③ **工具内部异常转为返回值**
    工具崩了不该让整个调查失败。把错误作为"数据"返回，
    模型可以据此换个工具、或用已有证据继续判断。
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

_DATA_DIR = Path(__file__).parent / "data"


@lru_cache(maxsize=1)
def _load_intel() -> dict:
    """加载本地情报库。

    用 lru_cache 只读一次：工具会被频繁调用（每条告警多次），
    每次都读文件是浪费。
    """
    with open(_DATA_DIR / "threat_intel.json", encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def _load_mitre() -> dict:
    with open(_DATA_DIR / "mitre_map.json", encoding="utf-8") as f:
        return json.load(f)


def _is_private_ip(ip: str) -> bool:
    """判断是否为内网地址（RFC1918 三段 + 回环）。"""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 127


# ── 工具实现 ───────────────────────────────────────────────────


def lookup_ip_reputation(args: dict, context: dict | None = None) -> dict[str, Any]:
    """查询 IP 的威胁情报。

    ⚠️ 注意返回语义：**查不到 = 未知，不是安全**。
    """
    ip = args.get("ip", "")

    if _is_private_ip(ip):
        # 内网地址：公网情报源不会有记录，正确做法是引导查资产而非判定安全
        return {
            "ip": ip,
            "note": (
                "这是内部/私有 IP，公网威胁情报中不会有记录。"
                "应改用 get_asset_context 查询该资产的角色与重要性，"
                "而不是把'查不到'理解为'安全'。"
            ),
        }

    intel = _load_intel()
    record = intel.get(ip)
    if not record:
        return {
            "ip": ip,
            "reputation": "unknown",
            "note": (
                "威胁情报库中无此 IP 的记录。这表示**未知**，不代表安全 —— "
                "新出现的攻击源通常还没有被情报库收录。"
            ),
        }
    return {"ip": ip, **record}


def lookup_mitre_technique(args: dict, context: dict | None = None) -> dict[str, Any]:
    """把攻击行为描述映射到 MITRE ATT&CK 技术编号。

    这是**防编造**的机制：模型必须通过查表获得编号，
    而不是凭记忆写一个看起来专业的 ID。
    """
    behavior = str(args.get("behavior", "")).lower().strip()
    # 归一化：把空格/连字符统一成下划线，提高匹配率
    normalized = behavior.replace(" ", "_").replace("-", "_")

    mitre = {k: v for k, v in _load_mitre().items() if not k.startswith("_")}

    matches = []
    for key, entry in mitre.items():
        # 双向包含匹配：模型可能给更泛或更具体的描述
        if (
            key == normalized
            or key in normalized
            or normalized in key
            or behavior in entry["technique_name"].lower()
        ):
            matches.append(entry)

    # 去重（多个 key 可能指向同一技术，如 port_scan / network_scan 都映射到 T1046）
    seen = set()
    unique = []
    for m in matches:
        if m["technique_id"] not in seen:
            seen.add(m["technique_id"])
            unique.append(m)

    if not unique:
        # 匹配不到时给出可用选项 —— 让模型下一步能查对，而不是编一个
        return {
            "note": (
                "没有匹配到该行为的技术编号。**不要凭记忆编造编号** —— "
                "可以尝试用下列已收录的行为名重新查询，或留空 mitre_techniques。"
            ),
            "available_behaviors": sorted(mitre.keys()),
        }
    return {"matches": unique}


def get_related_alerts(args: dict, context: dict | None = None) -> dict[str, Any]:
    """查找与当前告警相关联的其他告警（同源/同目标/同签名）。

    价值：单条"中等可疑"的告警，可能是某个多步攻击的一环。
    这是单看一条告警无法发现的信息。
    """
    allowed_fields = ("src_ip", "dst_ip", "signature", "attack_type")
    field = args.get("field", "")
    value = args.get("value", "")

    if field not in allowed_fields:
        return {"note": f"field must be one of: {', '.join(allowed_fields)}"}

    context = context or {}
    pool = context.get("alert_pool") or []
    exclude_id = context.get("exclude_id")

    related = [a for a in pool if a.get(field) == value and a.get("id") != exclude_id]

    if not related:
        return {
            "count": 0,
            "note": f"未找到其他 {field} = {value} 的告警。",
        }
    return {"count": len(related), "alerts": related}


def get_asset_context(args: dict, context: dict | None = None) -> dict[str, Any]:
    """查询内网资产的角色与重要性。

    为什么需要它：同一个扫描行为，打在数据库服务器和办公终端上，
    严重度判断完全不同。这是纯看告警文本无法得知的上下文。
    """
    ip = args.get("ip", "")
    assets = _load_intel().get("_internal_assets", {})
    record = assets.get(ip)

    if not record or ip.startswith("_"):
        return {
            "ip": ip,
            "note": (
                "资产库中无此 IP 的记录。可能是未登记的设备或外部地址。"
                "在判断严重度时应把'目标重要性未知'作为不确定性因素。"
            ),
        }
    return {"ip": ip, **record}


def get_alert_detail(args: dict, context: dict | None = None) -> dict[str, Any]:
    """获取告警的完整原始记录。

    浅层分诊只看摘要字段；深度调查需要原始 eve 记录
    （如 HTTP URI、TLS SNI、payload 长度等）。
    """
    alert_id = args.get("alert_id", "")
    context = context or {}
    lookup = context.get("alert_lookup")

    if lookup is None:
        return {"error": "缺少告警查询能力（工具调用时未提供上下文）"}

    alert = lookup(alert_id)
    if alert is None:
        return {"alert_id": alert_id, "note": "未找到该告警"}
    return dict(alert)


# ── 给 LLM 看的 schema ─────────────────────────────────────────

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "lookup_ip_reputation",
        "description": (
            "查询 IP 地址的威胁情报：信誉、滥用评分、地理位置、ISP、"
            "以及是否被标记为已知恶意。注意：返回 unknown 表示**未知**而非安全。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "要查询的 IPv4 地址"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "lookup_mitre_technique",
        "description": (
            "把攻击行为描述映射到 MITRE ATT&CK 技术编号。"
            "**必须用此工具获取编号，不得凭记忆编造**。"
            "若返回未匹配，可参考 available_behaviors 重新查询。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "behavior": {
                    "type": "string",
                    "description": "简短的行为描述，如 'brute force' 或 'port scan'",
                },
            },
            "required": ["behavior"],
        },
    },
    {
        "name": "get_related_alerts",
        "description": (
            "查找与当前告警相关联的其他告警（按相同源 IP / 目标 IP / 签名 / 攻击类型）。"
            "用于发现多步攻击或持续性扫描 —— 单条告警看不出的线索。"
            "当前告警自身不会计入结果。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "field": {
                    "type": "string",
                    "enum": ["src_ip", "dst_ip", "signature", "attack_type"],
                    "description": "按哪个字段匹配",
                },
                "value": {"type": "string", "description": "要匹配的值"},
            },
            "required": ["field", "value"],
        },
    },
    {
        "name": "get_asset_context",
        "description": (
            "查询内网资产的角色与重要性（如 Web 服务器 / 数据库 / 办公终端）。"
            "用于判断攻击目标的重要程度 —— 打数据库比打打印机严重得多。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "内网资产 IP"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "get_alert_detail",
        "description": "获取当前告警的完整原始记录（含载荷、协议细节等）。",
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "string", "description": "告警 ID"},
            },
            "required": ["alert_id"],
        },
    },
]


# 工具名 → 实现 的注册表
_IMPLEMENTATIONS = {
    "lookup_ip_reputation": lookup_ip_reputation,
    "lookup_mitre_technique": lookup_mitre_technique,
    "get_related_alerts": get_related_alerts,
    "get_asset_context": get_asset_context,
    "get_alert_detail": get_alert_detail,
}


def run_tool(
    name: str,
    args: dict[str, Any],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """执行工具调用，**永不抛异常**。

    异常转成 {"error": ...} 返回给模型 ——
    工具的 bug 不该让整个调查崩掉，模型可以据此换策略继续。

    context 用于注入运行时依赖（如告警池、告警查询函数）：
        工具实现保持"纯函数"风格，依赖从外部传入而非内部 import，
        这样测试时不需要数据库，也便于将来替换数据源。
    """
    impl = _IMPLEMENTATIONS.get(name)
    if impl is None:
        return {"error": f"未知工具: {name}"}

    try:
        return impl(args, context)
    except Exception as exc:
        log.warning("tool_execution_failed", tool=name, error=str(exc))
        return {"error": f"工具 {name} 执行失败: {exc}"}


def get_tool_names() -> list[str]:
    """当前可用工具名列表（供 prompt 与测试使用）。"""
    return sorted(_IMPLEMENTATIONS.keys())
