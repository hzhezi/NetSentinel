"""LLM 研判的 prompt 模板。

═══════════════════════════════════════════════════════════════════
防幻觉铁律（设计文档 §6.4）—— 这四条是这个项目在 LLM 使用上的底线
═══════════════════════════════════════════════════════════════════
1. 只引用告警或工具结果中的证据；**查不到视为"未知"，而非"安全"**
2. **needs_human_review 是一等结论**，不是失败
3. **不得凭记忆写 MITRE 编号**（本项目当前阶段：不确定就留空）
4. 严重度用**自己的判断**，不直接抄检测层上报值

为什么这四条重要（不是形式主义）：
    LLM 的天性是"给出看起来合理的答案"。在安全场景下，
    一个自信的错误结论比"我不确定"危险得多 ——
    分析师可能据此放行真实攻击。所以必须用 prompt 明确给出
    "承认不确定"的正当性。

测试 test_system_prompt_contains_anti_hallucination_rules
会检查这些规则是否存在，防止被无意删改。
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

from typing import Any

TRIAGE_SYSTEM = """你是网络安全运营中心（SOC）的值班分析师，负责对 IDS 告警做快速分诊。

你的任务是判断这条告警的性质，并输出严格 JSON。

【铁律 —— 必须遵守】
1. 只引用告警本身提供的信息。**信息不足时，说"未知"，不要说"安全"** ——
   "没查到证据"和"确认无害"是完全不同的两件事。
2. `needs_human_review` 是**正当结论**，不是失败。当你拿不准时选它，
   不要为了显得确定而硬给一个判断。
3. **不得凭记忆输出 MITRE ATT&CK 编号**。不确定就把 mitre_techniques 留空数组。
   编造的技术编号会误导后续调查。
4. severity 用**你自己的判断**，不要照抄告警上报的级别 ——
   检测规则给出的级别是机械映射的，可能偏高或偏低。

【输出格式】
只输出 JSON 对象，不要 markdown 代码块，不要额外说明。字段：
- verdict: "true_positive" | "false_positive" | "needs_human_review"
- severity: "critical" | "high" | "medium" | "low"
- confidence: 0-100 的整数（证据弱时给低分，这是诚实的表现）
- escalate: 布尔值，是否需要升级做深度调查（拿不准或疑似严重时设 true）
- attack_type: 字符串或 null（无法判断则为 null）
- summary: 2-3 句中文，分析师 10 秒内能读懂
- mitre_techniques: 字符串数组，不确定则为空数组
- recommended_actions: 2-4 条具体处置建议（字符串数组）
"""


def build_triage_prompt(alert: dict[str, Any]) -> str:
    """构造分诊的用户 prompt。

    只传结构化字段而不传原始 eve（原始事件可能很大，浪费 token）。
    深度调查阶段（L2）才需要完整原始数据。
    """
    lines = ["请研判以下 IDS 告警：", ""]
    # 按重要性排序，让模型先看到关键信息
    for key, label in [
        ("signature", "告警签名"),
        ("category", "分类"),
        ("severity", "检测层上报的严重度"),
        ("src_ip", "源 IP"),
        ("src_port", "源端口"),
        ("dst_ip", "目标 IP"),
        ("dst_port", "目标端口"),
        ("protocol", "协议"),
        ("detected_at", "事件时间"),
    ]:
        value = alert.get(key)
        if value is not None and value != "":
            lines.append(f"- {label}: {value}")

    return "\n".join(lines)
