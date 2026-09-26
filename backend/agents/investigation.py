"""Investigation Agent：工具驱动的多轮深度调查（L2）。

═══════════════════════════════════════════════════════════════════
与 L1 分诊的区别
═══════════════════════════════════════════════════════════════════
    L1（Triage）   ：单轮 · 只看告警本身 · 便宜快 · 结论保守
    L2（Investigation）：多轮 · 主动调工具补证据 · 强模型 · 结论有依据

为什么需要 L2（实测数据支撑）：
    L1 只拿到五元组 + 签名时，结论几乎全是 needs_human_review、
    置信度 35-45 —— 因为信息确实不够。
    L2 能查 IP 信誉、关联历史告警、查资产重要性，
    证据充分后结论才可能明确。

═══════════════════════════════════════════════════════════════════
ReAct 式工具循环
═══════════════════════════════════════════════════════════════════
    1. 把「告警 + 工具清单」发给模型
    2. 模型回「要调工具」或「给结论」
    3. 执行工具，把结果回传
    4. 重复，直到给结论或达迭代上限
    5. **最后一轮强制要求结论** —— 保证一定有结构化输出

两个安全阀：
    - max_iterations：防模型陷入"再查一个"的死循环（烧钱且不返回）
    - 最后强制 verdict：即使模型还想查，也必须给出阶段性结论

═══════════════════════════════════════════════════════════════════
证据链（Evidence Trail）—— 这个模块最重要的产出
═══════════════════════════════════════════════════════════════════
每一步推理、每一次工具调用及其结果都被记录，最终与结论一起持久化。

为什么它是核心而非副产品：
    "黑盒 AI 说这是误报，请相信我" 在安全运营中毫无价值 ——
    分析师需要能逐行审计："它查了什么、查到什么、为什么这么判断"。
    证据链让结论**可追溯、可质疑、可复核**，这是能落地的前提。

工具失败也被记录（在 trail 里带 error 字段）：
    让审计者看到"哪些证据是缺失的"，从而正确评估结论的可靠性。
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from backend.agents.tools import TOOL_SCHEMAS, run_tool

log = structlog.get_logger(__name__)

# 迭代上限。5 轮足够一个有条理的调查（查 IP → 查资产 → 查关联 →
# 查 MITRE → 给结论），又不会在模型卡住时烧太多钱。
DEFAULT_MAX_ITERATIONS = 5

INVESTIGATION_SYSTEM = """你是资深 SOC 分析师，正在对一条 IDS 告警进行深入调查。

你可以调用工具来收集证据。**先调查，再下结论。**

【调查方法】
- 查外部源 IP 的信誉，判断是否为已知恶意。
- 查目标 IP 的资产信息，判断攻击目标的重要性（打数据库比打打印机严重得多）。
- 查是否有同源/同目标的关联告警 —— 一条普通告警可能是多步攻击的一环。
- 需要 MITRE ATT&CK 编号时，**必须用 lookup_mitre_technique 查表**。

【铁律 —— 必须遵守】
1. 只引用告警本身或工具返回结果中的证据。**信息不足时，说"未知"，不要说"安全"** ——
   "没查到负面信息"和"确认无害"是完全不同的两件事。
2. `needs_human_review` 是**正当结论**，不是失败。当最终判断取决于工具无法获取的信息
   （如用户意图、业务上下文、加密内容）时，选它并说明人工应该查什么。
3. **不得凭记忆输出 MITRE ATT&CK 编号**。不确定就把 mitre_techniques 留空数组。
4. severity 用你自己的判断，不要照抄告警上报的级别。

【输出要求】
调查完成后直接输出最终结论的 JSON（不要 markdown 代码块）：
{
  "verdict": "true_positive" | "false_positive" | "needs_human_review",
  "severity": "critical" | "high" | "medium" | "low",
  "confidence": 0-100,
  "summary": "2-3 句中文，引用关键证据",
  "mitre_techniques": ["T1190"],
  "recommended_actions": ["具体建议"]
}
"""


@dataclass
class InvestigationResult:
    """深度调查的结论与证据链。"""

    verdict: str
    severity: str
    confidence: int
    summary: str
    mitre_techniques: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    attack_type: str | None = None
    escalate: bool = True  # 已经是 L2，标记为已升级

    # ── 过程记录 ──
    evidence_trail: list[dict[str, Any]] = field(default_factory=list)
    iterations: int = 0
    latency_ms: int = 0
    usage: dict[str, int] = field(default_factory=dict)
    error: str | None = None


def _degraded_result(error: str, iterations: int, started: float) -> InvestigationResult:
    """构造降级结论。

    调查失败（模型输出不合规、API 故障）时使用：
    降级为 needs_human_review，**而不是丢弃告警** ——
    研判器故障不该导致漏报。
    """
    return InvestigationResult(
        verdict="needs_human_review",
        severity="medium",
        confidence=0,
        summary=f"深度调查未能完成，需人工复核。（原因：{error}）",
        mitre_techniques=[],
        recommended_actions=["人工查看原始告警并结合其他信息判断"],
        evidence_trail=[],
        iterations=iterations,
        latency_ms=int((time.monotonic() - started) * 1000),
        error=error,
    )


class InvestigationAgent:
    """工具驱动的多轮调查 Agent。

    依赖注入 llm（需实现 complete_with_tools），
    因此测试可注入假客户端，不需要 API key 也不花钱。
    """

    def __init__(
        self,
        llm: Any,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        tool_context: dict[str, Any] | None = None,
    ):
        """
        Args:
            llm: 具备 `complete_with_tools(messages, tools) -> dict` 的客户端。
            max_iterations: 迭代上限（防死循环）。
            tool_context: 工具运行时依赖（告警池、告警查询函数等）。
        """
        self.llm = llm
        self.max_iterations = max_iterations
        self.tool_context = tool_context or {}

    def investigate(self, alert: dict[str, Any]) -> InvestigationResult:
        """对一条告警执行深度调查。"""
        started = time.monotonic()
        trail: list[dict[str, Any]] = []
        usage_total = {"prompt_tokens": 0, "completion_tokens": 0}

        # 对话历史：随调查推进不断增长
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": INVESTIGATION_SYSTEM},
            {
                "role": "user",
                "content": (
                    "请调查并判断这条 IDS 告警：\n\n"
                    f"{json.dumps(alert, ensure_ascii=False, indent=2, default=str)}"
                ),
            },
        ]

        for iteration in range(1, self.max_iterations + 1):
            last_chance = iteration == self.max_iterations

            try:
                reply = self.llm.complete_with_tools(
                    messages, TOOL_SCHEMAS, force_final=last_chance
                )
            except Exception as exc:
                log.warning("investigation_llm_failed", error=str(exc))
                result = _degraded_result(str(exc), iteration, started)
                result.evidence_trail = trail
                return result

            # 累加 token 用量（报告需要成本数据）
            for key in usage_total:
                usage_total[key] += getattr(self.llm, "last_usage", {}).get(key, 0)

            rtype = reply.get("type")

            # ├─ 情况 A：模型给出了结论
            if rtype == "final":
                return self._parse_final(
                    reply.get("content", ""), trail, iteration, usage_total, started
                )

            # ├─ 情况 B：模型的中间推理（叙述性文字）
            if rtype == "text":
                trail.append({"type": "reasoning", "text": reply.get("content", "")})
                messages.append({"role": "assistant", "content": reply.get("content", "")})
                continue

            # ├─ 情况 C：模型要求调用工具
            if rtype == "tool_call":
                name = reply.get("name", "")
                args = reply.get("args") or {}
                call_id = reply.get("id", f"call_{iteration}")

                # 执行工具（run_tool 永不抛异常，失败会返回 {"error": ...}）
                tool_result = run_tool(name, args, self.tool_context)

                step: dict[str, Any] = {
                    "type": "tool_call",
                    "tool": name,
                    "call_id": call_id,  # 与模型的调用 ID 对应，便于对照审计
                    "input": args,
                    "result": tool_result,
                }
                if isinstance(tool_result, dict) and "error" in tool_result:
                    # 失败也记录 —— 让审计者看到"哪些证据缺失"
                    step["error"] = tool_result["error"]
                trail.append(step)

                # 把工具结果回传给模型，让它继续
                messages.append(
                    {
                        "role": "assistant",
                        "content": f"调用工具 {name}({json.dumps(args, ensure_ascii=False)})",
                    }
                )
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            f"工具 {name} 返回结果：\n"
                            f"{json.dumps(tool_result, ensure_ascii=False, default=str)}"
                        ),
                    }
                )
                continue

            # 未知的回复类型：记录后继续，避免直接崩
            trail.append({"type": "unknown_reply", "reply": reply})

        # 理论上不会到这里（最后一轮 force_final 应产出结论），
        # 但保持防御性：明确报错而非假装有结论
        result = _degraded_result(
            f"达到迭代上限（{self.max_iterations}）仍未给出结论", self.max_iterations, started
        )
        result.evidence_trail = trail
        return result

    def _parse_final(
        self,
        content: str,
        trail: list[dict[str, Any]],
        iterations: int,
        usage: dict[str, int],
        started: float,
    ) -> InvestigationResult:
        """解析模型给出的最终结论。

        解析失败时降级为 needs_human_review —— 与分析失败同等处理，
        都保证"告警不丢、结论诚实"。
        """
        try:
            payload = json.loads(self._extract_json(content))
        except (json.JSONDecodeError, TypeError) as exc:
            result = _degraded_result(f"结论不是合法 JSON（{exc}）", iterations, started)
            result.evidence_trail = trail
            return result

        trail.append({"type": "verdict", "input": payload})

        return InvestigationResult(
            verdict=payload.get("verdict", "needs_human_review"),
            severity=payload.get("severity", "medium"),
            confidence=int(payload.get("confidence") or 0),
            summary=payload.get("summary", ""),
            mitre_techniques=payload.get("mitre_techniques") or [],
            recommended_actions=payload.get("recommended_actions") or [],
            attack_type=payload.get("attack_type"),
            evidence_trail=trail,
            iterations=iterations,
            latency_ms=int((time.monotonic() - started) * 1000),
            usage=usage,
        )

    @staticmethod
    def _extract_json(text: str) -> str:
        """从模型输出中提取 JSON（可能被 ```json 包裹或有前后文字）。"""
        text = text.strip()
        try:
            json.loads(text)
            return text
        except json.JSONDecodeError:
            pass

        # 剥离代码围栏
        if "```" in text:
            import re

            match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
            if match:
                return match.group(1).strip()

        # 兜底：截取最外层花括号
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            return text[start : end + 1]
        return text
