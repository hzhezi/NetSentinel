"""DeepSeek LLM 客户端（OpenAI 兼容接口）。

═══════════════════════════════════════════════════════════════════
核心挑战：让 LLM **稳定地**输出结构化数据
═══════════════════════════════════════════════════════════════════
LLM 输出的是自然语言，而系统需要能存库、能过滤的结构化字段。
两者之间的桥是三重保障：

    ① API 层强制：response_format={"type": "json_object"}
       要求模型只输出 JSON（DeepSeek 支持此参数）

    ② 解析层容错：剥离 markdown 代码围栏
       即使要求"只输出 JSON"，模型仍常包一层 ```json ... ```
       不处理的话每次都要白重试一遍

    ③ 校验层严格：Pydantic 校验，不合规就**重试**
       重试时把错误信息回传给模型，让它自我修正。
       校验不过就"凑合着用"是不可接受的 —— 脏结论比没有结论更危险。

为什么用 openai 这个库而不是自己写 HTTP：
    DeepSeek 提供 OpenAI 兼容接口，官方 SDK 已处理好重试、
    超时、流式等细节，没必要重复实现。
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import json
import re
from typing import Any

import structlog
from openai import APIError, OpenAI

from backend.agents.prompts import TRIAGE_SYSTEM, build_triage_prompt
from backend.schemas.triage import TriageResult

log = structlog.get_logger(__name__)


class LLMError(Exception):
    """LLM 调用或输出解析失败。

    单独定义而不直接用底层异常：上层（Agent/API）需要区分
    "LLM 不可用"（可重试/降级）与"业务逻辑错误"。
    """


# 匹配 ```json ... ``` 或 ``` ... ``` 代码围栏
_CODE_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def _extract_json(text: str) -> str:
    """从模型输出中提取 JSON 字符串。

    两种情况要处理：
        1. 包在 markdown 代码围栏里（最常见）
        2. 前后有多余说明文字（如 "好的，这是我的分析：{...}"）

    先试直接解析；失败再试剥离围栏；再失败则尝试截取第一个 { 到
    最后一个 } 之间的内容。都不行就原样返回，让调用方报错。
    """
    text = text.strip()

    # 快速路径：本来就是纯 JSON
    try:
        json.loads(text)
        return text
    except json.JSONDecodeError:
        pass

    # 剥离代码围栏
    match = _CODE_FENCE.search(text)
    if match:
        return match.group(1).strip()

    # 兜底：截取最外层的花括号
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        return text[start : end + 1]

    return text


class LLMClient:
    """DeepSeek 客户端（OpenAI 兼容）。"""

    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        max_retries: int = 3,
        timeout: float = 60.0,
    ):
        """
        Args:
            max_retries: 输出不合规时的重试次数（不含首次）。
                         设为 0 则只试一次 —— 测试里用。
        """
        self.model = model
        self.max_retries = max_retries
        self._client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)
        # 最近一次调用的 token 用量。报告需要成本数据，
        # 而 openai SDK 把 usage 挂在 response 上，取出来存下来更方便。
        self.last_usage: dict[str, int] = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
        }

    # ── 底层调用（测试通过 monkeypatch 替换它）────────────────────

    def _raw_call(self, system: str, user: str) -> str:
        """发起一次 LLM 调用，返回原始文本。

        所有测试都替换这个方法来避免真实网络调用与费用。
        """
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                # ① API 层强制 JSON 输出
                response_format={"type": "json_object"},
                # 低温度：研判是分析任务而非创作，需要稳定可复现的结果
                temperature=0.1,
            )
        except APIError as exc:
            raise LLMError(f"LLM API 调用失败: {exc}") from exc

        if resp.usage is not None:
            self.last_usage = {
                "prompt_tokens": resp.usage.prompt_tokens,
                "completion_tokens": resp.usage.completion_tokens,
            }

        return resp.choices[0].message.content or ""

    # ── 分诊（L1 快研判）─────────────────────────────────────────

    def triage(self, alert: dict[str, Any]) -> TriageResult:
        """对一条告警做快速分诊，返回结构化结论。

        重试策略：把上一次的失败原因**回传给模型**，
        让它有机会自我修正，而不是盲目重试同样的 prompt。
        """
        user_prompt = build_triage_prompt(alert)
        last_error = ""

        for attempt in range(self.max_retries + 1):
            prompt = user_prompt
            if last_error:
                # 带上错误反馈重试 —— 单纯重复同样的请求收效甚微
                prompt = (
                    f"{user_prompt}\n\n"
                    f"【上次输出不合规】{last_error}\n"
                    f"请重新输出，严格符合之前说明的 JSON 格式。"
                )

            raw = self._raw_call(TRIAGE_SYSTEM, prompt)

            try:
                # ② 容错：剥离代码围栏等杂质
                payload = json.loads(_extract_json(raw))
                # ③ 严格校验
                return TriageResult.model_validate(payload)
            except json.JSONDecodeError as exc:
                last_error = f"输出不是合法 JSON（{exc}）"
            except Exception as exc:  # pydantic.ValidationError
                last_error = f"字段不符合要求（{exc}）"

            log.warning(
                "triage_output_invalid",
                attempt=attempt + 1,
                max_attempts=self.max_retries + 1,
                error=last_error,
            )

        # 反复失败：明确报错，而不是返回一个"凑合"的结果。
        # 上层可将此告警标记为 needs_human_review 并记录，而非静默丢弃。
        raise LLMError(f"LLM 输出在 {self.max_retries + 1} 次尝试后仍不合规：{last_error}")

    # ── 工具调用（供 Investigation Agent 使用）────────────────────

    def complete_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        force_final: bool = False,
    ) -> dict[str, Any]:
        """发起一次带工具定义的调用，返回解析后的意图。

        返回值的 type 有三种：
            "tool_call" —— 模型要调工具，附带 name/args/id
            "final"     —— 模型给出最终结论，content 是 JSON 文本
            "text"      —— 模型的中间推理文字（叙述性内容）

        为什么要归一化成这几种：
            不同供应商的工具调用响应结构差异较大。归一化后，
            Investigation Agent 只处理这三种情况，与供应商解耦。

        Args:
            force_final: 最后一轮设为 True，通过 tool_choice 强制模型
                         不再调工具而是给出结论 —— 保证调查一定收敛。
        """
        tool_defs = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in tools
        ]

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "tools": tool_defs,
            "temperature": 0.1,
        }
        if force_final:
            # 禁止再调工具，迫使模型输出结论文本。
            # 这是"迭代上限"的执行手段：即使模型还想查，也必须收尾。
            kwargs["tool_choice"] = "none"

        try:
            resp = self._client.chat.completions.create(**kwargs)
        except APIError as exc:
            raise LLMError(f"LLM 工具调用失败: {exc}") from exc

        if resp.usage is not None:
            self.last_usage = {
                "prompt_tokens": resp.usage.prompt_tokens,
                "completion_tokens": resp.usage.completion_tokens,
            }

        choice = resp.choices[0]
        message = choice.message

        # 优先检查工具调用（有些模型会同时给文字和工具调用）
        if message.tool_calls:
            call = message.tool_calls[0]
            try:
                args = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                # 参数不是合法 JSON：交给工具层处理（run_tool 会返回 error）
                args = {}
            return {
                "type": "tool_call",
                "name": call.function.name,
                "args": args,
                "id": call.id,
            }

        content = (message.content or "").strip()

        # 没有工具调用：判断这是最终结论还是中间推理。
        # 判据：内容里是否含 JSON 对象且带 verdict 字段。
        # 用这个判据而非"最后一轮"是因为模型可能提前给出结论。
        if _looks_like_verdict(content):
            return {"type": "final", "content": content}

        # 最后一轮强制收尾：即使格式不完全规范也当结论处理，
        # 让 InvestigationAgent 的解析与降级逻辑接手。
        if force_final:
            return {"type": "final", "content": content}

        return {"type": "text", "content": content}


def _looks_like_verdict(content: str) -> bool:
    """判断模型输出是否像一条最终结论。

    只看是否含 verdict 字段，不做严格校验 ——
    严格校验由 InvestigationAgent 的 Pydantic/解析逻辑负责。
    """
    if "verdict" not in content:
        return False
    # 必须是 JSON 形态（含花括号），而不是叙述里恰好提到这个词
    return "{" in content and "}" in content

    def complete_text(self, system: str, user: str) -> str:
        """不带工具的简单文本补全（供 Agent 收尾逼问结论使用）。"""
        return self._raw_call(system, user)
