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
