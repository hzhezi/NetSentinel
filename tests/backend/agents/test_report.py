"""Report Agent（安全日报）的测试。

定位：**独立于实时研判主图**的汇总任务。
    实时研判：每条告警触发，单条视角，秒级
    日报：   定时/手动触发，全局视角，分钟级

设计要点：
    1. **输入是统计数据而非明细**：日报关心"今天有多少、分布如何、
       最值得关注的是什么"，把几万条明细塞给 LLM 既贵又没必要。
    2. **重点事件摘要**：从高严重度 / 需人工复核的告警里挑若干条，
       让日报有具体内容而不只是数字。
    3. **失败降级**：LLM 不可用时给出基于统计的模板化日报，
       而不是什么都不产出 —— 日报有基础内容也好过没有。
"""

import pytest

from backend.agents.report import ReportAgent, ReportResult


class FakeLLM:
    """假的 LLM，返回预设的日报文本。"""

    def __init__(self, text: str = "今日安全态势平稳。", raise_error: bool = False):
        self.text = text
        self.raise_error = raise_error
        self.calls: list[dict] = []
        self.last_usage = {"prompt_tokens": 500, "completion_tokens": 200}

    def complete_text(self, system: str, user: str) -> str:
        self.calls.append({"system": system, "user": user})
        if self.raise_error:
            from backend.agents.llm_client import LLMError

            raise LLMError("模拟的 LLM 故障")
        return self.text


@pytest.fixture
def stats():
    """典型的统计输入。"""
    return {
        "period_start": "2026-09-26T00:00:00+00:00",
        "period_end": "2026-09-26T23:59:59+00:00",
        "alerts": {
            "total": 128,
            "by_severity": {"critical": 3, "high": 20, "medium": 65, "low": 40},
            "by_attack_type": {"SQL Injection": 12, "PortScan": 80, "XSS": 36},
            "top_sources": [
                {"src_ip": "45.33.32.156", "count": 45},
                {"src_ip": "185.220.101.5", "count": 23},
            ],
        },
        "triage": {
            "by_verdict": {"true_positive": 30, "false_positive": 60, "needs_human_review": 38},
            "total_tokens": 45000,
            "avg_latency_ms": 2100,
        },
        "notable_alerts": [
            {
                "signature": "Log4Shell JNDI Injection",
                "severity": "critical",
                "src_ip": "45.33.32.156",
                "verdict": "true_positive",
            },
            {
                "signature": "Possible Reverse Shell",
                "severity": "critical",
                "src_ip": "185.220.101.5",
                "verdict": "needs_human_review",
            },
        ],
        "suppressed_count": 15,
    }


# ── 基本产出 ───────────────────────────────────────────────────


def test_agent_returns_report(stats):
    agent = ReportAgent(llm=FakeLLM("今日共处理 128 条告警，其中 3 条严重。"))
    result = agent.generate(stats)

    assert isinstance(result, ReportResult)
    assert "128" in result.content
    assert result.error is None


def test_report_includes_period(stats):
    """日报必须标明统计时段 —— 否则读者不知道这是哪段时间的。"""
    agent = ReportAgent(llm=FakeLLM("内容"))
    result = agent.generate(stats)

    assert result.period_start == stats["period_start"]
    assert result.period_end == stats["period_end"]


def test_llm_receives_stats_not_raw_alert_list(stats):
    """发给 LLM 的应是**统计摘要**，不是几万条明细。

    这条锁住成本控制的设计：明细喂给 LLM 会 token 爆炸且无必要。
    """
    llm = FakeLLM("内容")
    ReportAgent(llm=llm).generate(stats)

    prompt = llm.calls[0]["user"]
    # 统计数据应出现
    assert "128" in prompt
    assert "PortScan" in prompt
    # notable_alerts 之外的明细不应出现（这里只有 2 条摘要，不算明细）
    assert len(prompt) < 8000  # 提示词不应该很长


def test_includes_notable_alerts_in_prompt(stats):
    """重点事件要进提示词 —— 日报需要具体内容而不只是数字。"""
    llm = FakeLLM("内容")
    ReportAgent(llm=llm).generate(stats)

    prompt = llm.calls[0]["user"]
    assert "Log4Shell" in prompt
    assert "Reverse Shell" in prompt


def test_system_prompt_requires_honesty(stats):
    """提示词要求：不得夸大威胁、数字要准确。

    日报会被拿去做决策，编造的"态势严重"没有价值。
    """
    llm = FakeLLM("内容")
    ReportAgent(llm=llm).generate(stats)

    system = llm.calls[0]["system"]
    assert "不得" in system or "不要" in system
    assert "数字" in system or "准确" in system


def test_records_token_usage(stats):
    llm = FakeLLM("内容")
    result = ReportAgent(llm=llm).generate(stats)
    assert result.usage["prompt_tokens"] == 500


# ── 失败降级 ───────────────────────────────────────────────────


def test_llm_failure_degrades_to_template(stats):
    """LLM 不可用时给出基于统计的模板化日报，而非空内容。

    日报的基础价值（数字汇总）不依赖 LLM ——
    即使模型故障，值班人员也该看到"今天有多少告警"。
    """
    result = ReportAgent(llm=FakeLLM(raise_error=True)).generate(stats)

    assert result.error is not None
    assert result.content  # 不能是空字符串
    # 模板日报仍应包含关键数字
    assert "128" in result.content


def test_no_llm_configured_uses_template(stats):
    """未配置 LLM 时同样走模板路径。"""
    result = ReportAgent(llm=None).generate(stats)

    assert result.content
    assert "128" in result.content


def test_empty_stats_handled():
    """无告警的时段也要能生成日报（"今日无告警"也是有效结论）。"""
    empty = {
        "period_start": "2026-09-26T00:00:00+00:00",
        "period_end": "2026-09-26T23:59:59+00:00",
        "alerts": {"total": 0, "by_severity": {}, "by_attack_type": {}, "top_sources": []},
        "triage": {"by_verdict": {}, "total_tokens": 0, "avg_latency_ms": 0},
        "notable_alerts": [],
        "suppressed_count": 0,
    }
    result = ReportAgent(llm=FakeLLM("今日无告警。")).generate(empty)
    assert result.content
