"""LLM 研判结果的 Schema（结构化输出契约）。

这是"防幻觉"的第一道防线：LLM 必须输出符合这个结构的数据，
否则视为失败并重试。相比让它自由发挥，强制结构化让结果：
    - 可校验（Pydantic 检查）
    - 可存储（字段明确，能进数据库）
    - 可比较（verdict 是枚举，能统计准确率）

字段设计参考 alert-triage-copilot（MIT）的设计，并根据本项目调整：
    - verdict 三态而非二态：needs_human_review 是**一等结论**，
      不是失败。没有它，模型在拿不准时会"编"一个自信的答案。
"""

from typing import Literal

from pydantic import BaseModel, Field

# 三态而非二态 —— 这是关键设计。
# 若只允许 true_positive / false_positive，模型在证据不足时会被迫二选一，
# 于是"编造"一个看起来合理的答案。给一个诚实的出口，幻觉显著减少。
Verdict = Literal["true_positive", "false_positive", "needs_human_review"]

Severity = Literal["critical", "high", "medium", "low"]


class TriageResult(BaseModel):
    """单条告警的研判结论。

    这是 LLM 与系统之间的数据契约：模型输出 JSON，我们按此校验。
    校验不通过就重试，而不是"凑合着用"——脏结论比没有结论更危险。
    """

    verdict: Verdict = Field(description="真实攻击 / 误报 / 需人工复核")
    severity: Severity = Field(description="模型**自己的**严重度判断，不抄检测层上报值")
    confidence: int = Field(
        ge=0,
        le=100,
        description="对本次结论的置信度 0-100。证据弱时应给低分而非硬下结论",
    )
    # 是否升级到 L2 深度调查。
    # 由模型自己判断"我拿不准/这事严重"，而非纯靠硬规则阈值。
    escalate: bool = Field(
        default=False,
        description="是否需要升级到深度调查（拿不准或疑似严重）",
    )
    attack_type: str | None = Field(
        default=None,
        description="攻击类型（如 DDoS / PortScan / SQL Injection），无法判断则为 null",
    )
    summary: str = Field(
        description="2-3 句中文摘要，分析师 10 秒内能看懂",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK 技术编号，如 ['T1110']。不确定则留空",
    )
    recommended_actions: list[str] = Field(
        default_factory=list,
        description="2-4 条具体处置建议",
    )
