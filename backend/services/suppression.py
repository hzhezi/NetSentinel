"""抑制规则：把"已知噪声"告警自动过滤掉。

═══════════════════════════════════════════════════════════════════
解决什么问题
═══════════════════════════════════════════════════════════════════
真实 SOC 里相当一部分告警是**预期的**，例如：
    - 内部漏洞扫描器每周一凌晨扫描全网段
    - 监控系统定期探测端口存活
    - 已知的业务系统间的特殊协议交互

这些告警每次都触发研判 = 浪费分析师精力 + 浪费 LLM 费用。
抑制规则让用户显式声明"这类告警我已知晓，不必处理"。

═══════════════════════════════════════════════════════════════════
三条重要设计
═══════════════════════════════════════════════════════════════════

① **AND 逻辑**
    规则里的多个条件必须**同时**满足才抑制。
    如果只按 src_ip 抑制，该 IP 之后发起的**真实攻击**也会被静默吞掉 ——
    这是危险的过度抑制。用户想宽松抑制时可以只写一个条件（显式选择）。

② **可选过期**
    临时抑制（如安全演练期间）应能自动失效。
    "忘了删规则"导致的长期漏报是真实存在的运维事故。

③ **空规则绝不匹配**
    什么条件都没写的规则如果匹配所有告警，等于关闭了整个系统。
    这里显式禁止，宁可让它无效也不要造成灾难。

═══════════════════════════════════════════════════════════════════
与真实数据的关系
═══════════════════════════════════════════════════════════════════
本模块只做**匹配判断**（纯逻辑，无 IO），因此：
    - 测试不需要数据库
    - 可以从 DB 加载规则后构造，也可从配置/API 构造
规则持久化由 repository 层负责（见 suppression_repository）。
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog

log = structlog.get_logger(__name__)


@dataclass
class SuppressionRule:
    """一条抑制规则。

    所有条件字段都是**可选**的：为 None 表示"不限制该字段"。
    只有显式给出的条件才参与匹配（AND 逻辑）。

    ⚠️ 至少要有一个条件，否则规则不生效（见 matches_rule 的保护）。
    """

    id: int
    name: str
    # ── 匹配条件（全部可选）──
    src_ip: str | None = None
    signature_id: int | None = None
    category: str | None = None
    # ── 元信息 ──
    reason: str | None = None
    expires_at: datetime | None = None
    enabled: bool = True
    created_by: str | None = None

    @property
    def has_conditions(self) -> bool:
        """是否写了至少一个匹配条件。"""
        return any(v is not None for v in (self.src_ip, self.signature_id, self.category))


def matches_rule(rule: SuppressionRule, alert: dict[str, Any]) -> bool:
    """判断一条告警是否命中该规则。

    判定顺序（先做便宜的检查，尽早短路）：
        1. 规则启用且未过期
        2. 规则至少有一个条件
        3. 所有非空条件都匹配（AND）
    """
    if not rule.enabled:
        return False

    # 过期检查：用 UTC 比较，避免本地时区带来的偏差
    if rule.expires_at is not None:
        now = datetime.now(UTC)
        expires = rule.expires_at
        # 数据库读出的时间可能缺时区信息（取决于驱动），补上 UTC 再比较
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if now > expires:
            return False

    # 空规则保护：没有条件的规则如果匹配，会抑制所有告警
    if not rule.has_conditions:
        return False

    # ── AND 逻辑：每个非空条件都必须满足 ──
    if rule.src_ip is not None and alert.get("src_ip") != rule.src_ip:
        return False

    if rule.signature_id is not None:
        # 类型可能不一致（DB 给 int、告警里也可能给 str），统一转 int 比较
        try:
            if int(alert.get("signature_id") or 0) != int(rule.signature_id):
                return False
        except (TypeError, ValueError):
            return False

    if rule.category is not None:
        # 分类比较不区分大小写：Suricata 输出的大小写不完全一致
        alert_category = str(alert.get("category") or "").strip().lower()
        if alert_category != rule.category.strip().lower():
            return False

    return True


class SuppressionService:
    """抑制规则服务。

    内存持有规则列表 —— 抑制检查在**每条告警**上都会执行，
    每次都查数据库会成为瓶颈。规则变更时通过 reload() 刷新。

    为什么不用 TTL 缓存自动刷新：
        规则变更是低频事件（人工配置），显式 reload 更可预测 ——
        自动过期意味着"改完规则要等最多 N 秒才生效"，反而令人困惑。
        多实例部署时可改为订阅 Redis 的规则变更频道（本期单实例，不做）。
    """

    def __init__(self, rules: list[SuppressionRule] | None = None):
        self._rules: list[SuppressionRule] = rules or []

    def reload(self, rules: list[SuppressionRule]) -> None:
        """替换规则列表（新增/删除/修改后调用）。"""
        self._rules = list(rules)
        log.info("suppression_rules_reloaded", count=len(self._rules))

    @property
    def active_count(self) -> int:
        """启用的规则数（供健康检查与仪表盘展示）。"""
        return sum(1 for r in self._rules if r.enabled)

    def match(self, alert: dict[str, Any]) -> SuppressionRule | None:
        """返回命中的第一条规则，未命中返回 None。

        返回规则而非布尔值：便于解释"这条告警为什么被抑制了"——
        排查误抑制时需要知道是哪条规则干的。
        """
        for rule in self._rules:
            if matches_rule(rule, alert):
                return rule
        return None

    def is_suppressed(self, alert: dict[str, Any]) -> bool:
        """是否应被抑制（热路径调用的便捷方法）。"""
        return self.match(alert) is not None
