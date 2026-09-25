"""告警领域服务：归一化与去重。

放在 services 层而不是 repositories 层的原因：
    这里是**业务规则**（什么样的告警算重复、缺字段怎么兜底），
    不是数据存取。repository 只认"合法数据"，本模块负责把
    引擎的原始输出**变成**合法数据。

本模块当前不依赖数据库（纯函数 + 内存缓存），
所以测试无需 fixture，跑得很快。落库由调用方（worker）用 repository 完成。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cachetools import TTLCache

# 引擎可能传来各种意料之外的严重度字符串（如 Suricata priority 映射偏差、
# ML 标签命名不一致）。收敛到平台允许的 5 个级别，未知值降级为 info。
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_DEFAULT_SEVERITY = "info"


def normalize_alert(raw: dict[str, Any]) -> dict[str, Any]:
    """把任意引擎的输出归一化为 AlertCreate 所需的字段形状。

    设计取舍：**宽容而非严格**。
        引擎输出字段命名不完全可控，缺字段、多字段、值异常都可能发生。
        如果这里严格校验（缺字段就报错），一条异常告警会让整批重放中断 ——
        对安全系统而言，"漏报"比"标错级别"严重得多。
        所以这里尽量兜底，把严格的形状校验交给 Pydantic Schema
        （在写库前一刻发生）。

    返回 dict 而非 AlertCreate：
        让本函数保持无 Pydantic 依赖的纯数据变换，便于单测与复用。
    """
    # 严重度归一到合法集合；未知值降级为 info 而不是崩溃
    raw_severity = (raw.get("severity") or "").lower().strip()
    severity = raw_severity if raw_severity in _VALID_SEVERITIES else _DEFAULT_SEVERITY

    # 源 IP 缺失时用 0.0.0.0 占位而不是 None：
    # 数据库该列是 NOT NULL，且去重键需要它参与拼接。
    src_ip = raw.get("src_ip") or "0.0.0.0"
    signature = raw.get("signature") or "Unknown"

    return {
        "source_engine": raw["source_engine"],
        # 事件原始时间优先。缺失才用当前时间兜底 ——
        # 注意必须是"兜底"而非默认行为，否则重放时所有告警都变成"现在"。
        "detected_at": raw.get("detected_at") or datetime.now(UTC),
        "src_ip": src_ip,
        "src_port": raw.get("src_port"),
        "dst_ip": raw.get("dst_ip") or "0.0.0.0",
        "dst_port": raw.get("dst_port"),
        "protocol": raw.get("protocol"),
        "signature": signature,
        "attack_type": raw.get("attack_type"),
        "severity": severity,
        # 转 float 并兜底：引擎可能给 None 或字符串
        "confidence": float(raw.get("confidence") or 0.0),
        "category": raw.get("category"),
        # 保留完整原始记录，便于事后追溯研判依据
        "raw": raw.get("raw") or raw,
        # 去重键：(源IP, 签名)。同源同规则的重复触发视为"同一件事"；
        # 不同源或不同规则则是不同事件，不合并。
        "dedup_key": f"{src_ip}-{signature}",
    }


class AlertPipeline:
    """告警去重管道。

    解决的真实问题 —— 告警风暴：
        攻击者对一个端口扫描 5000 次，Suricata 会产出 5000 条完全相同的告警。
        不过滤的话：数据库塞 5000 行、Web 界面刷 5000 条、
        LLM 被调用 5000 次（费用爆炸）。

    实现选择 TTLCache 而非自己写 dict + 定时清理：
        TTLCache 同时提供**容量上限**与**过期淘汰**，且是线程安全的。
        自己写容易漏掉容量控制，导致攻击者用海量唯一 IP 把内存打满。

    注意这是**进程内**缓存：
        多实例部署时每个实例各有一份，去重不是全局的。
        对本项目（单实例部署）足够；若将来多实例，应换成 Redis。
        这个限制不影响期 1，但需要知道边界在哪。
    """

    def __init__(self, ttl_seconds: int | float = 60, maxsize: int = 10000):
        """
        Args:
            ttl_seconds: 同一告警在该窗口内重复出现视为重复。
                         窗口太短 → 聚合不足；太长 → 攻击者隔一阵再扫会被吞掉。
                         60 秒是常见选择，可通过 settings.DEDUP_TTL_SECONDS 配置。
            maxsize: 缓存容量上限，防止告警洪泛耗尽内存。
        """
        self._recent: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl_seconds)

    def is_duplicate(self, alert: dict[str, Any]) -> bool:
        """判断告警是否重复。**有副作用**：首次调用会记录该告警。

        返回值语义：
            True  → 是重复，调用方应丢弃
            False → 是新告警，调用方应继续处理

        为什么把"记录"和"判断"合成一个方法：
            分成 check() + mark() 两步的话，调用方可能忘记调 mark()，
            导致去重静默失效（不报错，只是完全不起作用）。
            合并成一个原子操作可以杜绝这类误用。
        """
        key = f"{alert.get('src_ip')}-{alert.get('signature')}"
        if key in self._recent:
            return True
        self._recent[key] = True
        return False
