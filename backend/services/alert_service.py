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

from backend.schemas.alert import AlertCreate, Severity

# 引擎可能传来各种意料之外的严重度字符串（如 Suricata priority 映射偏差、
# ML 标签命名不一致）。收敛到平台允许的 5 个级别，未知值降级为 info。
_VALID_SEVERITIES: set[str] = {"critical", "high", "medium", "low", "info"}
_DEFAULT_SEVERITY: Severity = "info"


def _normalize_severity(value: Any) -> Severity:
    """把任意严重度输入收敛为合法的 Severity。

    单独抽成函数是为了让**类型窄化**明确可见：
    `str` 经此函数后返回 `Severity`（Literal），mypy 才能接受它传给
    AlertCreate。若内联写在字典/dict 里，类型会退化成 `Any | str`，
    mypy 会报 arg-type 错误（这是真实遇到过的）。
    """
    if isinstance(value, str) and value.lower().strip() in _VALID_SEVERITIES:
        # cast 的必要性：mypy 无法从集合成员判断推出 Literal 类型，
        # 但此处逻辑上已保证值属于该集合。
        return value.lower().strip()  # type: ignore[return-value]
    return _DEFAULT_SEVERITY


def normalize_alert(raw: dict[str, Any]) -> AlertCreate:
    """把任意引擎的输出归一化为 AlertCreate。

    两阶段设计（顺序不可颠倒）：
        引擎原始输出（脏：缺字段、值异常、命名不一）
            ↓ 第一阶段的**宽容**处理：降级、兜底、类型转换
        中间态（已尽量补全）
            ↓ AlertCreate 构造的**严格**校验（最后一道闸门）
        合法数据 → 落库

    为什么不直接返回手写 dict：AlertCreate 的字段与归一化产出**完全一一对应**，
    手写 dict 等于把字段清单抄第二遍（改名时必漏），且类型退化为
    dict[str, Any] —— mypy 对拼错的字段名毫无察觉。
    返回 AlertCreate 让字段单一来源、类型可检查、合法性当场校验。
    """
    # ── 第一阶段：宽容兜底（必须在构造之前完成）──────────────────
    # 严重度归一到合法集合；未知值降级为 info 而不是崩溃
    severity = _normalize_severity(raw.get("severity"))

    # 源 IP 缺失时用 0.0.0.0 占位而不是 None：
    # 数据库该列是 NOT NULL，且去重键需要它参与拼接。
    src_ip = raw.get("src_ip") or "0.0.0.0"
    signature = raw.get("signature") or "Unknown"

    # ── 第二阶段：严格构造 ────────────────────────────────────
    return AlertCreate(
        source_engine=raw["source_engine"],
        # 事件原始时间优先。缺失才用当前时间兜底 ——
        # 注意必须是"兜底"而非默认行为，否则重放时所有告警都变成"现在"。
        detected_at=raw.get("detected_at") or datetime.now(UTC),
        src_ip=src_ip,
        src_port=raw.get("src_port"),
        dst_ip=raw.get("dst_ip") or "0.0.0.0",
        dst_port=raw.get("dst_port"),
        protocol=raw.get("protocol"),
        signature=signature,
        attack_type=raw.get("attack_type"),
        severity=severity,
        # 转 float 并兜底：引擎可能给 None 或字符串
        confidence=float(raw.get("confidence") or 0.0),
        category=raw.get("category"),
        # 保留完整原始记录，便于事后追溯研判依据
        raw=raw.get("raw") or raw,
        # 去重键：(源IP, 签名)。同源同规则的重复触发视为"同一件事"；
        # 不同源或不同规则则是不同事件，不合并。
        dedup_key=f"{src_ip}-{signature}",
    )


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


def eve_to_raw(event: Any) -> dict[str, Any]:
    """把 EveAlert 适配成 normalize_alert 接受的入参 dict。

    为什么需要这层适配（而不是让 normalize_alert 直接吃 EveAlert）：
        若本模块 import 了 EveAlert，服务层就绑定了"检测引擎是 Suricata"。
        将来接入别的引擎（或 Suricata 的多种事件）都要改服务层。
        现在服务层只认 dict —— **谁知道怎么转是调用方的事**，
        依赖方向保持"上层知道下层、下层不知道上层"。

    参数用 Any 而非 EveAlert 类型：
        本模块刻意不 import 解析层的类型，保持解耦。
        代价是丢失了类型检查；换来的是服务层不依赖具体引擎。
        （若将来需要类型安全，可定义一个 Protocol 而非直接依赖 EveAlert。）
    """
    return {
        "source_engine": "suricata",
        # 事件原始时间原样传递 —— 重放的时间线完全依赖它
        "detected_at": event.detected_at,
        "src_ip": event.src_ip,
        "src_port": event.src_port,
        "dst_ip": event.dst_ip,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
        "signature": event.signature,
        "severity": event.severity,
        "category": event.category,
        # 原始事件带上，供研判层作为证据、供事后追溯
        "raw": event.raw,
        # 刻意不含 dedup_key：由 normalize_alert 统一生成，
        # 两处都算会导致去重规则有两个来源、易不一致。
    }
