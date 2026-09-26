"""EveFeeder 的测试。

EveFeeder 是"准实时演示"的核心：读 eve.json，按事件原始时间戳的节奏
逐条产出告警，从而复现实时 IDS 的观感。

测试不需要 pcap，也不需要真的等待真实时长 ——
通过极大的 speed（倍速）让延迟趋近于 0。
"""

import json

from backend.detection.feeders.eve_feeder import EveFeeder


def _write_eve(tmp_path, events: list[dict], name: str = "eve.json"):
    """把事件列表写成 eve.json（NDJSON）。"""
    p = tmp_path / name
    p.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return p


def _alert(ts: str, signature: str, **overrides) -> dict:
    evt = {
        "timestamp": ts,
        "event_type": "alert",
        "src_ip": "45.33.32.156",
        "dest_ip": "10.0.0.5",
        "proto": "TCP",
        "alert": {"signature": signature, "signature_id": 1, "category": "Test", "severity": 2},
    }
    evt.update(overrides)
    return evt


# 用极高倍速让真实延迟趋近 0，测试才能在毫秒级完成
FAST = 1_000_000.0


# ── 基本行为 ───────────────────────────────────────────────────


async def test_streams_alerts_in_file_order_when_already_sorted(tmp_path):
    p = _write_eve(
        tmp_path,
        [
            _alert("2017-07-05T10:00:00+0000", "first"),
            _alert("2017-07-05T10:00:01+0000", "second"),
            _alert("2017-07-05T10:00:02+0000", "third"),
        ],
    )
    feeder = EveFeeder(p, speed=FAST, max_delay=0.001)

    signatures = [e.signature async for e in feeder.stream()]
    assert signatures == ["first", "second", "third"]


async def test_sorts_by_timestamp_not_file_order(tmp_path):
    """必须按**事件时间**排序，而不是文件里的物理顺序。

    为什么需要排序：eve.json 是 Suricata 追加写的，单文件通常有序；
    但多个文件拼接、或人工处理过之后，乱序是可能的。
    按时间排序保证重放的时间线正确 —— 否则演示时告警会"时光倒流"。
    """
    p = _write_eve(
        tmp_path,
        [
            _alert("2017-07-05T10:00:02+0000", "third"),
            _alert("2017-07-05T10:00:00+0000", "first"),
            _alert("2017-07-05T10:00:01+0000", "second"),
        ],
    )
    feeder = EveFeeder(p, speed=FAST, max_delay=0.001)

    signatures = [e.signature async for e in feeder.stream()]
    assert signatures == ["first", "second", "third"]


async def test_skips_non_alert_events(tmp_path):
    """flow / dns 等事件不产出告警。"""
    p = _write_eve(
        tmp_path,
        [
            {"timestamp": "2017-07-05T10:00:00+0000", "event_type": "flow", "flow_id": 1},
            _alert("2017-07-05T10:00:01+0000", "real-alert"),
            {"timestamp": "2017-07-05T10:00:02+0000", "event_type": "dns", "flow_id": 2},
        ],
    )
    feeder = EveFeeder(p, speed=FAST, max_delay=0.001)

    signatures = [e.signature async for e in feeder.stream()]
    assert signatures == ["real-alert"]


async def test_skips_malformed_lines_without_crashing(tmp_path):
    """混入坏行不能让整批重放失败。"""
    p = tmp_path / "eve.json"
    p.write_text(
        _json_line_alert("2017-07-05T10:00:00+0000", "first")
        + "\nnot valid json\n"
        + "\n"  # 空行
        + _json_line_alert("2017-07-05T10:00:01+0000", "second")
        + "\n",
        encoding="utf-8",
    )
    feeder = EveFeeder(p, speed=FAST, max_delay=0.001)

    signatures = [e.signature async for e in feeder.stream()]
    assert signatures == ["first", "second"]


async def test_empty_file_yields_nothing(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text("", encoding="utf-8")
    feeder = EveFeeder(p, speed=FAST, max_delay=0.001)

    assert [e async for e in feeder.stream()] == []


async def test_file_with_no_alerts_yields_nothing(tmp_path):
    p = _write_eve(
        tmp_path,
        [
            {"timestamp": "2017-07-05T10:00:00+0000", "event_type": "stats"},
        ],
    )
    feeder = EveFeeder(p, speed=FAST, max_delay=0.001)

    assert [e async for e in feeder.stream()] == []


# ── 节奏控制 ───────────────────────────────────────────────────


async def test_max_delay_caps_single_step_wait(tmp_path):
    """单步等待有上限 —— 防止真实间隔过大把演示卡死。

    真实数据里两次攻击可能相隔数小时。若严格按原速等待，
    演示将无法进行。max_delay 给单步等待封顶。
    """
    p = _write_eve(
        tmp_path,
        [
            _alert("2017-07-05T10:00:00+0000", "a"),
            _alert("2017-07-05T18:00:00+0000", "b"),  # 相隔 8 小时
        ],
    )
    # speed=1（原速）+ max_delay=0.05 → 第二步最多等 50ms
    feeder = EveFeeder(p, speed=1.0, max_delay=0.05)

    import time

    start = time.monotonic()
    signatures = [e.signature async for e in feeder.stream()]
    elapsed = time.monotonic() - start

    assert signatures == ["a", "b"]
    # 若未封顶，这里会等待 8 小时；封顶后应远小于 1 秒
    assert elapsed < 1.0


async def test_speed_multiplier_reduces_wait(tmp_path):
    """倍速越大，总耗时越短 —— 演示用高倍速。

    注意：因为 max_delay 封顶，这里只验证"高倍速不会更慢"这一定性性质，
    不硬编码具体秒数（那会随机器性能漂移、让测试脆弱）。
    """
    p = _write_eve(
        tmp_path,
        [
            _alert("2017-07-05T10:00:00+0000", "a"),
            _alert("2017-07-05T10:00:01+0000", "b"),  # 相隔 1 秒
        ],
    )

    import time

    t0 = time.monotonic()
    _ = [e async for e in EveFeeder(p, speed=1000.0, max_delay=10.0).stream()]
    fast = time.monotonic() - t0

    # 1000 倍速下，1 秒间隔 → 1 毫秒，应远低于 1 秒
    assert fast < 0.5


def _json_line_alert(ts: str, signature: str) -> str:
    return json.dumps(_alert(ts, signature))
