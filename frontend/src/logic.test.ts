// 前端单元测试。
//
// 只测**纯逻辑**（store 去重、退避计算、色板映射），
// 不做组件快照或端到端 —— 前者维护成本高、价值低，
// 后者用 Playwright 更合适（本期未做）。

import { beforeEach, describe, expect, test } from "vitest";
import { useAlertStream, ALERT_BUFFER_LIMIT } from "./store";
import { nextBackoff } from "./ws";
import type { Alert } from "./types";

const makeAlert = (id: string): Alert => ({
  id,
  source_engine: "suricata",
  detected_at: "2017-07-05T10:00:00Z",
  src_ip: "1.1.1.1",
  src_port: null,
  dst_ip: "2.2.2.2",
  dst_port: null,
  protocol: "TCP",
  signature: "test",
  attack_type: null,
  severity: "high",
  confidence: 0.9,
  category: null,
  status: "new",
  notes: "",
  created_at: "2017-07-05T10:00:00Z",
});

describe("告警实时缓冲", () => {
  beforeEach(() => {
    useAlertStream.setState({ alerts: [] });
  });

  test("新告警插入到最前面", () => {
    const { prependNewest } = useAlertStream.getState();
    prependNewest(makeAlert("1"));
    prependNewest(makeAlert("2"));

    const ids = useAlertStream.getState().alerts.map((a) => a.id);
    expect(ids).toEqual(["2", "1"]);
  });

  test("按 id 去重（同一告警既可能来自推送也可能来自历史查询）", () => {
    const { prependNewest } = useAlertStream.getState();
    prependNewest(makeAlert("1"));
    prependNewest(makeAlert("1"));

    expect(useAlertStream.getState().alerts).toHaveLength(1);
  });

  test("缓冲有上限，防止长时间运行吃满内存", () => {
    const { prependNewest } = useAlertStream.getState();
    for (let i = 0; i < ALERT_BUFFER_LIMIT + 50; i++) {
      prependNewest(makeAlert(String(i)));
    }
    expect(useAlertStream.getState().alerts).toHaveLength(ALERT_BUFFER_LIMIT);
  });

  test("clear 清空缓冲", () => {
    const { prependNewest, clear } = useAlertStream.getState();
    prependNewest(makeAlert("1"));
    clear();
    expect(useAlertStream.getState().alerts).toHaveLength(0);
  });
});

describe("WebSocket 退避", () => {
  test("每次翻倍", () => {
    expect(nextBackoff(1000)).toBe(2000);
    expect(nextBackoff(2000)).toBe(4000);
  });

  test("有上限，不会无限增长", () => {
    expect(nextBackoff(32000, 32000)).toBe(32000);
    expect(nextBackoff(20000, 32000)).toBe(32000);
  });
});
