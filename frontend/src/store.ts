// 告警实时流的本地状态（Zustand）。
//
// 为什么需要它（而不是只用 TanStack Query）：
//     WebSocket 推来的告警是"增量"的，而 TanStack Query 擅长的是
//     "请求-缓存"模式。用 Query 的 setQueryData 每次推一条也可行，
//     但会频繁触发重新渲染整个列表。
//     这里用一个轻量 store 持有实时缓冲，配合去重与上限控制。

import { create } from "zustand";
import type { Alert } from "./types";

// 缓冲上限。长时间运行（如演示跑几小时）时不设限会持续吃内存。
// 取 500：足够覆盖当前视图，超出的旧数据仍可通过分页接口获取。
const MAX_BUFFER = 500;

interface AlertStreamState {
  alerts: Alert[];
  /** 插入到最前面；按 id 去重；超出上限时丢弃最旧的。 */
  prependNewest: (alert: Alert) => void;
  /** 清空缓冲（切换数据集/手动刷新时用）。 */
  clear: () => void;
}

export const useAlertStream = create<AlertStreamState>((set) => ({
  alerts: [],

  prependNewest: (alert) =>
    set((state) => {
      // 去重：同一告警可能既来自 WS 推送、又来自历史查询
      if (state.alerts.some((a) => a.id === alert.id)) {
        return state;
      }
      return { alerts: [alert, ...state.alerts].slice(0, MAX_BUFFER) };
    }),

  clear: () => set({ alerts: [] }),
}));

export const ALERT_BUFFER_LIMIT = MAX_BUFFER;
