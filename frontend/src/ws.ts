// WebSocket 客户端：带指数退避重连。
//
// 为什么要重连：后端重启、网络抖动、笔记本休眠都会断开连接。
// 没有重连的话，用户必须手动刷新页面才能恢复实时推送 ——
// 演示时这是致命的。
//
// 指数退避（1s → 2s → 4s ... → 上限 32s）而非固定间隔：
// 固定 1 秒重连会在服务端长期不可用时造成大量无效请求；
// 退避让重试逐渐稀疏，同时保留"服务恢复后能较快重连"的能力。

export type MessageHandler = (msg: unknown) => void;

export interface WsOptions {
  url?: string;
  maxDelayMs?: number;
  onOpen?: () => void;
  onClose?: () => void;
}

const INITIAL_DELAY = 1000;
const MAX_DELAY = 32000;

/** 计算下一次重连延迟（导出以便单测，避免为了测试去 mock WebSocket）。 */
export function nextBackoff(current: number, maxDelay = MAX_DELAY): number {
  return Math.min(current * 2, maxDelay);
}

export function connectWs(handler: MessageHandler, options: WsOptions = {}) {
  // 用相对地址 + 协议推断：开发时 vite proxy 转发，生产同源部署。
  // 硬编码 ws://localhost:8000 在演示机/容器里会失效。
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const url =
    options.url ?? import.meta.env.VITE_WS_URL ?? `${proto}//${window.location.host}/ws/events`;

  const maxDelay = options.maxDelayMs ?? MAX_DELAY;
  let ws: WebSocket | null = null;
  let delay = INITIAL_DELAY;
  let closed = false; // 主动关闭后不再重连
  let timer: ReturnType<typeof setTimeout> | null = null;

  const open = () => {
    if (closed) return;
    ws = new WebSocket(url);

    ws.onopen = () => {
      delay = INITIAL_DELAY; // 连上后重置退避
      options.onOpen?.();
    };

    ws.onmessage = (event) => {
      try {
        handler(JSON.parse(event.data));
      } catch {
        // 单条消息格式错误不该中断整个连接
        console.warn("ws: 无法解析的消息", event.data);
      }
    };

    ws.onclose = () => {
      options.onClose?.();
      if (closed) return;
      // 安排重连而非立即重试：立即重试在服务端持续不可用时会刷爆请求
      timer = setTimeout(open, delay);
      delay = nextBackoff(delay, maxDelay);
    };

    ws.onerror = () => {
      // onerror 之后通常紧跟 onclose，重连逻辑统一放在 onclose，
      // 这里只避免未捕获的错误冒泡到控制台。
      ws?.close();
    };
  };

  open();

  // 返回清理函数：组件卸载时调用，避免泄漏连接与定时器
  return () => {
    closed = true;
    if (timer) clearTimeout(timer);
    ws?.close();
  };
}
