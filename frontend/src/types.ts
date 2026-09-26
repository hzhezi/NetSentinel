// 与后端 API 对应的类型定义。
// 手写而非自动生成（OpenAPI codegen）：接口数量少，手写可读性更好，
// 且字段说明能直接写在这里。接口若变动，这里会先报类型错误。

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verdict = "true_positive" | "false_positive" | "needs_human_review";
export type AlertStatus = "new" | "triaged" | "escalated" | "closed" | "suppressed";

export interface Alert {
  id: string;
  source_engine: string;
  detected_at: string;
  src_ip: string;
  src_port: number | null;
  dst_ip: string;
  dst_port: number | null;
  protocol: string | null;
  signature: string;
  attack_type: string | null;
  severity: Severity;
  confidence: number;
  category: string | null;
  status: AlertStatus;
  notes: string;
  created_at: string;
}

export interface AlertPage {
  items: Alert[];
  total: number;
  page: number;
  size: number;
}

export interface TriageRecord {
  id: string;
  alert_id: string;
  stage: string;
  verdict: Verdict;
  severity: Severity;
  confidence: number;
  escalate: boolean;
  attack_type: string | null;
  summary: string;
  mitre_techniques: string[];
  recommended_actions: string[];
  model: string | null;
  prompt_tokens: number;
  completion_tokens: number;
  latency_ms: number;
  error: string | null;
  evidence_trail: unknown[] | null;
  created_at: string;
}

export interface Overview {
  alerts: {
    total: number;
    by_severity: Record<string, number>;
  };
  triage: {
    by_verdict: Record<string, number>;
    usage: {
      prompt_tokens: number;
      completion_tokens: number;
      total_tokens: number;
      total_latency_ms: number;
      count: number;
    };
  };
}

// WebSocket 推送的消息。后端用 {type, data} 包装，
// 前端据此分发到不同 handler。
export type WsMessage =
  | { type: "new_alert"; data: Alert }
  | { type: string; data: unknown };
