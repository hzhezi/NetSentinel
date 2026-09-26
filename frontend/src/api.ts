// API 客户端。
// 用 Vite proxy 后，开发环境用相对路径即可（见 vite.config.ts）。

import axios from "axios";
import type { Alert, AlertPage, Overview, TriageRecord } from "./types";

const baseURL = import.meta.env.VITE_API_BASE ?? "/api/v1";

export const api = axios.create({
  baseURL,
  timeout: 15000,
});

export interface ListAlertsParams {
  page?: number;
  size?: number;
  severity?: string;
  status?: string;
  q?: string;
}

export interface AvailableFiles {
  files: string[];
}

export const fetchAlerts = async (params: ListAlertsParams = {}): Promise<AlertPage> => {
  const { data } = await api.get<AlertPage>("/alerts", { params });
  return data;
};

export const fetchAlert = async (id: string): Promise<Alert> => {
  const { data } = await api.get<Alert>(`/alerts/${id}`);
  return data;
};

export const fetchTriage = async (id: string): Promise<TriageRecord[]> => {
  const { data } = await api.get<TriageRecord[]>(`/alerts/${id}/triage`);
  return data;
};

export const fetchOverview = async (): Promise<Overview> => {
  const { data } = await api.get<Overview>("/statistics/overview");
  return data;
};

export const fetchAvailableFiles = async (): Promise<AvailableFiles> => {
  const { data } = await api.get<AvailableFiles>("/feeds/available");
  return data;
};

export const startReplay = async (body: {
  eve_path: string;
  speed: number;
}): Promise<{ status: string; message: string }> => {
  const { data } = await api.post("/feeds/replay", body);
  return data;
};

/** 手动触发深度调查（L2）。实测 6-9 秒返回，因此超时设长一些。 */
export const investigateAlert = async (id: string): Promise<TriageRecord> => {
  const { data } = await api.post<TriageRecord>(`/alerts/${id}/investigate`, null, {
    timeout: 120000,
  });
  return data;
};

// ── 抑制规则 ──────────────────────────────────────────────────

export interface SuppressionRule {
  id: string;
  name: string;
  src_ip: string | null;
  signature_id: number | null;
  category: string | null;
  reason: string | null;
  expires_at: string | null;
  enabled: boolean;
  created_at: string;
}

export interface SuppressionRuleInput {
  name: string;
  src_ip?: string | null;
  signature_id?: number | null;
  category?: string | null;
  reason?: string | null;
}

export const fetchSuppressions = async (): Promise<SuppressionRule[]> => {
  const { data } = await api.get<SuppressionRule[]>("/suppressions");
  return data;
};

export const createSuppression = async (
  body: SuppressionRuleInput,
): Promise<SuppressionRule> => {
  const { data } = await api.post<SuppressionRule>("/suppressions", body);
  return data;
};

export const deleteSuppression = async (id: string): Promise<void> => {
  await api.delete(`/suppressions/${id}`);
};
