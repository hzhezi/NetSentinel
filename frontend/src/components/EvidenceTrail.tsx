// 证据链时间线：展示 AI 是如何得出结论的。
//
// 这是本项目的**核心差异化展示** ——
// 传统 IDS 只有一行告警文本；这里能看到 AI 的完整调查过程：
//   推理 → 调工具 → 拿到什么 → 再推理 → 结论
//
// 为什么它重要：
//   "黑盒 AI 说这是误报，请相信我" 在安全运营中毫无价值。
//   分析师需要能审计："它查了什么、查到什么、为什么这么判断"。
//   这个组件就是把"可审计"变成看得见的东西。

import { Card, Empty, Tag, Timeline, Typography } from "antd";
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  ExperimentOutlined,
  ToolOutlined,
} from "@ant-design/icons";

const { Text, Paragraph } = Typography;

// 工具名 → 中文说明。让非技术背景的人也能看懂这次调查做了什么
const TOOL_LABEL: Record<string, string> = {
  lookup_ip_reputation: "查询 IP 威胁情报",
  lookup_mitre_technique: "查询 MITRE ATT&CK 技术编号",
  get_related_alerts: "查找关联告警",
  get_asset_context: "查询资产重要性",
  get_alert_detail: "获取告警原始记录",
};

interface TrailStep {
  type: string;
  tool?: string;
  call_id?: string;
  input?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: string;
  text?: string;
  input_: Record<string, unknown>;
  input_verdict?: unknown;
}

/** 把工具返回结果压成一行可读摘要。 */
function summarizeResult(tool: string | undefined, result: unknown): string {
  if (!result || typeof result !== "object") return String(result ?? "");
  const r = result as Record<string, unknown>;

  if (r.error) return `执行失败：${r.error}`;
  if (r.note) return String(r.note);

  switch (tool) {
    case "lookup_ip_reputation":
      if (r.reputation === "unknown") return "情报库无记录（未知，不等于安全）";
      return `信誉=${r.reputation} 滥用分=${r.abuse_score} ${r.country ?? ""} ${r.isp ?? ""}`;
    case "lookup_mitre_technique": {
      const matches = r.matches as Array<{ technique_id: string; technique_name: string }> | undefined;
      if (!matches?.length) return "未匹配到编号（模型被要求留空而非编造）";
      return matches.map((m) => `${m.technique_id} ${m.technique_name}`).join("；");
    }
    case "get_related_alerts":
      return r.count
        ? `找到 ${r.count} 条关联告警`
        : "未找到关联告警";
    case "get_asset_context":
      return r.criticality
        ? `资产类型=${r.type} 重要性=${r.criticality}`
        : "资产库无记录";
    case "get_alert_detail":
      return r.signature ? `签名=${r.signature}` : "已获取";
    default:
      return JSON.stringify(r).slice(0, 120);
  }
}

export function EvidenceTrail({ trail }: { trail: unknown[] | null }) {
  if (!trail || trail.length === 0) {
    return (
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        description="本次研判未使用工具（快速分诊，无深度调查）"
      />
    );
  }

  const steps = trail as TrailStep[];

  return (
    <Timeline
      style={{ marginTop: 16 }}
      items={steps
        .map((step, idx) => {
        // ── 工具调用 ──
        if (step.type === "tool_call") {
          const failed = Boolean(step.error);
          return {
            key: idx,
            color: failed ? "red" : "blue",
            dot: failed ? <CloseCircleOutlined /> : <ToolOutlined />,
            children: (
              <div>
                <Text strong>
                  {TOOL_LABEL[step.tool ?? ""] ?? step.tool}
                </Text>
                <div style={{ marginTop: 4 }}>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    参数：{JSON.stringify(step.input ?? {})}
                  </Text>
                </div>
                <div style={{ marginTop: 4 }}>
                  {failed ? (
                    <Tag color="red">失败：{step.error}</Tag>
                  ) : (
                    <Tag color="green">
                      {summarizeResult(step.tool, step.result)}
                    </Tag>
                  )}
                </div>
              </div>
            ),
          };
        }

        // ── 模型推理（叙述性文字）──
        if (step.type === "reasoning") {
          return {
            key: idx,
            color: "gray",
            dot: <ExperimentOutlined />,
            children: (
              <Paragraph
                type="secondary"
                style={{ marginBottom: 0, fontStyle: "italic" }}
              >
                {step.text}
              </Paragraph>
            ),
          };
        }

        // ── 最终结论 ──
        if (step.type === "verdict") {
          const v = (step as unknown as { input?: { verdict?: string } }).input;
          return {
            key: idx,
            color: "green",
            dot: <CheckCircleOutlined />,
            children: (
              <Text strong>
                给出结论：{v?.verdict ?? "-"}
              </Text>
            ),
          };
        }

          return null;
        })
        // Timeline 不接受 null 项，过滤掉未知类型的步骤后再传入
        .filter((item): item is NonNullable<typeof item> => item !== null)}
    />
  );
}

export function EvidenceTrailCard({ trail }: { trail: unknown[] | null }) {
  return (
    <Card size="small" title="调查过程（证据链）" style={{ marginTop: 12 }}>
      <Text type="secondary" style={{ fontSize: 12 }}>
        AI 的每一步推理与工具调用都被记录，结论可逐行审计。
      </Text>
      <EvidenceTrail trail={trail} />
    </Card>
  );
}
