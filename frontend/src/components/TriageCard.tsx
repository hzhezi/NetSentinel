// AI 研判卡片：展示 LLM 对一条告警的结论。
//
// 这是本项目的**核心展示物** —— 传统 IDS 只有一行告警文本，
// 这里展示的是"结论 + 理由 + 建议 + 依据"，即 LLM 研判层的增值。

import { Alert as AntAlert, Card, Empty, Space, Tag, Typography } from "antd";
import { ConfidenceBar, VerdictTag } from "./Tags";
import type { TriageRecord } from "../types";

const { Paragraph, Text } = Typography;

export function TriageCard({ result }: { result: TriageRecord }) {
  return (
    <Card
      size="small"
      title={
        <Space wrap>
          <VerdictTag verdict={result.verdict} />
          <Text type="secondary" style={{ fontSize: 12 }}>
            置信度
          </Text>
          <ConfidenceBar value={result.confidence} />
          {result.escalate && <Tag color="purple">已升级深度调查</Tag>}
        </Space>
      }
      style={{ marginBottom: 12 }}
    >
      {/* 研判失败时明确标出 —— 不伪装成正常结论 */}
      {result.error && (
        <AntAlert
          type="warning"
          showIcon
          message="自动研判未完成"
          description={result.error}
          style={{ marginBottom: 12 }}
        />
      )}

      <Paragraph style={{ marginBottom: 8 }}>{result.summary}</Paragraph>

      {result.attack_type && (
        <div style={{ marginBottom: 8 }}>
          <Text type="secondary">攻击类型：</Text>
          <Tag>{result.attack_type}</Tag>
        </div>
      )}

      {result.mitre_techniques.length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <Text type="secondary">MITRE ATT&CK：</Text>
          {result.mitre_techniques.map((t) => (
            <Tag key={t} color="geekblue">
              {t}
            </Tag>
          ))}
        </div>
      )}

      {result.recommended_actions.length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <Text type="secondary">处置建议：</Text>
          <ul style={{ margin: "4px 0 0 0", paddingLeft: 20 }}>
            {result.recommended_actions.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </div>
      )}

      <Text type="secondary" style={{ fontSize: 12 }}>
        {result.model ?? "unknown"} · {result.latency_ms}ms ·{" "}
        {result.prompt_tokens + result.completion_tokens} tokens
      </Text>
    </Card>
  );
}

export function TriageEmpty() {
  return (
    <Empty
      image={Empty.PRESENTED_IMAGE_SIMPLE}
      description="尚无研判结果（可能仍在处理中，或未配置 LLM API Key）"
    />
  );
}
