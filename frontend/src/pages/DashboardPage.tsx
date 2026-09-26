// 仪表盘：总览指标 + 分布图。
//
// 数据来自 /statistics/overview（后端用 GROUP BY 聚合），
// 前端只负责展示 —— 不把明细拉回来自己算。

import { Card, Col, Row, Statistic, Spin, Empty } from "antd";
import { useQuery } from "@tanstack/react-query";
import ReactECharts from "echarts-for-react";

import { fetchOverview } from "../api";

const SEVERITY_LABEL: Record<string, string> = {
  critical: "严重",
  high: "高",
  medium: "中",
  low: "低",
  info: "信息",
};

const VERDICT_LABEL: Record<string, string> = {
  true_positive: "真实攻击",
  false_positive: "误报",
  needs_human_review: "待人工复核",
};

export default function DashboardPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["overview"],
    queryFn: fetchOverview,
    refetchInterval: 10000,
  });

  if (isLoading) return <Spin />;
  if (!data) return <Empty description="暂无数据" />;

  const severityEntries = Object.entries(data.alerts.by_severity);
  const verdictEntries = Object.entries(data.triage.by_verdict);
  const usage = data.triage.usage;

  // 平均耗时（有研判时才计算，避免除零）
  const avgLatency = usage.count > 0 ? Math.round(usage.total_latency_ms / usage.count) : 0;

  const severityOption = {
    tooltip: { trigger: "item" },
    series: [
      {
        type: "pie",
        radius: ["45%", "70%"],
        data: severityEntries.map(([k, v]) => ({
          name: SEVERITY_LABEL[k] ?? k,
          value: v,
        })),
        label: { formatter: "{b}: {c}" },
      },
    ],
  };

  const verdictOption = {
    tooltip: { trigger: "item" },
    series: [
      {
        type: "pie",
        radius: ["45%", "70%"],
        data: verdictEntries.map(([k, v]) => ({
          name: VERDICT_LABEL[k] ?? k,
          value: v,
        })),
        label: { formatter: "{b}: {c}" },
      },
    ],
  };

  return (
    <Row gutter={[16, 16]}>
      <Col span={6}>
        <Card>
          <Statistic title="告警总数" value={data.alerts.total} />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic title="已研判" value={usage.count} />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic title="平均研判耗时" value={avgLatency} suffix="ms" />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic title="累计 Token" value={usage.total_tokens} />
        </Card>
      </Col>

      <Col span={12}>
        <Card title="告警严重度分布">
          {severityEntries.length === 0 ? (
            <Empty description="暂无告警" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : (
            <ReactECharts option={severityOption} style={{ height: 260 }} />
          )}
        </Card>
      </Col>
      <Col span={12}>
        <Card title="AI 研判结论分布">
          {verdictEntries.length === 0 ? (
            <Empty description="暂无研判结果" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : (
            <ReactECharts option={verdictOption} style={{ height: 260 }} />
          )}
        </Card>
      </Col>
    </Row>
  );
}
