// 评测结果页：展示 L1 vs L2 的实测对比。
//
// 这是答辩时的核心论据页面 —— 用真实数据回答
// "加了 LLM 研判到底有没有用"这个问题。

import { Alert, Card, Col, Empty, Row, Space, Statistic, Table, Tag, Typography } from "antd";
import { useQuery } from "@tanstack/react-query";
import ReactECharts from "echarts-for-react";

import { fetchEvalReport, type EvalDetailItem, type EvalMetrics } from "../api";

const { Text, Title, Paragraph } = Typography;

const VERDICT_LABEL: Record<string, string> = {
  true_positive: "真实攻击",
  false_positive: "误报",
  needs_human_review: "待人工复核",
};

function verdictColor(v: string) {
  if (v === "true_positive") return "red";
  if (v === "false_positive") return "green";
  return "gold";
}

/** 指标卡片组 */
function MetricsCards({ metrics }: { metrics: EvalMetrics }) {
  return (
    <Row gutter={[12, 12]}>
      <Col span={6}>
        <Statistic
          title="结论一致率"
          value={metrics.agreement * 100}
          precision={1}
          suffix="%"
          valueStyle={{
            color: metrics.agreement >= 0.8 ? "#52c41a" : metrics.agreement >= 0.5 ? "#faad14" : "#ff4d4f",
          }}
        />
      </Col>
      <Col span={6}>
        <Statistic
          title="待人工复核比例"
          value={metrics.needs_human_review_rate * 100}
          precision={1}
          suffix="%"
        />
      </Col>
      <Col span={6}>
        <Statistic title="平均耗时" value={metrics.avg_latency_ms} suffix="ms" />
      </Col>
      <Col span={6}>
        <Statistic title="总 token" value={metrics.total_tokens} />
      </Col>
    </Row>
  );
}

/** 逐条明细表：真值 vs 模型结论 */
function DetailTable({ detail }: { detail: EvalDetailItem[] }) {
  return (
    <Table
      rowKey={(r) => `${r.scenario}-${r.signature}`}
      size="small"
      pagination={false}
      dataSource={detail}
      columns={[
        {
          title: "告警签名",
          dataIndex: "signature",
          render: (v: string) => <Text style={{ fontSize: 12 }}>{v}</Text>,
        },
        {
          title: "标准答案",
          dataIndex: "ground_truth",
          width: 110,
          render: (v: string) => <Tag color={verdictColor(v)}>{VERDICT_LABEL[v] ?? v}</Tag>,
        },
        {
          title: "模型结论",
          dataIndex: "predicted",
          width: 110,
          render: (v: string, r) => (
            <Tag color={v === r.ground_truth ? "success" : verdictColor(v)}>
              {VERDICT_LABEL[v] ?? v}
            </Tag>
          ),
        },
        {
          title: "置信度",
          dataIndex: "confidence",
          width: 80,
          render: (v?: number) => (v != null ? v : "-"),
        },
        {
          title: "调用工具",
          dataIndex: "tools_used",
          render: (v?: string[]) =>
            v?.length ? (
              <Space size={2} wrap>
                {v.map((t) => (
                  <Tag key={t} style={{ fontSize: 11 }}>
                    {t.replace("lookup_", "").replace("get_", "")}
                  </Tag>
                ))}
              </Space>
            ) : (
              <Text type="secondary">-</Text>
            ),
        },
      ]}
    />
  );
}

/** 混淆矩阵图（只画有数据的部分） */
function ConfusionChart({ metrics }: { metrics: EvalMetrics }) {
  const keys = ["true_positive", "false_positive"];
  const data: Array<[number, number, number]> = [];

  keys.forEach((gt, i) => {
    keys.forEach((pred, j) => {
      const count = metrics.confusion?.[gt]?.[pred] ?? 0;
      if (count > 0) data.push([j, i, count]);
    });
  });

  if (data.length === 0) {
    return <Empty description="无明确判断样本" image={Empty.PRESENTED_IMAGE_SIMPLE} />;
  }

  return (
    <ReactECharts
      style={{ height: 220 }}
      option={{
        tooltip: {
          formatter: (p: { data: [number, number, number] }) =>
            `标准=${VERDICT_LABEL[keys[p.data[1]]]}<br/>模型=${VERDICT_LABEL[keys[p.data[0]]]}<br/>数量=${p.data[2]}`,
        },
        grid: { left: 90, right: 20, top: 20, bottom: 40 },
        xAxis: {
          type: "category",
          data: keys.map((k) => `模型:${VERDICT_LABEL[k]}`),
          splitArea: { show: true },
        },
        yAxis: {
          type: "category",
          data: keys.map((k) => `标准:${VERDICT_LABEL[k]}`),
          splitArea: { show: true },
        },
        visualMap: {
          min: 0,
          max: Math.max(...data.map((d) => d[2])),
          calculable: true,
          orient: "horizontal",
          left: "center",
          bottom: 0,
          inRange: { color: ["#f0f0f0", "#52c41a"] },
        },
        series: [
          {
            type: "heatmap",
            data,
            label: { show: true },
            emphasis: { itemStyle: { shadowBlur: 10 } },
          },
        ],
      }}
    />
  );
}

export default function EvaluationPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["evalReport"],
    queryFn: fetchEvalReport,
  });

  if (isLoading) return <Card loading />;

  if (!data?.available) {
    return (
      <Card title="LLM 研判评测">
        <Alert
          type="info"
          showIcon
          message="尚未运行评测"
          description={
            <div>
              <Paragraph style={{ marginBottom: 8 }}>
                评测需要调用真实 LLM（有费用与耗时），因此设计为**离线运行**，
                结果由本页面读取展示。
              </Paragraph>
              <pre
                style={{
                  background: "#f5f5f5",
                  padding: 12,
                  borderRadius: 4,
                  fontSize: 12,
                  margin: 0,
                }}
              >
                {data?.message ?? "uv run python scripts/run_eval.py --with-l2"}
              </pre>
            </div>
          }
        />
      </Card>
    );
  }

  const l1 = data.results?.l1;
  const l2 = data.results?.l2;

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Card>
        <Space direction="vertical" size={4}>
          <Title level={4} style={{ margin: 0 }}>
            LLM 研判评测结果
          </Title>
          <Text type="secondary">
            样本量 {data.sample_size} 条 · 运行于{" "}
            {data.run_at ? new Date(data.run_at).toLocaleString("zh-CN") : "-"}
            {data.models?.triage && ` · L1 模型 ${data.models.triage}`}
            {data.models?.investigation && ` · L2 模型 ${data.models.investigation}`}
          </Text>
        </Space>
      </Card>

      {/* L1 */}
      <Card
        title={
          <Space>
            <span>L1 快速分诊</span>
            <Tag>单轮 · 仅告警本身</Tag>
          </Space>
        }
      >
        {l1 ? (
          <>
            <MetricsCards metrics={l1.metrics} />
            <div style={{ marginTop: 16 }}>
              <DetailTable detail={l1.detail} />
            </div>
          </>
        ) : (
          <Empty description="未运行 L1 评测" image={Empty.PRESENTED_IMAGE_SIMPLE} />
        )}
      </Card>

      {/* L2 */}
      <Card
        title={
          <Space>
            <span>L2 深度调查</span>
            <Tag color="blue">多轮 · 工具驱动</Tag>
          </Space>
        }
      >
        {l2 ? (
          <>
            <MetricsCards metrics={l2.metrics} />
            <Row gutter={16} style={{ marginTop: 16 }}>
              <Col span={12}>
                <Card size="small" title="混淆矩阵">
                  <ConfusionChart metrics={l2.metrics} />
                </Card>
              </Col>
              <Col span={12}>
                <Card size="small" title="逐条明细">
                  <DetailTable detail={l2.detail} />
                </Card>
              </Col>
            </Row>
          </>
        ) : (
          <Empty description="未运行 L2 评测" image={Empty.PRESENTED_IMAGE_SIMPLE} />
        )}
      </Card>

      {/* 局限性说明 —— 评估诚实性要求 */}
      <Alert
        type="warning"
        showIcon
        message="评测局限说明"
        description={
          <ul style={{ margin: 0, paddingLeft: 20 }}>
            <li>
              样本量仅 <strong>{data.sample_size}</strong> 条，统计置信度有限，
              不能据此推断大规模场景下的表现。
            </li>
            <li>
              标准答案来自流量构造过程（攻击包 vs 正常包），
              在真实网络中"攻击"与"正常"的边界更模糊。
            </li>
            <li>
              结论一致率仅在"模型给出明确判断"的样本上计算；
              <code>待人工复核</code> 单独统计 —— 它是审慎而非错误。
            </li>
          </ul>
        }
      />
    </Space>
  );
}
