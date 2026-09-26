// 评测结果页：展示 L1 vs L2 的实测对比。
//
// 这是答辩时的核心论据页面 —— 用真实数据回答
// "加了 LLM 研判到底有没有用"。

import { Alert, Card, Col, Empty, Row, Space, Table, Tag, Typography } from "antd";
import { useQuery } from "@tanstack/react-query";
import ReactECharts from "echarts-for-react";

import { fetchEvalReport, type EvalDetailItem, type EvalMetrics } from "../api";
import { CARD_STYLE, GRADIENTS, PAGE_GAP } from "../theme";

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

/** 一组指标卡片（渐变底，用于突出关键结论） */
function MetricCards({
  metrics,
  gradient,
  levelLabel,
}: {
  metrics: EvalMetrics;
  gradient: string;
  levelLabel: string;
}) {
  const agree = metrics.agreement;
  return (
    <div style={{ background: gradient, borderRadius: 12, padding: 20, color: "#fff" }}>
      <div style={{ fontSize: 13, opacity: 0.88, marginBottom: 12 }}>{levelLabel}</div>
      <Row gutter={16}>
        <Col span={6}>
          <div style={{ fontSize: 12, opacity: 0.85 }}>结论一致率</div>
          <div style={{ fontSize: 28, fontWeight: 700 }}>
            {(agree * 100).toFixed(1)}%
          </div>
        </Col>
        <Col span={6}>
          <div style={{ fontSize: 12, opacity: 0.85 }}>明确判断</div>
          <div style={{ fontSize: 28, fontWeight: 700 }}>
            {metrics.decisive_count ?? 0}
            <span style={{ fontSize: 14, opacity: 0.8 }}>/{metrics.total}</span>
          </div>
        </Col>
        <Col span={6}>
          <div style={{ fontSize: 12, opacity: 0.85 }}>待人工复核</div>
          <div style={{ fontSize: 28, fontWeight: 700 }}>
            {(metrics.needs_human_review_rate * 100).toFixed(0)}%
          </div>
        </Col>
        <Col span={6}>
          <div style={{ fontSize: 12, opacity: 0.85 }}>平均耗时</div>
          <div style={{ fontSize: 28, fontWeight: 700 }}>
            {metrics.avg_latency_ms}
            <span style={{ fontSize: 14, opacity: 0.8 }}>ms</span>
          </div>
        </Col>
      </Row>
      <div style={{ marginTop: 12, fontSize: 12, opacity: 0.8 }}>
        消耗 {metrics.total_tokens.toLocaleString()} tokens
      </div>
    </div>
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
          width: 105,
          render: (v: string) => <Tag color={verdictColor(v)}>{VERDICT_LABEL[v] ?? v}</Tag>,
        },
        {
          title: "模型结论",
          dataIndex: "predicted",
          width: 105,
          render: (v: string, r) => (
            <Tag color={v === r.ground_truth ? "success" : verdictColor(v)}>
              {VERDICT_LABEL[v] ?? v}
            </Tag>
          ),
        },
        {
          title: "置信度",
          dataIndex: "confidence",
          width: 75,
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

/** 混淆矩阵热力图 */
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
      style={{ height: 200 }}
      option={{
        tooltip: {
          formatter: (p: { data: [number, number, number] }) =>
            `标准=${VERDICT_LABEL[keys[p.data[1]]]}<br/>模型=${VERDICT_LABEL[keys[p.data[0]]]}<br/>数量=${p.data[2]}`,
        },
        grid: { left: 100, right: 20, top: 16, bottom: 44 },
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
          inRange: { color: ["#f0f0f0", "#2f9e6e"] },
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

  if (isLoading) return <Card loading style={CARD_STYLE} />;

  if (!data?.available) {
    return (
      <Card title="LLM 研判评测" style={CARD_STYLE}>
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
                  borderRadius: 6,
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
    <Space orientation="vertical" size={PAGE_GAP} style={{ width: "100%" }}>
      <Card style={CARD_STYLE}>
        <Space orientation="vertical" size={4}>
          <Title level={4} style={{ margin: 0 }}>
            LLM 研判评测结果
          </Title>
          <Text type="secondary">
            样本量 {data.sample_size} 条 · 运行于{" "}
            {data.run_at ? new Date(data.run_at).toLocaleString("zh-CN") : "-"}
            {data.models?.triage && ` · L1 ${data.models.triage}`}
            {data.models?.investigation && ` · L2 ${data.models.investigation}`}
          </Text>
        </Space>
      </Card>

      {/* L1 / L2 指标对比：渐变卡突出关键结论 */}
      <Row gutter={[16, 16]}>
        <Col span={12}>
          {l1 ? (
            <MetricCards
              metrics={l1.metrics}
              gradient={GRADIENTS.orange}
              levelLabel="L1 快速分诊（单轮 · 仅告警本身）"
            />
          ) : (
            <Card style={CARD_STYLE}>
              <Empty description="未运行 L1 评测" image={Empty.PRESENTED_IMAGE_SIMPLE} />
            </Card>
          )}
        </Col>
        <Col span={12}>
          {l2 ? (
            <MetricCards
              metrics={l2.metrics}
              gradient={GRADIENTS.green}
              levelLabel="L2 深度调查（多轮 · 工具驱动）"
            />
          ) : (
            <Card style={CARD_STYLE}>
              <Empty description="未运行 L2 评测" image={Empty.PRESENTED_IMAGE_SIMPLE} />
            </Card>
          )}
        </Col>
      </Row>

      {/* 逐条明细 */}
      <Row gutter={[16, 16]}>
        <Col span={12}>
          <Card title="L1 逐条明细" size="small" style={CARD_STYLE}>
            {l1 ? <DetailTable detail={l1.detail} /> : <Empty />}
          </Card>
        </Col>
        <Col span={12}>
          <Card title="L2 逐条明细" size="small" style={CARD_STYLE}>
            {l2 ? <DetailTable detail={l2.detail} /> : <Empty />}
          </Card>
        </Col>
      </Row>

      {l2 && (
        <Card title="L2 混淆矩阵" size="small" style={CARD_STYLE}>
          <ConfusionChart metrics={l2.metrics} />
        </Card>
      )}

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
