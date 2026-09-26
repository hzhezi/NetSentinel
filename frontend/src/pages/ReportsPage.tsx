// 安全日报页：汇总一段时间窗的态势，由 LLM 写成人话。
//
// 与实时研判的区别：这里看的是**全局态势**（今天多少、什么类型、
// 最该关注什么），而不是单条告警的处理。

import { useState } from "react";
import {
  Alert,
  Button,
  Card,
  Col,
  Row,
  Select,
  Space,
  Statistic,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import { FileTextOutlined, ReloadOutlined } from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";

import { fetchDailyReport } from "../api";
import { SeverityTag } from "../components/Tags";

const { Text, Paragraph } = Typography;

const VERDICT_LABEL: Record<string, string> = {
  true_positive: "真实攻击",
  false_positive: "误报",
  needs_human_review: "待人工复核",
};

export default function ReportsPage() {
  const [hours, setHours] = useState(24);

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["dailyReport", hours],
    queryFn: () => fetchDailyReport(hours),
  });

  if (isLoading) return <Card loading />;
  if (!data) return <Card>加载失败</Card>;

  const { stats } = data;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(data.report);
      message.success("日报已复制到剪贴板");
    } catch {
      message.warning("复制失败，请手动选择文本");
    }
  };

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Card
        title={
          <Space>
            <FileTextOutlined />
            <span>安全日报</span>
          </Space>
        }
        extra={
          <Space>
            <Select
              value={hours}
              style={{ width: 140 }}
              onChange={setHours}
              options={[
                { value: 1, label: "最近 1 小时" },
                { value: 6, label: "最近 6 小时" },
                { value: 24, label: "最近 24 小时" },
                { value: 168, label: "最近 7 天" },
              ]}
            />
            <Button
              icon={<ReloadOutlined />}
              loading={isFetching}
              onClick={() => refetch()}
            >
              重新生成
            </Button>
            <Button onClick={handleCopy}>复制</Button>
          </Space>
        }
      >
        {/* LLM 不可用时明确标注，不假装是 AI 写的 */}
        {!data.generated_by_llm && (
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 12 }}
            message="LLM 不可用，当前为模板日报（数字准确，但无分析内容）"
            description={data.error}
          />
        )}
        <Paragraph
          style={{
            whiteSpace: "pre-wrap",
            fontSize: 14,
            lineHeight: 1.9,
            marginBottom: 0,
          }}
        >
          {data.report}
        </Paragraph>
      </Card>

      <Row gutter={[16, 16]}>
        <Col span={6}>
          <Card>
            <Statistic title="告警总数" value={stats.alerts.total} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="需人工复核"
              value={stats.triage.by_verdict?.needs_human_review ?? 0}
              valueStyle={{ color: "#faad14" }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="确认攻击"
              value={stats.triage.by_verdict?.true_positive ?? 0}
              valueStyle={{ color: "#cf1322" }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="研判成本"
              value={stats.triage.total_tokens}
              suffix="tokens"
            />
          </Card>
        </Col>
      </Row>

      <Card title={`重点事件（${stats.notable_alerts.length}）`} size="small">
        <Table
          rowKey={(r) => `${r.signature}-${r.src_ip}`}
          size="small"
          pagination={false}
          dataSource={stats.notable_alerts}
          columns={[
            {
              title: "严重度",
              dataIndex: "severity",
              width: 100,
              render: (v: string) => <SeverityTag severity={v} />,
            },
            { title: "签名", dataIndex: "signature" },
            { title: "来源", dataIndex: "src_ip", width: 150 },
            { title: "目标", dataIndex: "dst_ip", width: 150 },
            {
              title: "研判结论",
              dataIndex: "verdict",
              width: 130,
              render: (v: string) => (
                <Tag color={v === "true_positive" ? "red" : v === "false_positive" ? "green" : "gold"}>
                  {VERDICT_LABEL[v] ?? v}
                </Tag>
              ),
            },
          ]}
        />
        {stats.notable_alerts.length === 0 && (
          <Text type="secondary">本时段内无高严重度告警。</Text>
        )}
      </Card>

      <Card title="高频来源 IP" size="small">
        {stats.alerts.top_sources.length === 0 ? (
          <Text type="secondary">无数据</Text>
        ) : (
          <Space wrap>
            {stats.alerts.top_sources.map((s) => (
              <Tag key={s.src_ip} color="volcano">
                {s.src_ip} × {s.count}
              </Tag>
            ))}
          </Space>
        )}
      </Card>
    </Space>
  );
}
