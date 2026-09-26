// 告警详情页：原始信息 + 富化 + **AI 研判**。
//
// 这是"研判层增值"最直观的展示位置：左侧是传统 IDS 会给出的东西
// （签名、五元组），右侧/下方是 LLM 提供的结论、理由与建议。

import { useParams, Link } from "react-router-dom";
import { Button, Card, Descriptions, Space, Spin, Typography } from "antd";
import { useQuery } from "@tanstack/react-query";
import dayjs from "dayjs";

import { fetchAlert, fetchTriage } from "../api";
import { SeverityTag } from "../components/Tags";
import { TriageCard, TriageEmpty } from "../components/TriageCard";

const { Text } = Typography;

export default function AlertDetailPage() {
  const { id = "" } = useParams();

  const alertQuery = useQuery({
    queryKey: ["alert", id],
    queryFn: () => fetchAlert(id),
    enabled: Boolean(id),
  });

  const triageQuery = useQuery({
    queryKey: ["triage", id],
    queryFn: () => fetchTriage(id),
    enabled: Boolean(id),
    // 研判是异步产生的：进入详情页时可能还没算完，因此轮询几次。
    refetchInterval: (query) =>
      (query.state.data?.length ?? 0) > 0 ? false : 3000,
  });

  if (alertQuery.isLoading) return <Spin />;
  if (alertQuery.isError || !alertQuery.data) {
    return <Card>未找到该告警。</Card>;
  }

  const alert = alertQuery.data;

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Card
        title="告警详情"
        extra={<Link to="/alerts">← 返回列表</Link>}
      >
        <Descriptions column={2} size="small" bordered>
          <Descriptions.Item label="签名" span={2}>
            {alert.signature}
          </Descriptions.Item>
          <Descriptions.Item label="严重度">
            <SeverityTag severity={alert.severity} />
          </Descriptions.Item>
          <Descriptions.Item label="事件时间">
            {dayjs(alert.detected_at).format("YYYY-MM-DD HH:mm:ss")}
          </Descriptions.Item>
          <Descriptions.Item label="源地址">
            {alert.src_ip}
            {alert.src_port ? `:${alert.src_port}` : ""}
          </Descriptions.Item>
          <Descriptions.Item label="目标地址">
            {alert.dst_ip}
            {alert.dst_port ? `:${alert.dst_port}` : ""}
          </Descriptions.Item>
          <Descriptions.Item label="协议">{alert.protocol ?? "-"}</Descriptions.Item>
          <Descriptions.Item label="分类">{alert.category ?? "-"}</Descriptions.Item>
          <Descriptions.Item label="状态">{alert.status}</Descriptions.Item>
          <Descriptions.Item label="检测引擎">{alert.source_engine}</Descriptions.Item>
        </Descriptions>

        <Button
          type="link"
          style={{ paddingLeft: 0, marginTop: 8 }}
          onClick={() => alertQuery.refetch()}
        >
          刷新
        </Button>
      </Card>

      <Card title="AI 研判">
        {triageQuery.isLoading ? (
          <Spin />
        ) : (triageQuery.data?.length ?? 0) === 0 ? (
          <TriageEmpty />
        ) : (
          triageQuery.data!.map((r) => <TriageCard key={r.id} result={r} />)
        )}

        <Text type="secondary" style={{ fontSize: 12 }}>
          研判结果由 LLM 生成，仅供参考；结论与依据均可在上方追溯。
        </Text>
      </Card>
    </Space>
  );
}
