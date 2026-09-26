// 告警详情页：原始信息 + L1 分诊 + **L2 深度调查（证据链）**。
//
// 这是"研判层增值"最直观的展示位置 ——
// 左侧是传统 IDS 给出的东西（签名、五元组），
// 下方是 LLM 提供的结论、理由、建议，以及**得出这些结论的调查过程**。

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  Button,
  Card,
  Descriptions,
  Divider,
  Space,
  Spin,
  Typography,
  message,
} from "antd";
import { ExperimentOutlined } from "@ant-design/icons";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import dayjs from "dayjs";

import { fetchAlert, fetchTriage, investigateAlert } from "../api";
import { EvidenceTrailCard } from "../components/EvidenceTrail";
import { SeverityTag } from "../components/Tags";
import { TriageCard, TriageEmpty } from "../components/TriageCard";

const { Text, Title } = Typography;

export default function AlertDetailPage() {
  const { id = "" } = useParams();
  const queryClient = useQueryClient();
  const [investigating, setInvestigating] = useState(false);

  const alertQuery = useQuery({
    queryKey: ["alert", id],
    queryFn: () => fetchAlert(id),
    enabled: Boolean(id),
  });

  const triageQuery = useQuery({
    queryKey: ["triage", id],
    queryFn: () => fetchTriage(id),
    enabled: Boolean(id),
    // 研判是异步产生的：进入详情页时可能还没算完，因此轮询几次
    refetchInterval: (query) =>
      (query.state.data?.length ?? 0) > 0 ? false : 3000,
  });

  // 手动触发深度调查。这是 Human-in-the-loop 的入口：
  // 分析人员可以主动要求深入调查，即使 L1 判断"无需升级"。
  const handleInvestigate = async () => {
    setInvestigating(true);
    try {
      await investigateAlert(id);
      message.success("深度调查完成");
      // 重新拉取研判结果以展示新增的 L2 结论
      await queryClient.invalidateQueries({ queryKey: ["triage", id] });
    } catch (err: unknown) {
      const detail =
        (err as { response?: { data?: { message?: string } } })?.response?.data
          ?.message ?? "调查失败，请查看后端日志";
      message.error(detail);
    } finally {
      setInvestigating(false);
    }
  };

  if (alertQuery.isLoading) return <Spin />;
  if (alertQuery.isError || !alertQuery.data) {
    return <Card>未找到该告警。</Card>;
  }

  const alert = alertQuery.data;
  const triageRecords = triageQuery.data ?? [];
  const l1 = triageRecords.filter((r) => r.stage === "triage");
  const l2 = triageRecords.filter((r) => r.stage === "investigation");

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Card title="告警详情" extra={<Link to="/alerts">← 返回列表</Link>}>
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

      {/* ── L1 快速分诊 ── */}
      <Card
        title="AI 研判 · L1 快速分诊"
        extra={<Text type="secondary">每条告警自动执行</Text>}
      >
        {triageQuery.isLoading ? (
          <Spin />
        ) : l1.length === 0 ? (
          <TriageEmpty />
        ) : (
          l1.map((r) => <TriageCard key={r.id} result={r} />)
        )}
      </Card>

      {/* ── L2 深度调查 ── */}
      <Card
        title="AI 研判 · L2 深度调查"
        extra={
          <Button
            type="primary"
            icon={<ExperimentOutlined />}
            loading={investigating}
            onClick={handleInvestigate}
          >
            {l2.length > 0 ? "重新调查" : "深度调查"}
          </Button>
        }
      >
        <Text type="secondary" style={{ fontSize: 12 }}>
          L2 会调用工具（威胁情报、关联告警、资产信息）收集更多证据，
          耗时约 6-10 秒。适用于 L1 结论为"待人工复核"或你认为需要深入核查的告警。
        </Text>
        <Divider style={{ margin: "12px 0" }} />

        {l2.length === 0 ? (
          <Text type="secondary">
            尚未执行深度调查。点击右上角按钮开始。
          </Text>
        ) : (
          l2.map((r) => (
            <div key={r.id} style={{ marginBottom: 16 }}>
              <Title level={5} style={{ marginTop: 0 }}>
                {r.verdict === "true_positive"
                  ? "结论：真实攻击"
                  : r.verdict === "false_positive"
                    ? "结论：误报"
                    : "结论：待人工复核"}
              </Title>
              <TriageCard result={r} />
              <EvidenceTrailCard trail={r.evidence_trail} />
            </div>
          ))
        )}
      </Card>
    </Space>
  );
}
