// 抑制规则管理页。
//
// 用途：把"已知噪声"告警自动过滤（如内部扫描器、监控探测），
// 不占用分析师精力，也不浪费 LLM 费用。

import { useState } from "react";
import {
  Alert,
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  Popconfirm,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import { DeleteOutlined, PlusOutlined } from "@ant-design/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import dayjs from "dayjs";

import {
  createSuppression,
  deleteSuppression,
  fetchSuppressions,
  type SuppressionRule,
} from "../api";

const { Text } = Typography;

const columns = [
  { title: "名称", dataIndex: "name" },
  {
    title: "匹配条件",
    render: (_: unknown, r: SuppressionRule) => (
      <Space wrap size={4}>
        {r.src_ip && <Tag color="blue">源 IP: {r.src_ip}</Tag>}
        {r.signature_id != null && <Tag color="purple">规则 ID: {r.signature_id}</Tag>}
        {r.category && <Tag color="cyan">分类: {r.category}</Tag>}
      </Space>
    ),
  },
  {
    title: "过期时间",
    dataIndex: "expires_at",
    width: 180,
    render: (v: string | null) =>
      v ? dayjs(v).format("YYYY-MM-DD HH:mm") : <Text type="secondary">永久</Text>,
  },
  { title: "创建时间", dataIndex: "created_at", width: 180,
    render: (v: string) => dayjs(v).format("YYYY-MM-DD HH:mm") },
];

export default function SuppressionsPage() {
  const [form] = Form.useForm();
  const queryClient = useQueryClient();
  const [submitting, setSubmitting] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["suppressions"],
    queryFn: fetchSuppressions,
  });

  const deleteMutation = useMutation({
    mutationFn: deleteSuppression,
    onSuccess: () => {
      message.success("已删除");
      queryClient.invalidateQueries({ queryKey: ["suppressions"] });
    },
  });

  const onFinish = async (values: {
    name: string;
    src_ip?: string;
    signature_id?: number;
    category?: string;
    reason?: string;
  }) => {
    // 前端先做一次校验，避免无谓的请求往返
    if (!values.src_ip && values.signature_id == null && !values.category) {
      message.warning("至少要填一个匹配条件 —— 空规则会匹配所有告警");
      return;
    }
    setSubmitting(true);
    try {
      await createSuppression(values);
      message.success("已创建");
      form.resetFields();
      queryClient.invalidateQueries({ queryKey: ["suppressions"] });
    } catch (err: unknown) {
      const detail =
        (err as { response?: { data?: { message?: string } } })?.response?.data
          ?.message ?? "创建失败";
      message.error(detail);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Alert
        type="info"
        showIcon
        message="抑制规则的作用"
        description="命中规则的告警会被自动跳过：不落库、不做 AI 研判、不推送。适用于已知的预期流量（如内部漏洞扫描器、监控端口探测）。注意规则采用 AND 逻辑 —— 多个条件必须同时满足，只写源 IP 会抑制该 IP 的所有告警。"
      />

      <Card title="新建规则">
        <Form form={form} layout="inline" onFinish={onFinish}>
          <Form.Item name="name" rules={[{ required: true, message: "请填名称" }]}>
            <Input placeholder="规则名称（如：内部扫描器）" style={{ width: 200 }} />
          </Form.Item>
          <Form.Item name="src_ip">
            <Input placeholder="源 IP（可选）" style={{ width: 160 }} />
          </Form.Item>
          <Form.Item name="signature_id">
            <InputNumber placeholder="规则 ID（可选）" style={{ width: 140 }} />
          </Form.Item>
          <Form.Item name="category">
            <Input placeholder="分类（可选）" style={{ width: 160 }} />
          </Form.Item>
          <Form.Item>
            <Button
              type="primary"
              htmlType="submit"
              icon={<PlusOutlined />}
              loading={submitting}
            >
              创建
            </Button>
          </Form.Item>
        </Form>
      </Card>

      <Card title={`已有规则（${data?.length ?? 0}）`}>
        <Table
          rowKey="id"
          size="small"
          loading={isLoading}
          columns={[
            ...columns,
            {
              title: "操作",
              width: 90,
              render: (_: unknown, r: SuppressionRule) => (
                <Popconfirm
                  title="确认删除这条规则？"
                  onConfirm={() => deleteMutation.mutate(r.id)}
                >
                  <Button type="link" danger icon={<DeleteOutlined />} size="small">
                    删除
                  </Button>
                </Popconfirm>
              ),
            },
          ]}
          dataSource={data ?? []}
        />
      </Card>
    </Space>
  );
}
