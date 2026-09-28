// 数据输入页：两条路都能喂数据给系统。
//
//   A. 上传 pcap —— 系统自动跑 Suricata 检测 + 重放（贴近"真在检测"）
//   B. 选择已有 eve.json 重放 —— 跳过检测，直接走研判链路
//
// 两条路的区别只在"检测由谁完成"：
//   A：后端调 Suricata 容器现场检测
//   B：文件里已经是 Suricata 的产出

import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Divider,
  Form,
  Input,
  InputNumber,
  Select,
  Space,
  Tag,
  Typography,
  Upload,
  message,
} from "antd";
import { InboxOutlined, PlayCircleOutlined } from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";

import {
  fetchAvailableFiles,
  fetchUploadLimits,
  startReplay,
  uploadPcap,
} from "../api";
import { useAlertStream } from "../store";
import { CARD_STYLE, PAGE_GAP } from "../theme";

const { Text, Paragraph } = Typography;

export default function FeedPage() {
  const [form] = Form.useForm();
  const [submitting, setSubmitting] = useState(false);
  const [uploading, setUploading] = useState(false);
  const clear = useAlertStream((s) => s.clear);

  const { data, refetch } = useQuery({
    queryKey: ["availableFiles"],
    queryFn: fetchAvailableFiles,
  });
  const { data: limits } = useQuery({
    queryKey: ["uploadLimits"],
    queryFn: fetchUploadLimits,
  });

  useEffect(() => {
    if (data?.files?.length) {
      form.setFieldValue("eve_path", data.files[0]);
    }
  }, [data, form]);

  const onReplay = async (values: { eve_path: string; speed: number }) => {
    setSubmitting(true);
    try {
      const res = await startReplay(values);
      message.success(res.message);
      clear();
    } catch (err: unknown) {
      const detail =
        (err as { response?: { data?: { message?: string } } })?.response?.data
          ?.message ?? "启动失败";
      message.error(detail);
    } finally {
      setSubmitting(false);
    }
  };

  // 上传 pcap：后端会跑 Suricata 检测、然后自动重放
  const handleUpload = async (file: File) => {
    setUploading(true);
    clear();
    const hide = message.loading("正在检测流量，请稍候…", 0);
    try {
      const res = await uploadPcap(file);
      hide();
      message.success(res.message, 6);
      // 检测完的告警已经推到前端了，提示用户去看告警页
      if (res.alerts_created > 0) {
        message.info("可切换到「实时告警」页查看结果", 5);
      }
    } catch (err: unknown) {
      hide();
      const detail =
        (err as { response?: { data?: { message?: string } } })?.response?.data
          ?.message ?? "上传处理失败";
      // 用车错误提示展示 —— Suricata 不可用等提示较长，需要完整看到
      message.error(detail, 8);
    } finally {
      setUploading(false);
    }
  };

  return (
    <Space orientation="vertical" size={PAGE_GAP} style={{ width: "100%" }}>
      {/* ── 方式 A：上传 pcap ── */}
      <Card
        style={CARD_STYLE}
        title="上传流量包检测"
        extra={
          <Text type="secondary" style={{ fontSize: 12 }}>
            系统会调用 Suricata 现场分析
          </Text>
        }
      >
        <Upload.Dragger
          accept=".pcap,.pcapng"
          maxCount={1}
          showUploadList={false}
          disabled={uploading}
          beforeUpload={(file) => {
            // 返回 false 阻止 antd 自行上传 —— 我们走自己的接口
            handleUpload(file);
            return false;
          }}
        >
          <p className="ant-upload-drag-icon">
            <InboxOutlined />
          </p>
          <p className="ant-upload-text">
            点击或拖拽 pcap 文件到此处
          </p>
          <p className="ant-upload-hint">
            支持 {limits?.allowed_extensions.join(" / ") ?? ".pcap / .pcapng"}，
            最大 {limits?.max_mb ?? 50}MB。
            处理完成后临时文件会被删除。
          </p>
        </Upload.Dragger>

        <Paragraph type="secondary" style={{ fontSize: 12, marginTop: 12, marginBottom: 0 }}>
          上传后系统会自动完成：<Tag>Suricata 检测</Tag>
          <Tag>去重</Tag>
          <Tag>抑制过滤</Tag>
          <Tag>告警落库</Tag>
          —— 结果推送到「实时告警」页。
        </Paragraph>
      </Card>

      <Divider style={{ margin: 0 }}>
        <Text type="secondary" style={{ fontSize: 12 }}>
          或
        </Text>
      </Divider>

      {/* ── 方式 B：重放已有 eve.json ── */}
      <Card
        style={CARD_STYLE}
        title="重放已有检测结果"
        extra={
          <Text type="secondary" style={{ fontSize: 12 }}>
            按事件时间节奏重放，复现实时观感
          </Text>
        }
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={onReplay}
          initialValues={{ speed: 50 }}
        >
          <Form.Item
            label="eve.json 文件"
            name="eve_path"
            rules={[{ required: true, message: "请选择文件" }]}
          >
            <Select
              showSearch
              placeholder="选择 data/ 下的 eve.json"
              options={(data?.files ?? []).map((f) => ({ value: f, label: f }))}
              notFoundContent="data/ 下未找到 eve.json"
            />
          </Form.Item>

          <Form.Item label="倍速" name="speed" rules={[{ required: true }]}>
            <InputNumber min={1} max={10000} style={{ width: 180 }} />
          </Form.Item>

          <Space>
            <Button
              type="primary"
              htmlType="submit"
              icon={<PlayCircleOutlined />}
              loading={submitting}
            >
              开始重放
            </Button>
            <Button onClick={() => refetch()}>刷新文件列表</Button>
            <Button onClick={clear}>清空实时缓冲</Button>
          </Space>
        </Form>

        <Alert
          type="info"
          showIcon
          style={{ marginTop: 16 }}
          message="与上传的区别"
          description="这种方式跳过检测步骤 —— 文件里已经是 Suricata 的输出。适合反复演示同一批数据。"
        />
      </Card>

      {/* 手动指定路径（保留，用于没被扫描到的文件） */}
      <Card size="small" style={CARD_STYLE} title="手动指定路径">
        <Form
          layout="inline"
          onFinish={(v) =>
            onReplay({ eve_path: v.manual_path, speed: v.manual_speed })
          }
          initialValues={{ manual_speed: 50 }}
        >
          <Form.Item
            name="manual_path"
            rules={[{ required: true, message: "请输入路径" }]}
          >
            <Input
              style={{ width: 360 }}
              placeholder="data/logs/xxx.json（仅允许 data/ 下）"
            />
          </Form.Item>
          <Form.Item name="manual_speed">
            <InputNumber min={1} max={10000} />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={submitting}>
              重放
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </Space>
  );
}
