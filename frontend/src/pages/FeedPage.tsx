// 数据流控制页：选择 eve.json、倍速，启动重放。
//
// 演示的入口 —— 点击"开始重放"后，告警会按事件时间节奏
// 一条条出现在"实时告警流"页面。

import { useEffect, useState } from "react";
import { Alert, Button, Card, Form, Input, InputNumber, Select, Space, message } from "antd";
import { useQuery } from "@tanstack/react-query";

import { fetchAvailableFiles, startReplay } from "../api";
import { useAlertStream } from "../store";

export default function FeedPage() {
  const [form] = Form.useForm();
  const [submitting, setSubmitting] = useState(false);
  const clear = useAlertStream((s) => s.clear);

  const { data, refetch } = useQuery({
    queryKey: ["availableFiles"],
    queryFn: fetchAvailableFiles,
  });

  // 选中第一个可用文件，省去手动输入
  useEffect(() => {
    if (data?.files?.length) {
      form.setFieldValue("eve_path", data.files[0]);
    }
  }, [data, form]);

  const onFinish = async (values: { eve_path: string; speed: number }) => {
    setSubmitting(true);
    try {
      const res = await startReplay(values);
      message.success(res.message);
      // 启动新重放时清空实时缓冲，避免新旧数据混在一起难以分辨
      clear();
    } catch (err: unknown) {
      // axios 错误里后端返回的 {"code","message"} 才是可读信息
      const detail =
        (err as { response?: { data?: { message?: string } } })?.response?.data
          ?.message ?? "启动失败";
      message.error(detail);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Card title="数据重放控制">
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="说明"
          description="系统按 eve.json 中记录的**事件原始时间戳**节奏重放告警，复现实时 IDS 的观感。倍速越高播放越快；单步等待有上限，因此长时间间隔不会卡住演示。"
        />

        <Form
          form={form}
          layout="vertical"
          onFinish={onFinish}
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
              notFoundContent="data/ 下未找到 eve.json（请先准备数据）"
            />
          </Form.Item>

          <Form.Item label="倍速" name="speed" rules={[{ required: true }]}>
            <InputNumber min={1} max={10000} style={{ width: 200 }} />
          </Form.Item>

          <Space>
            <Button type="primary" htmlType="submit" loading={submitting}>
              开始重放
            </Button>
            <Button onClick={() => refetch()}>刷新文件列表</Button>
            <Button onClick={clear}>清空实时缓冲</Button>
          </Space>
        </Form>
      </Card>

      <Card title="手动指定路径" size="small">
        <Form
          layout="inline"
          onFinish={(v) => onFinish({ eve_path: v.manual_path, speed: v.manual_speed })}
          initialValues={{ manual_speed: 50 }}
        >
          <Form.Item
            name="manual_path"
            rules={[{ required: true, message: "请输入路径" }]}
          >
            <Input
              style={{ width: 380 }}
              placeholder="data/logs/eve.json（仅允许 data/ 下）"
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
