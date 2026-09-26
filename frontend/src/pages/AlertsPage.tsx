// 实时告警流页面。
//
// 数据来源有两路：
//   1. 历史查询（TanStack Query + 分页接口）—— 刷新后能看到已有数据
//   2. WebSocket 实时推送 —— 新告警插到最前
// 两路数据在渲染时合并去重（见下方的 merge）。

import { useMemo, useState } from "react";
import { Card, Input, Space, Table, Tag } from "antd";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import dayjs from "dayjs";

import { fetchAlerts } from "../api";
import { SeverityTag } from "../components/Tags";
import { useAlertStream } from "../store";
import type { Alert } from "../types";

const columns = [
  {
    title: "时间",
    dataIndex: "detected_at",
    width: 170,
    // 展示事件**原始时间**（而非入库时间）—— 重放历史流量时两者可能差很远
    render: (v: string) => dayjs(v).format("MM-DD HH:mm:ss"),
  },
  {
    title: "严重度",
    dataIndex: "severity",
    width: 100,
    render: (v: string) => <SeverityTag severity={v} />,
  },
  {
    title: "签名",
    dataIndex: "signature",
    render: (v: string, row: Alert) => <Link to={`/alerts/${row.id}`}>{v}</Link>,
  },
  { title: "源 IP", dataIndex: "src_ip", width: 140 },
  {
    title: "目标",
    dataIndex: "dst_ip",
    width: 160,
    render: (v: string, row: Alert) =>
      row.dst_port ? `${v}:${row.dst_port}` : v,
  },
  {
    title: "协议",
    dataIndex: "protocol",
    width: 80,
    render: (v: string | null) => (v ? <Tag>{v}</Tag> : "-"),
  },
];

export default function AlertsPage() {
  const [page, setPage] = useState(1);
  const [keyword, setKeyword] = useState("");
  const liveAlerts = useAlertStream((s) => s.alerts);

  const { data, isLoading } = useQuery({
    queryKey: ["alerts", page, keyword],
    queryFn: () => fetchAlerts({ page, size: 20, q: keyword || undefined }),
    // 实时流已经负责"新告警"，历史查询不必频繁轮询
    refetchInterval: 30000,
  });

  // 合并历史与实时：实时在前，按 id 去重。
  // 实时的那条可能也已经出现在历史页里（若刚刷新过），所以必须去重。
  const merged = useMemo(() => {
    const seen = new Set<string>();
    const out: Alert[] = [];
    for (const a of [...liveAlerts, ...(data?.items ?? [])]) {
      if (seen.has(a.id)) continue;
      seen.add(a.id);
      out.push(a);
    }
    return out;
  }, [liveAlerts, data?.items]);

  return (
    <Card
      title={
        <Space>
          <span>实时告警流</span>
          <Tag color="green">WebSocket 已连接时自动更新</Tag>
        </Space>
      }
      extra={
        <Input.Search
          placeholder="搜索签名"
          allowClear
          style={{ width: 220 }}
          onSearch={(v) => {
            setKeyword(v);
            setPage(1);
          }}
        />
      }
    >
      <Table
        rowKey="id"
        size="small"
        loading={isLoading}
        columns={columns}
        dataSource={merged}
        pagination={{
          current: page,
          pageSize: 20,
          total: data?.total ?? 0,
          onChange: setPage,
          showSizeChanger: false,
        }}
      />
    </Card>
  );
}
