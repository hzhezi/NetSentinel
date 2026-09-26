// 仪表盘：主视觉统计卡 + 彩色功能卡网格。
//
// 视觉设计参考"雪山 Link"风格：
//   1. 一块**大渐变卡片**占主位，承载最核心的指标与图表
//   2. 下方是**彩色渐变小卡网格**，每个入口一个大图标
//   3. 柔和渐变 + 大圆角，避免纯白+细边的冷淡感

import { Link } from "react-router-dom";
import { Card, Col, Empty, Row, Space, Typography } from "antd";
import {
  AlertOutlined,
  ExperimentOutlined,
  FileTextOutlined,
  PlayCircleOutlined,
  StopOutlined,
} from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";
import ReactECharts from "echarts-for-react";

import { fetchOverview } from "../api";

const { Text } = Typography;

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

/** 渐变配色。每个功能卡一套，形成视觉节奏 */
const GRADIENTS = {
  green: "linear-gradient(135deg, #2f9e6e 0%, #6dd5a4 100%)",
  purple: "linear-gradient(135deg, #7c6df0 0%, #a99bf5 100%)",
  blue: "linear-gradient(135deg, #3b82f6 0%, #7cb4fc 100%)",
  orange: "linear-gradient(135deg, #f59e0b 0%, #fbbf5c 100%)",
  pink: "linear-gradient(135deg, #ec4899 0%, #f58fb9 100%)",
};

/** 功能入口卡片（彩色渐变 + 大图标 + 底部说明） */
function NavCard({
  to,
  icon,
  title,
  desc,
  gradient,
}: {
  to: string;
  icon: React.ReactNode;
  title: string;
  desc: string;
  gradient: string;
}) {
  return (
    <Link to={to}>
      <div
        style={{
          background: gradient,
          borderRadius: 14,
          padding: "20px 20px 0",
          height: 168,
          display: "flex",
          flexDirection: "column",
          color: "#fff",
          transition: "transform .15s, box-shadow .15s",
          overflow: "hidden",
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = "translateY(-2px)";
          e.currentTarget.style.boxShadow = "0 8px 20px rgba(0,0,0,.12)";
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = "none";
          e.currentTarget.style.boxShadow = "none";
        }}
      >
        <div style={{ fontSize: 34, opacity: 0.95 }}>{icon}</div>
        <div style={{ marginTop: "auto" }}>
          <div style={{ fontSize: 17, fontWeight: 600 }}>{title}</div>
          <div style={{ fontSize: 12, opacity: 0.85, marginTop: 2 }}>{desc}</div>
        </div>
        {/* 底部说明条：视觉上把卡片"收口" */}
        <div
          style={{
            marginTop: 14,
            marginLeft: -20,
            marginRight: -20,
            padding: "10px 20px",
            background: "rgba(255,255,255,.16)",
            fontSize: 12,
            display: "flex",
            justifyContent: "space-between",
          }}
        >
          <span>查看 →</span>
        </div>
      </div>
    </Link>
  );
}

export default function DashboardPage() {
  const { data } = useQuery({
    queryKey: ["overview"],
    queryFn: fetchOverview,
    refetchInterval: 10000,
  });

  const total = data?.alerts.total ?? 0;
  const bySev = data?.alerts.by_severity ?? {};
  const usage = data?.triage.usage;
  const triaged = usage?.count ?? 0;

  const criticalCount = (bySev.critical ?? 0) + (bySev.high ?? 0);

  // 环形图：严重度分布
  const severityOption = {
    tooltip: { trigger: "item" },
    series: [
      {
        type: "pie",
        radius: ["58%", "78%"],
        center: ["50%", "50%"],
        itemStyle: { borderColor: "#fff", borderWidth: 2 },
        label: {
          color: "#fff",
          fontSize: 12,
          formatter: "{b}\n{c}",
        },
        labelLine: { lineStyle: { color: "rgba(255,255,255,.6)" } },
        data: Object.entries(bySev).map(([k, v]) => ({
          name: SEVERITY_LABEL[k] ?? k,
          value: v,
        })),
      },
    ],
  };

  return (
    <Space orientation="vertical" size={20} style={{ width: "100%" }}>
      {/* ── 主视觉卡：大渐变 + 核心指标 ── */}
      <div
        style={{
          background: GRADIENTS.green,
          borderRadius: 16,
          padding: 28,
          color: "#fff",
          position: "relative",
          overflow: "hidden",
        }}
      >
        <Row align="middle" gutter={24}>
          <Col span={13}>
            <div style={{ fontSize: 13, opacity: 0.85 }}>当前态势</div>
            <div style={{ fontSize: 34, fontWeight: 700, marginTop: 4 }}>
              共 {total} 条告警
            </div>
            <div
              style={{
                marginTop: 16,
                fontSize: 14,
                lineHeight: 2,
                opacity: 0.95,
              }}
            >
              <div>
                高危告警（严重 + 高）：<strong>{criticalCount}</strong> 条
              </div>
              <div>
                已完成 AI 研判：<strong>{triaged}</strong> 条
              </div>
              <div>
                平均研判耗时：
                <strong>
                  {usage && usage.count > 0
                    ? Math.round(usage.total_latency_ms / usage.count)
                    : 0}
                </strong>{" "}
                ms
              </div>
              <div>
                累计消耗：<strong>{usage?.total_tokens ?? 0}</strong> tokens
              </div>
            </div>
          </Col>
          <Col span={11}>
            <div style={{ textAlign: "center" }}>
              {Object.keys(bySev).length === 0 ? (
                <div style={{ padding: "40px 0", opacity: 0.9 }}>
                  <Empty
                    image={Empty.PRESENTED_IMAGE_SIMPLE}
                    description={
                      <span style={{ color: "rgba(255,255,255,.85)" }}>
                        暂无告警数据
                      </span>
                    }
                  />
                </div>
              ) : (
                <ReactECharts
                  option={severityOption}
                  style={{ height: 240 }}
                />
              )}
            </div>
          </Col>
        </Row>
      </div>

      {/* ── 功能入口卡网格 ── */}
      <Row gutter={[16, 16]}>
        <Col span={8}>
          <NavCard
            to="/alerts"
            icon={<AlertOutlined />}
            title="实时告警"
            desc="告警流 + AI 研判"
            gradient={GRADIENTS.purple}
          />
        </Col>
        <Col span={8}>
          <NavCard
            to="/feed"
            icon={<PlayCircleOutlined />}
            title="数据重放"
            desc="按原始时间戳准实时重放"
            gradient={GRADIENTS.blue}
          />
        </Col>
        <Col span={8}>
          <NavCard
            to="/reports"
            icon={<FileTextOutlined />}
            title="安全日报"
            desc="态势汇总与重点事件"
            gradient={GRADIENTS.orange}
          />
        </Col>
        <Col span={8}>
          <NavCard
            to="/evaluation"
            icon={<ExperimentOutlined />}
            title="研判评测"
            desc="L1 vs L2 实测对比"
            gradient={GRADIENTS.pink}
          />
        </Col>
        <Col span={8}>
          <NavCard
            to="/suppressions"
            icon={<StopOutlined />}
            title="抑制规则"
            desc="过滤已知噪声"
            gradient="linear-gradient(135deg, #0891b2 0%, #4dd0e1 100%)"
          />
        </Col>
        <Col span={8}>
          <Card
            style={{
              height: 168,
              borderRadius: 14,
              background: "#fafafa",
              border: "1px dashed #d9d9d9",
            }}
            styles={{ body: { height: "100%" } }}
          >
            <div
              style={{
                height: "100%",
                display: "flex",
                flexDirection: "column",
                justifyContent: "center",
                alignItems: "center",
                color: "#8c8c8c",
                textAlign: "center",
              }}
            >
              <div style={{ fontSize: 13, lineHeight: 1.9 }}>
                AI 研判结论分布
                <br />
                <Text type="secondary" style={{ fontSize: 12 }}>
                  {Object.entries(data?.triage.by_verdict ?? {}).length === 0
                    ? "暂无研判结果"
                    : Object.entries(data!.triage.by_verdict)
                        .map(([k, v]) => `${VERDICT_LABEL[k] ?? k} ${v}`)
                        .join(" · ")}
                </Text>
              </div>
            </div>
          </Card>
        </Col>
      </Row>
    </Space>
  );
}
