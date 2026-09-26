// 顶部导航栏。
//
// 风格参考：横向白底导航 + 图标 + 高亮当前项，
// 比侧边栏更扁平、更适合"仪表盘"类应用（内容区更宽）。

import { Link, useLocation } from "react-router-dom";
import { Badge, Layout, Space } from "antd";
import {
  AlertOutlined,
  DashboardOutlined,
  ExperimentOutlined,
  FileTextOutlined,
  PlayCircleOutlined,
  SafetyCertificateOutlined,
  StopOutlined,
} from "@ant-design/icons";

const { Header } = Layout;

const NAV = [
  { key: "/", to: "/", label: "仪表盘", icon: <DashboardOutlined /> },
  { key: "/alerts", to: "/alerts", label: "实时告警", icon: <AlertOutlined /> },
  { key: "/feed", to: "/feed", label: "数据重放", icon: <PlayCircleOutlined /> },
  { key: "/reports", to: "/reports", label: "安全日报", icon: <FileTextOutlined /> },
  { key: "/evaluation", to: "/evaluation", label: "研判评测", icon: <ExperimentOutlined /> },
  { key: "/suppressions", to: "/suppressions", label: "抑制规则", icon: <StopOutlined /> },
];

export function TopNav({ wsConnected }: { wsConnected: boolean }) {
  const location = useLocation();

  // 当前激活项：取路径前缀匹配最长的那个
  // （否则 `/alerts` 详情页 `/alerts/xxx` 也能正确高亮）
  const active =
    NAV.filter((n) => n.key !== "/" && location.pathname.startsWith(n.key))
      .sort((a, b) => b.key.length - a.key.length)[0]?.key ??
    (location.pathname === "/" ? "/" : "");

  return (
    <Header
      style={{
        position: "sticky",
        top: 0,
        zIndex: 10,
        height: 64,
        padding: "0 24px",
        background: "#fff",
        borderBottom: "1px solid #f0f0f0",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
      }}
    >
      {/* 左侧：Logo */}
      <Space size={10} style={{ minWidth: 200 }}>
        <div
          style={{
            width: 34,
            height: 34,
            borderRadius: 9,
            background: "linear-gradient(135deg, #2f9e6e 0%, #52c41a 100%)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <SafetyCertificateOutlined style={{ color: "#fff", fontSize: 18 }} />
        </div>
        <span style={{ fontWeight: 700, fontSize: 18, letterSpacing: 0.3 }}>
          NetSentinel
        </span>
      </Space>

      {/* 中间：导航 */}
      <Space size={4}>
        {NAV.map((item) => {
          const isActive = active === item.key;
          return (
            <Link
              key={item.key}
              to={item.to}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                padding: "8px 14px",
                borderRadius: 8,
                fontSize: 14,
                fontWeight: isActive ? 600 : 400,
                color: isActive ? "#1f8a5f" : "#595959",
                background: isActive ? "#eafaf2" : "transparent",
                transition: "all .15s",
              }}
            >
              {item.icon}
              {item.label}
            </Link>
          );
        })}
      </Space>

      {/* 右侧：连接状态 */}
      <div style={{ minWidth: 150, textAlign: "right" }}>
        <Badge
          status={wsConnected ? "success" : "default"}
          text={
            <span style={{ fontSize: 12, color: "#8c8c8c" }}>
              {wsConnected ? "实时连接正常" : "连接中断"}
            </span>
          }
        />
      </div>
    </Header>
  );
}
