// 应用主框架：布局 + 路由 + WebSocket 生命周期管理。
//
// WebSocket 在**根组件**建立一次（而非各页面分别建立）：
//    多个页面各自建连接会造成重复连接，且切换页面时反复断开重连。
//    根组件持有连接，通过 store 把数据分发给订阅它的页面。

import { useEffect, useState } from "react";
import {
  BrowserRouter,
  Link,
  Navigate,
  Route,
  Routes,
  useLocation,
} from "react-router-dom";
import { Badge, ConfigProvider, Layout, Menu, theme } from "antd";
import {
  AlertOutlined,
  DashboardOutlined,
  ExperimentOutlined,
  PlayCircleOutlined,
  StopOutlined,
} from "@ant-design/icons";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { connectWs } from "./ws";
import { useAlertStream } from "./store";
import DashboardPage from "./pages/DashboardPage";
import AlertsPage from "./pages/AlertsPage";
import AlertDetailPage from "./pages/AlertDetailPage";
import FeedPage from "./pages/FeedPage";
import SuppressionsPage from "./pages/SuppressionsPage";
import EvaluationPage from "./pages/EvaluationPage";
import type { Alert, WsMessage } from "./types";

const { Content, Sider } = Layout;

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // 实时数据由 WebSocket 推送，查询结果没必要频繁判为过期
      staleTime: 10_000,
      retry: 1,
    },
  },
});

// 深色侧边栏 + 浅色内容区：视觉层次更清晰，
// 也避免整个界面一片白显得单调。
const SIDER_BG = "#001529";

function Shell() {
  const location = useLocation();
  const prependNewest = useAlertStream((s) => s.prependNewest);
  const [wsConnected, setWsConnected] = useState(false);

  useEffect(() => {
    // 建立一次连接，组件卸载时清理（见 ws.ts 返回的清理函数）
    const cleanup = connectWs(
      (msg) => {
        const m = msg as WsMessage;
        if (m.type === "new_alert") {
          prependNewest(m.data as Alert);
        }
      },
      {
        onOpen: () => setWsConnected(true),
        onClose: () => setWsConnected(false),
      },
    );
    return cleanup;
  }, [prependNewest]);

  const selectedKey = location.pathname.startsWith("/alerts")
    ? "/alerts"
    : location.pathname.startsWith("/feed")
      ? "/feed"
      : location.pathname.startsWith("/suppressions")
        ? "/suppressions"
        : location.pathname.startsWith("/evaluation")
          ? "/evaluation"
          : "/";

  return (
    <Layout style={{ minHeight: "100vh" }}>
      <Sider width={216} style={{ background: SIDER_BG }}>
        <div
          style={{
            height: 64,
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "0 20px",
          }}
        >
          <ExperimentOutlined style={{ color: "#1677ff", fontSize: 22 }} />
          <span style={{ color: "#fff", fontWeight: 600, fontSize: 17 }}>
            NetSentinel
          </span>
        </div>
        <Menu
          mode="inline"
          theme="dark"
          selectedKeys={[selectedKey]}
          style={{ background: "transparent", borderRight: 0 }}
          items={[
            {
              key: "/",
              icon: <DashboardOutlined />,
              label: <Link to="/">仪表盘</Link>,
            },
            {
              key: "/alerts",
              icon: <AlertOutlined />,
              label: <Link to="/alerts">实时告警</Link>,
            },
            {
              key: "/feed",
              icon: <PlayCircleOutlined />,
              label: <Link to="/feed">数据重放</Link>,
            },
            {
              key: "/evaluation",
              icon: <ExperimentOutlined />,
              label: <Link to="/evaluation">研判评测</Link>,
            },
            {
              key: "/suppressions",
              icon: <StopOutlined />,
              label: <Link to="/suppressions">抑制规则</Link>,
            },
          ]}
        />
      </Sider>

      <Layout>
        <Content style={{ padding: 20, background: "#f5f7fa" }}>
          {/* 连接状态放在内容区右上角，避免占用侧边栏空间 */}
          <div style={{ textAlign: "right", marginBottom: 8 }}>
            <Badge
              status={wsConnected ? "success" : "default"}
              text={
                <span style={{ fontSize: 12, color: "#8c8c8c" }}>
                  {wsConnected ? "实时连接正常" : "实时连接中断（自动重连中）"}
                </span>
              }
            />
          </div>
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/alerts/:id" element={<AlertDetailPage />} />
            <Route path="/feed" element={<FeedPage />} />
            <Route path="/suppressions" element={<SuppressionsPage />} />
            <Route path="/evaluation" element={<EvaluationPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Content>
      </Layout>
    </Layout>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ConfigProvider
        theme={{
          algorithm: theme.defaultAlgorithm,
          token: {
            // 收紧默认圆角与字号，整体更紧凑利落
            borderRadius: 6,
            fontSize: 13,
          },
        }}
      >
        <BrowserRouter>
          <Shell />
        </BrowserRouter>
      </ConfigProvider>
    </QueryClientProvider>
  );
}
