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
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { connectWs } from "./ws";
import { useAlertStream } from "./store";
import DashboardPage from "./pages/DashboardPage";
import AlertsPage from "./pages/AlertsPage";
import AlertDetailPage from "./pages/AlertDetailPage";
import FeedPage from "./pages/FeedPage";
import SuppressionsPage from "./pages/SuppressionsPage";
import type { Alert, WsMessage } from "./types";

const { Header, Content, Sider } = Layout;

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // 实时数据由 WebSocket 推送，查询结果没必要频繁判为过期
      staleTime: 10_000,
      retry: 1,
    },
  },
});

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
        : "/";

  return (
    <Layout style={{ minHeight: "100vh" }}>
      <Header style={{ display: "flex", alignItems: "center", gap: 16 }}>
        <div style={{ color: "#fff", fontWeight: 600, fontSize: 18 }}>
          NetSentinel
        </div>
        <Badge
          status={wsConnected ? "success" : "default"}
          text={
            <span style={{ color: "#rgba(255,255,255,.65)" }}>
              {wsConnected ? "实时已连接" : "实时未连接"}
            </span>
          }
        />
      </Header>
      <Layout>
        <Sider width={200} theme="light">
          <Menu
            mode="inline"
            selectedKeys={[selectedKey]}
            style={{ height: "100%", borderRight: 0 }}
            items={[
              { key: "/", label: <Link to="/">仪表盘</Link> },
              { key: "/alerts", label: <Link to="/alerts">实时告警</Link> },
              { key: "/feed", label: <Link to="/feed">数据重放</Link> },
              {
                key: "/suppressions",
                label: <Link to="/suppressions">抑制规则</Link>,
              },
            ]}
          />
        </Sider>
        <Content style={{ padding: 16 }}>
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/alerts/:id" element={<AlertDetailPage />} />
            <Route path="/feed" element={<FeedPage />} />
            <Route path="/suppressions" element={<SuppressionsPage />} />
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
      <ConfigProvider theme={{ algorithm: theme.defaultAlgorithm }}>
        <BrowserRouter>
          <Shell />
        </BrowserRouter>
      </ConfigProvider>
    </QueryClientProvider>
  );
}
