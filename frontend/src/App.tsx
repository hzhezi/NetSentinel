// 应用主框架：顶部导航 + 路由 + WebSocket 生命周期管理。
//
// WebSocket 在**根组件**建立一次（而非各页面分别建立）：
//    多个页面各自建连接会造成重复连接，且切换页面时反复断开重连。

import { useEffect, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { ConfigProvider, Layout, theme } from "antd";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { TopNav } from "./components/TopNav";
import { connectWs } from "./ws";
import { useAlertStream } from "./store";
import DashboardPage from "./pages/DashboardPage";
import AlertsPage from "./pages/AlertsPage";
import AlertDetailPage from "./pages/AlertDetailPage";
import FeedPage from "./pages/FeedPage";
import SuppressionsPage from "./pages/SuppressionsPage";
import EvaluationPage from "./pages/EvaluationPage";
import ReportsPage from "./pages/ReportsPage";
import type { Alert, WsMessage } from "./types";

const { Content } = Layout;

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      retry: 1,
    },
  },
});

function Shell() {
  const prependNewest = useAlertStream((s) => s.prependNewest);
  const [wsConnected, setWsConnected] = useState(false);

  useEffect(() => {
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

  return (
    <Layout style={{ minHeight: "100vh", background: "#f7f8fa" }}>
      <TopNav wsConnected={wsConnected} />
      {/* 宽度约束放在内层容器上，而不是 Content 本身 ——
          Content 是 flex 子项，直接加 maxWidth + auto margin
          会导致它在某些视口下被压缩、内容溢出裁切（实测踩到）。 */}
      <Content style={{ padding: 24 }}>
        <div style={{ maxWidth: 1400, margin: "0 auto" }}>
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/alerts/:id" element={<AlertDetailPage />} />
            <Route path="/feed" element={<FeedPage />} />
            <Route path="/suppressions" element={<SuppressionsPage />} />
            <Route path="/evaluation" element={<EvaluationPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </Content>
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
            // 与参考风格一致：更大的圆角、绿色主色
            borderRadius: 10,
            fontSize: 13,
            colorPrimary: "#2f9e6e",
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
