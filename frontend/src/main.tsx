import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.tsx";

// 不引入样式框架的全局 CSS —— 全部用 antd 组件与内联样式，
// 避免样式来源分散在两处难以排查。
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
