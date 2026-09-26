// 从 vitest/config 导入 defineConfig（而非 vite）：
// 只有它的类型定义里包含 `test` 字段。从 vite 导入会报
// "Object literal may only specify known properties, and 'test' does not exist"。
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// 前端开发服务器配置。
// proxy 把 /api 与 /ws 转发到后端（8000），这样前端代码里用相对路径即可，
// 不必在代码里硬编码后端地址，也避免了开发期的 CORS 问题。
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
      "/ws": { target: "ws://localhost:8000", ws: true },
      "/health": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test-setup.ts"],
  },
});
