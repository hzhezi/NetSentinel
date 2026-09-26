/// <reference types="vitest" />
/// <reference types="vite/client" />

// 前端环境变量的类型声明。
// 开发时用相对路径（由 vite proxy 转发），生产同源部署也适用。
interface ImportMetaEnv {
  readonly VITE_API_BASE?: string;
  readonly VITE_WS_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
