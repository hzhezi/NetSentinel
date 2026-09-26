// 全局视觉常量。
//
// 集中定义的原因：配色与圆角散落在各页面会导致：
//    - 改一次主色要翻十几个文件
//    - 同一种卡片在不同页面边框/圆角不一致（看起来像没做完）
//
// 这里只放"跨页面共用"的视觉值；页面特有的布局仍写在各自文件里。

export const COLORS = {
  /** 主色（与 ConfigProvider 的 colorPrimary 一致） */
  primary: "#2f9e6e",
  /** 主色的浅底，用于选中态、标签底 */
  primaryBg: "#eafaf2",
  /** 页面背景 */
  pageBg: "#f7f8fa",
  /** 卡片/容器背景 */
  cardBg: "#ffffff",
  /** 次级文字 */
  textSecondary: "#8c8c8c",
  /** 分隔线 */
  border: "#f0f0f0",
} as const;

/** 卡片统一圆角 */
export const RADIUS = 12;

/** 统一的渐变配色 */
export const GRADIENTS = {
  green: "linear-gradient(135deg, #2f9e6e 0%, #6dd5a4 100%)",
  purple: "linear-gradient(135deg, #7c6df0 0%, #a99bf5 100%)",
  blue: "linear-gradient(135deg, #3b82f6 0%, #7cb4fc 100%)",
  orange: "linear-gradient(135deg, #f59e0b 0%, #fbbf5c 100%)",
  pink: "linear-gradient(135deg, #ec4899 0%, #f58fb9 100%)",
  cyan: "linear-gradient(135deg, #0891b2 0%, #4dd0e1 100%)",
} as const;

/** 卡片通用外壳样式（白底、圆角、无重边框） */
export const CARD_STYLE: React.CSSProperties = {
  borderRadius: RADIUS,
  border: "none",
  boxShadow: "0 1px 3px rgba(0,0,0,.04)",
};

/** 页面根容器的统一间距 */
export const PAGE_GAP = 16;
