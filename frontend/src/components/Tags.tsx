// 严重度 / 结论的展示组件。
//
// 颜色映射集中在这里，而不是散落在各页面 ——
// 改配色只需改一处，也保证全局一致。

import { Tag } from "antd";
import type { Severity, Verdict } from "../types";

const SEVERITY_COLOR: Record<string, string> = {
  critical: "magenta",
  high: "red",
  medium: "orange",
  low: "blue",
  info: "default",
};

const VERDICT_COLOR: Record<Verdict, string> = {
  true_positive: "red",
  false_positive: "green",
  needs_human_review: "gold",
};

const VERDICT_LABEL: Record<Verdict, string> = {
  true_positive: "真实攻击",
  false_positive: "误报",
  needs_human_review: "待人工复核",
};

export function SeverityTag({ severity }: { severity: Severity | string }) {
  return <Tag color={SEVERITY_COLOR[severity] ?? "default"}>{severity}</Tag>;
}

export function VerdictTag({ verdict }: { verdict: Verdict }) {
  return (
    <Tag color={VERDICT_COLOR[verdict] ?? "default"}>
      {VERDICT_LABEL[verdict] ?? verdict}
    </Tag>
  );
}

/** 置信度进度条式的展示：数字 + 颜色分段，一眼看出可信程度。 */
export function ConfidenceBar({ value }: { value: number }) {
  const color = value >= 80 ? "#52c41a" : value >= 50 ? "#faad14" : "#ff4d4f";
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
      <span
        style={{
          display: "inline-block",
          width: 48,
          height: 6,
          background: "#f0f0f0",
          borderRadius: 3,
          overflow: "hidden",
        }}
      >
        <span
          style={{
            display: "block",
            width: `${Math.max(0, Math.min(100, value))}%`,
            height: "100%",
            background: color,
          }}
        />
      </span>
      <span style={{ fontSize: 12, color: "#666" }}>{value}</span>
    </span>
  );
}
